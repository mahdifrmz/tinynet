#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "parse.h"
#include "vm.h"
#include "vec.h"

typedef enum {
    TOK_IDENT,
    TOK_STRING,
    TOK_INTEGER,
    TOK_DECIMAL,
    TOK_PLUS,
    TOK_LBRACE,
    TOK_RBRACE,
    TOK_ENDL,
    TOK_EOF,
    TOK_UNKNOWN
} TokenType;

typedef struct {
    TokenType type;
    char *text;
    int line;
    int column;
} Token;

typedef struct {
    Token currentToken;
    FILE *inputFile;
    tn_vm *vm;
    int line;
    int column;
    int buffer;
    
    char *sbuf;
    size_t scap;
    size_t slen;
} Parser;

void pushChar(Parser *parser, char c)
{
    if(!parser->sbuf) {
        parser->slen = 0;
        parser->scap = 16;
        parser->sbuf = malloc(parser->scap);
    }
    if(parser->slen == parser->scap) {
        parser->scap *= 2;
        parser->sbuf = realloc(parser->sbuf, parser->scap);
    }
    parser->sbuf[parser->slen++] = c;
}

// Function to initialize the parser
void initParser(Parser *parser, FILE *inputFile) {
    parser->inputFile = inputFile;
    parser->line = 0;
    parser->column = 0;
    parser->buffer = -2;
    parser->sbuf = NULL;
    parser->vm = tn_vm_init();
}

// Helper function to advance the character position
int advance(Parser *parser) {
    int c;
    if (parser->buffer == -2) {
        c = fgetc(parser->inputFile);
    } else {
        c = parser->buffer;
        parser->buffer = -2;
    }

    if (c == '\n') {
        parser->line++;
        parser->column = 0;
    } else if(c != -1) {
        parser->column++;
    }

    return c;
}


// Helper function to advance the character position
int peek(Parser *parser) {
    int c;
    if(parser->buffer == -2) {
        c = parser->buffer = fgetc(parser->inputFile);
    } else {
        c = parser->buffer;
    }
    return c;
}

// Function to get the next token from input
Token nextToken(Parser *parser) {
    int c;
    Token token;
    token.text = NULL;

    // Skip whitespace except for newline
    while (isspace((c = peek(parser))) && c != '\n') {
        advance(parser);
    }
    token.line = parser->line + 1;
    token.column = parser->column + 1;
    c = advance(parser);

    if (c == EOF) {
        token.type = TOK_EOF;
        token.text = NULL;
    } else if (c == '"') {
        // Parse string with escape sequences
        while ((c = advance(parser)) != '"' && c != EOF) {
            if (c == '\\') {
                // Handle escape sequences
                c = advance(parser);
                if (c == 'n') {
                    pushChar(parser,'\n');
                } else if (c == 't') {
                    pushChar(parser,'\t');
                } else if (c == 'r') {
                    pushChar(parser,'\r');
                } else if (c == '"') {
                    pushChar(parser,'"');
                } else if (c == '\\') {
                    pushChar(parser,'\\');
                } else {
                    pushChar(parser,'\\');
                    pushChar(parser,c);
                }
            } else {
                pushChar(parser,c);
            }
        }
        pushChar(parser, '\0');
        token.type = TOK_STRING;
        token.text = parser->sbuf;
        parser->sbuf = NULL;
    } else {
        char *end, p;
        int is_ident, len;
        pushChar(parser,c);
        if (c != '\n') {
            while (!isspace(( p = peek(parser))) && p != EOF) {
                pushChar(parser, advance(parser));
            }
        }
        pushChar(parser, '\0');
        len = parser->slen - 1;
        if(len == 1) {
            // Parse single-character tokens
            switch (c) {
                case '+': token.type = TOK_PLUS; goto next_token_end;
                case '{': token.type = TOK_LBRACE; goto next_token_end;
                case '}': token.type = TOK_RBRACE; goto next_token_end;
                case '\n': token.type = TOK_ENDL; goto next_token_end;
                default: break;
            }
        }
        token.text = parser->sbuf;
        parser->sbuf = NULL;
        strtol(token.text, &end, 10);
        if(end == token.text + len) {
            token.type = TOK_INTEGER;
            goto next_token_end;
        }
        strtod(token.text, &end);
        if(end == token.text + len) {
            token.type = TOK_DECIMAL;
            goto next_token_end;
        }
        if(isalpha(token.text[0]) || token.text[0] == '-') {
            is_ident = 1;
            for(size_t i=0;i<len;i++) {
                if(!isalnum(token.text[i]) && '-' != token.text[i]) {
                    is_ident = 0;
                }
            }
            if(is_ident) {
                token.type = TOK_IDENT;
                goto next_token_end;
            }
        }
        token.type = TOK_STRING;
    }
next_token_end:
    parser->currentToken = token;
    parser->slen = 0;
    return token;
}

// Expect a specific token type
void expect(Parser *parser, TokenType expectedType) {
    if (parser->currentToken.type != expectedType) {
        fprintf(stderr, "Error at line %d, column %d: expected token type %d, but got %d\n",
                parser->currentToken.line, parser->currentToken.column, expectedType, parser->currentToken.type);
        exit(1);
    }
    nextToken(parser);
}

// Forward declarations for recursive parsing functions
void parseDOC(Parser *parser);
void parseBODY(Parser *parser, tn_entity *ent);
void parseENTITY(Parser *parser, tn_entity *ent,  char *name);
void parseCOMP(Parser *parser, tn_entity *ent);

// DOC := BODY
void parseDOC(Parser *parser) {
    // parse the root entity
    parseBODY(parser, tn_entities[0]);
}

// ENTITY := [ IDENT | STRING ] '{' BODY '}'
void parseENTITY(Parser *parser, tn_entity *ent,  char *name) {
    uint32_t line, column;
    tn_vm_bytecode bc;
    line = parser->currentToken.line;
    column = parser->currentToken.column;
    bc.opcode = TN_VM_OPCODE_CREATE_ENTITY;
    bc.arg = ent->index;
    bc.line = line;
    bc.column = column;
    vec_push(parser->vm->prog_v, bc);
    if (name) {
        tn_entity_attribute *attr;
        vec_foreach(attr, ent->attrs_v) {
            if(!strcmp(attr->name,"name")) {
                break;
            }
        }
        if(attr == vec_end(ent->attrs_v)) {
            // TODO: error
        } else {
            tn_vm_value val;
            val.type = TN_VM_TYPE_STRING;
            val.as.string = name;
            pushInstructions(parser, attr, val);
        }
    }
    expect(parser, TOK_LBRACE);
    parseBODY(parser,ent);
    expect(parser, TOK_RBRACE);
}

// BODY := COMP*
void parseBODY(Parser *parser, tn_entity *ent) {
    while ( parser->currentToken.type == TOK_IDENT ||
            parser->currentToken.type == TOK_PLUS ||
            parser->currentToken.type == TOK_ENDL )
    {
        parseCOMP(parser, ent);
    }
}

void parseOpt(Parser *parser, tn_entity *ent)
{
    nextToken(parser);
    if(parser->currentToken.type != TOK_IDENT) {
        expect(parser,TOK_IDENT);
    }
    tn_entity_option *opt;
    int idx = -1;
    vec_foreach(opt, ent->options_v) {
        if(!strcmp(opt->name, parser->currentToken.text)) {
            idx = opt->index;
            break;
        }
    }
    if(idx == -1) {
        // TODO: err
    } else {
        tn_vm_bytecode bc;
        bc.opcode = TN_VM_OPCODE_SET_OPTION;
        bc.arg = idx;
        bc.line = parser->currentToken.line;
        bc.column = parser->currentToken.column;
        vec_push(parser->vm->prog_v, bc);
    }
}

void pushInstructions(Parser *parser, tn_entity_attribute *attr, tn_vm_value val)
{
    tn_vm_bytecode bc;
    // push the CONST instruction
    bc.opcode = TN_VM_OPCODE_CONSTANT;
    bc.arg = tn_vm_add_constant(parser->vm, val);
    bc.line = parser->currentToken.line;
    bc.column = parser->currentToken.column;
    vec_push(parser->vm->prog_v, bc);
    // push the SET instruction
    bc.opcode = TN_VM_OPCODE_SET_ATTRIBUTE;
    bc.arg = attr->index;
    bc.line = parser->currentToken.line;
    bc.column = parser->currentToken.column;
    vec_push(parser->vm->prog_v, bc);
}

void parseAttr(Parser *parser, tn_entity *ent)
{
    const char *attr_name = parser->currentToken.text;
    nextToken(parser);
    tn_entity *child;
    tn_entity_attribute *attr;
    tn_vm_value val;
    tn_vm_bytecode bc;
    vec_foreach(attr, ent->attrs_v) {
        if(!strcmp(attr->name, attr_name)) {
            break;
        }
    }
    if(attr == vec_end(ent->attrs_v)) {
        // TODO: error
    }
    else if(attr->type == TN_VM_TYPE_STRING) {
        if(parser->currentToken.type != TOK_IDENT && parser->currentToken.type != TOK_STRING){
            expect(parser, TOK_STRING);
        }
        val.type = TN_VM_TYPE_STRING;
        val.as.string = parser->currentToken.text;
        nextToken(parser);
    } else if(attr->type == TN_VM_TYPE_INTEGER) {
        if(parser->currentToken.type != TOK_INTEGER){
            expect(parser, TOK_INTEGER);
        }
        val.type = TN_VM_TYPE_INTEGER;
        val.as.integer = atoi(parser->currentToken.text);
        free(parser->currentToken.text);
        nextToken(parser);
        pushInstructions(parser, attr, val);
    } else if(attr->type == TN_VM_TYPE_DECIMAL) {
        if(parser->currentToken.type != TOK_DECIMAL){
            expect(parser, TOK_DECIMAL);
        }
        val.type = TN_VM_TYPE_DECIMAL;
        val.as.decimal = atoi(parser->currentToken.text);
        free(parser->currentToken.text);
        nextToken(parser);
        pushInstructions(parser, attr, val);
    } else if (attr->type == TN_VM_TYPE_ENTITY) {
        const char *name = NULL;
        if(parser->currentToken.type == TOK_IDENT || parser->currentToken.type == TOK_STRING){
            name = parser->currentToken.text;
            nextToken(parser);
        }
        vec_foreach(child,tn_entities) {
            if(!strcmp(child,attr->name)) {
                break;
            }
        }
        parseENTITY(parser,child,name);
        // push the SET instruction
        bc.opcode = TN_VM_OPCODE_SET_ATTRIBUTE;
        bc.arg = attr->index;
        bc.line = parser->currentToken.line;
        bc.column = parser->currentToken.column;
        vec_push(parser->vm->prog_v, bc);
    }
}

// COMP := <IDENT|'+'> <IDENT|STRING|NUMBER|ENTITY> ENDL
void parseCOMP(Parser *parser, tn_entity *ent) {
    if (parser->currentToken.type == TOK_ENDL){
        nextToken(parser);
        return;
    }
    if (parser->currentToken.type == TOK_IDENT || parser->currentToken.type == TOK_PLUS) {
        int type = 0;
        char *name = NULL;
        if(parser->currentToken.type == TOK_IDENT) {
            parseAttr(parser, ent);
        } else if(parser->currentToken.type == TOK_PLUS) {
            parseOpt(parser, ent);
        }
        // Expect ENDL token
        if(parser->currentToken.type == TOK_EOF)
            return;
        expect(parser, TOK_ENDL);
    } else {
        fprintf(stderr, "Error at line %d, column %d: invalid start of COMP\n",
                parser->currentToken.line, parser->currentToken.column);
        exit(1);
    }
}

tn_vm *tncfg_parse(FILE *file) {
    
    Parser parser;
    
    initParser(&parser, file);
    nextToken(&parser);  // Initialize first token
    parseDOC(&parser);   // Start parsing from DOC rule

    if (parser.currentToken.type != TOK_EOF) {
        fprintf(stderr, "Error at line %d, column %d: unexpected token at end of input\n",
                parser.currentToken.line, parser.currentToken.column);
    }

    fclose(file);
    return parser.vm;
}