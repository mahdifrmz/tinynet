#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "parse.h"

void tncfg_init(tncfg *tncfg) {
    tncfg->data = malloc(16 * sizeof(value_t));
    tncfg->size = 0;
    tncfg->capacity = 16;
}

void tncfg_add(tncfg *tncfg, value_t element) {
    if (tncfg->size == tncfg->capacity) {
        tncfg->capacity = 2 * tncfg->capacity * sizeof(value_t);
        tncfg->data = realloc(tncfg->data, tncfg->capacity);
    }
    tncfg->data[tncfg->size++] = element;
}

void tncfg_destroy(tncfg *tncfg) {
    free(tncfg->data);
}

typedef enum {
    TOK_IDENT,
    TOK_STRING,
    TOK_INTEGER,
    TOK_DECIMAL,
    TOK_PLUS,
    TOK_MINUS,
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
    tncfg cfg;
    int line;
    int column;
    int buffer;
} Parser;

// Function to initialize the parser
void initParser(Parser *parser, FILE *inputFile) {
    parser->inputFile = inputFile;
    parser->line = 0;
    parser->column = 0;
    parser->buffer = -2;
    tncfg_init(&parser->cfg);
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
    }
    else if (isalpha(c) || c == '_') {
        // Parse identifier
        char buffer[256];
        int i = 0;
        buffer[i++] = c;
        while (isalnum(c = peek(parser)) || c == '_') {
            buffer[i++] = c;
            advance(parser);
        }
        buffer[i] = '\0';
        token.type = TOK_IDENT;
        token.text = strdup(buffer);
    } else if (isdigit(c)) {
        // Parse integer or decimal number
        char buffer[256];
        int i = 0;

        if (c == '-') {
            buffer[i++] = c;
            c = advance(parser);
        }

        buffer[i++] = c;

        int hasDecimal = 0;
        while (isdigit(c = peek(parser)) || (c == '.' && !hasDecimal)) {
            if (c == '.') hasDecimal = 1;  // Allow only one decimal point
            buffer[i++] = c;
            advance(parser);
        }
        buffer[i] = '\0';
        token.type = hasDecimal ? TOK_DECIMAL : TOK_INTEGER;
        token.text = strdup(buffer);
    } else if (c == '"') {
        // Parse string with escape sequences
        char buffer[256];
        int i = 0;
        while ((c = advance(parser)) != '"' && c != EOF) {
            if (c == '\\') {
                // Handle escape sequences
                c = advance(parser);
                if (c == 'n') {
                    buffer[i++] = '\n';
                } else if (c == 't') {
                    buffer[i++] = '\t';
                } else if (c == 'r') {
                    buffer[i++] = '\r';
                } else if (c == '"') {
                    buffer[i++] = '"';
                } else if (c == '\\') {
                    buffer[i++] = '\\';
                } else {
                    buffer[i++] = '\\';
                    buffer[i++] = c;
                }
            } else {
                buffer[i++] = c;
            }
        }
        buffer[i] = '\0';
        token.type = TOK_STRING;
        token.text = strdup(buffer);
    } else {
        // Parse single-character tokens
        token.text = NULL;
        switch (c) {
            case '+': token.type = TOK_PLUS; break;
            case '-': token.type = TOK_MINUS; break;
            case '{': token.type = TOK_LBRACE; break;
            case '}': token.type = TOK_RBRACE; break;
            case '\n': token.type = TOK_ENDL; break;
            default: token.type = TOK_UNKNOWN; break;
        }
    }
    parser->currentToken = token;
    printf("--> %d [%d,%d]\n", token.type, token.line, token.column);
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
void parseBODY(Parser *parser);
void parseENTITY(Parser *parser, char *name, int type);
void parseCOMP(Parser *parser);

value_t *parser_last_value(Parser *parser)
{
    return &parser->cfg.data[parser->cfg.size -1];
}

// DOC := BODY
void parseDOC(Parser *parser) {
    value_t val;
    val.tag = NULL;
    val.type = TYPE_ENTITY;
    tncfg_add(&parser->cfg, val);
    value_t *pval = parser_last_value(parser);
    pval->data.entity.from = parser->cfg.size;
    parseBODY(parser);
    pval->data.entity.to = parser->cfg.size;
}

// ENTITY := [ IDENT | STRING ] '{' BODY '}'
void parseENTITY(Parser *parser, char *name, int type) {
    expect(parser, TOK_LBRACE);
    value_t val;
    val.tag = name;
    val.type = TYPE_ENTITY | type;
    tncfg_add(&parser->cfg, val);
    value_t *pval = parser_last_value(parser);
    pval->data.entity.from = parser->cfg.size;
    if (name) {
        value_t val;
        val.tag = strdup("name");
        val.type = TYPE_STRING;
        val.data.string = name;
        tncfg_add(&parser->cfg, val);
    }
    parseBODY(parser);
    pval->data.entity.to = parser->cfg.size;
    expect(parser, TOK_RBRACE);
}

// BODY := COMP*
void parseBODY(Parser *parser) {
    while ( parser->currentToken.type == TOK_IDENT ||
            parser->currentToken.type == TOK_PLUS ||
            parser->currentToken.type == TOK_MINUS ||
            parser->currentToken.type == TOK_ENDL )
    {
        parseCOMP(parser);
    }
}

// COMP := <IDENT|'+'|'-'> <IDENT|STRING|NUMBER|ENTITY> ENDL
void parseCOMP(Parser *parser) {
    if (parser->currentToken.type == TOK_ENDL){
        nextToken(parser);
        return;
    }
    if (parser->currentToken.type == TOK_IDENT || parser->currentToken.type == TOK_PLUS || parser->currentToken.type == TOK_MINUS) {
        int type = 0;
        char *name = NULL;
        if(parser->currentToken.type == TOK_IDENT) {
            name = parser->currentToken.text;
        } else if(parser->currentToken.type == TOK_MINUS) {
            type = TYPE_ELEMENT;
        } else if(parser->currentToken.type == TOK_PLUS) {
            type = TYPE_OPTION;
        }

        nextToken(parser);

        // Handle second part of COMP rule
        if (parser->currentToken.type == TOK_IDENT || parser->currentToken.type == TOK_STRING || parser->currentToken.type == TOK_DECIMAL
         || parser->currentToken.type == TOK_INTEGER) {
            value_t val = {
                .tag = name,
                .type = 0,
            };
            if(parser->currentToken.type == TOK_IDENT || parser->currentToken.type == TOK_STRING) {
                val.type = type | TYPE_STRING;
                val.data.string = parser->currentToken.text;
                nextToken(parser);
                if(parser->currentToken.type == TOK_LBRACE) {
                    parseENTITY(parser, val.data.string, type);
                } else {
                    tncfg_add(&parser->cfg, val);
                }
            } else if(parser->currentToken.type == TOK_INTEGER) {
                val.type = type | TYPE_INTEGER;
                val.data.integer = atol(parser->currentToken.text);
                tncfg_add(&parser->cfg, val);
                nextToken(parser);
            } else {
                val.type = type | TYPE_DECIMAL;
                val.data.decimal = strtod(parser->currentToken.text, NULL);
                tncfg_add(&parser->cfg, val);
                nextToken(parser);
            }
        } else if (parser->currentToken.type == TOK_LBRACE) {
            parseENTITY(parser,NULL,type);
        } else {
            fprintf(stderr, "Error at line %d, column %d: expected IDENT, STRING, NUMBER, or ENTITY, but got %d\n",
                    parser->currentToken.line, parser->currentToken.column, parser->currentToken.type);
            exit(1);
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

tncfg tncfg_parse(FILE *file) {
    
    Parser parser;
    
    initParser(&parser, file);
    nextToken(&parser);  // Initialize first token
    parseDOC(&parser);   // Start parsing from DOC rule

    if (parser.currentToken.type == TOK_EOF) {
        printf("Parsing completed successfully.\n");
    } else {
        fprintf(stderr, "Error at line %d, column %d: unexpected token at end of input\n",
                parser.currentToken.line, parser.currentToken.column);
    }

    fclose(file);
    return parser.cfg;
}

tncfg_id tncfg_root(tncfg *cfg)
{
    return 0;
}
int tncfg_type(tncfg *cfg, tncfg_id id)
{
    return cfg->data[id].type;
}
double tncfg_get_decimal(tncfg *cfg, tncfg_id id)
{
    return cfg->data[id].data.decimal;
}
tncfg_id tncfg_entity_reset(tncfg *cfg, tncfg_id id)
{
    cfg->data[id].data.entity.ptr = id + 1;
    if(cfg->data[id].data.entity.ptr == cfg->data[id].data.entity.to)
        return -1;
    return id + 1;
}
tncfg_id tncfg_entity_next(tncfg *cfg, tncfg_id id)
{
    tncfg_id ptr = cfg->data[id].data.entity.ptr;
    tncfg_id to = cfg->data[id].data.entity.to;
    int cur_type = cfg->data[ptr].type;
    if( cur_type & TYPE_ENTITY ) {
        tncfg_id next_start = cfg->data[ptr].data.entity.to;
        cfg->data[id].data.entity.ptr = next_start;
    } else {
        cfg->data[id].data.entity.ptr++;
    }
    if(cfg->data[id].data.entity.ptr == to)
        return -1;
    return cfg->data[id].data.entity.ptr;
}
int32_t tncfg_get_integer(tncfg *cfg, tncfg_id id)
{
    return cfg->data[id].data.integer;
}
const char *tncfg_get_str(tncfg *cfg, tncfg_id id)
{
    return cfg->data[id].data.string;
}