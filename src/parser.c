#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "parse.h"

void tncfg_init(tncfg *tncfg) {
    tncfg->size = 0;
    tncfg->capacity = 16;
    tncfg->data = malloc(tncfg->capacity * sizeof(value_t));
}

void tncfg_add(tncfg *tncfg, value_t element) {
    if (tncfg->size == tncfg->capacity) {
        tncfg->capacity *= 2;
        tncfg->data = realloc(tncfg->data, tncfg->capacity * sizeof(value_t));
    }
    tncfg->data[tncfg->size++] = element;
}

void tncfg_destroy(tncfg *tncfg) {
    for(tncfg_id i = 0; i < tncfg->size; i++)
    {
        value_t v = tncfg->data[i];
        free(v.tag);
        if (v.type & TYPE_STRING) {
            free(v.data.string);
        }
    }
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
                case '-': token.type = TOK_MINUS; goto next_token_end;
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
        if(isalpha(token.text[0])) {
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
void parseBODY(Parser *parser);
void parseENTITY(Parser *parser, char *name, char *tag, int type);
void parseCOMP(Parser *parser);

// DOC := BODY
void parseDOC(Parser *parser) {
    value_t val;
    val.tag = NULL;
    val.type = TYPE_ENTITY;
    tncfg_add(&parser->cfg, val);
    tncfg_id last = parser->cfg.size - 1;
    parser->cfg.data[last].data.entity.from = parser->cfg.size;
    parseBODY(parser);
    parser->cfg.data[last].data.entity.to = parser->cfg.size;
}

// ENTITY := [ IDENT | STRING ] '{' BODY '}'
void parseENTITY(Parser *parser, char *name, char *tag, int type) {
    expect(parser, TOK_LBRACE);
    value_t val;
    val.tag = tag;
    val.type = TYPE_ENTITY | type;
    tncfg_add(&parser->cfg, val);
    tncfg_id last = parser->cfg.size - 1;
    parser->cfg.data[last].data.entity.from = parser->cfg.size;
    if (name) {
        value_t val;
        val.tag = strdup("name");
        val.type = TYPE_STRING;
        val.data.string = name;
        tncfg_add(&parser->cfg, val);
    }
    parseBODY(parser);
    parser->cfg.data[last].data.entity.to = parser->cfg.size;
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
                    parseENTITY(parser, val.data.string, name, type);
                } else {
                    tncfg_add(&parser->cfg, val);
                }
            } else if(parser->currentToken.type == TOK_INTEGER) {
                val.type = type | TYPE_INTEGER;
                val.data.integer = atol(parser->currentToken.text);
                free(parser->currentToken.text);
                tncfg_add(&parser->cfg, val);
                nextToken(parser);
            } else {
                val.type = type | TYPE_DECIMAL;
                val.data.decimal = strtod(parser->currentToken.text, NULL);
                free(parser->currentToken.text);
                tncfg_add(&parser->cfg, val);
                nextToken(parser);
            }
        } else if (parser->currentToken.type == TOK_LBRACE) {
            parseENTITY(parser,NULL,name,type);
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

    if (parser.currentToken.type != TOK_EOF) {
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
    return cfg->data[id].type & 0x0000000f;
}
int tncfg_tag_type(tncfg *cfg, tncfg_id id)
{
    return cfg->data[id].type & 0xfffffff0;
}
char *tncfg_tag(tncfg *cfg, tncfg_id id)
{
    return cfg->data[id].tag;
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
int64_t tncfg_value_integer(tncfg *cfg, tncfg_id id)
{
    return cfg->data[id].data.integer;
}
double tncfg_value_decimal(tncfg *cfg, tncfg_id id)
{
    return cfg->data[id].data.decimal;
}
char *tncfg_value_string(tncfg *cfg, tncfg_id id)
{
    return cfg->data[id].data.string;
}
tncfg_id tncfg_lookup_next(tncfg *cfg, tncfg_id id, const char *name, int type)
{
    tncfg_id child;
    do {
        child = tncfg_entity_next(cfg, id);
    } while (child != -1 && !(
        tncfg_type(cfg, child) == type && 
        tncfg_tag_type(cfg, child) == 0 && 
        !strcmp(tncfg_tag(cfg, child), name)
    ));
    return child;
}
tncfg_id tncfg_lookup_reset(tncfg *cfg, tncfg_id id, const char *name, int type)
{
    tncfg_id child = tncfg_entity_reset(cfg, id);
    if(child == -1) {
        return -1;
    }
    while (child != -1 && !(
        tncfg_type(cfg, child) == type && 
        tncfg_tag_type(cfg, child) == 0 &&
        !strcmp(tncfg_tag(cfg, child), name)
    ))
        child = tncfg_entity_next(cfg, id);
    return child;
}

int tncfg_comp_verify(tncfg *cfg, tncfg_id id, tncfg_comp *comps, size_t comps_count)
{
    int seen[comps_count];
    int failed = 0;
    memset(seen,0,comps_count * sizeof(int));
    tncfg_id child = tncfg_entity_reset(cfg, id);
    while(child != -1) {
        if (tncfg_tag_type(cfg, child) == TYPE_ELEMENT) {
            fprintf(stderr, "Unexpected element\n");
            failed = 1;
        } else if (tncfg_tag_type(cfg, child) == TYPE_OPTION) {
            if(tncfg_type(cfg, child) != TYPE_STRING)
            {
                fprintf(stderr, "Unknown option\n");
                failed = 1;
            }
            int f = 1;
            for(int i=0;i<comps_count;i++)
            {
                if(comps[i].type & TYPE_STRING && !strcmp(tncfg_value_string(cfg,child), comps[i].string)) {
                    if(seen[i]) {
                        fprintf(stderr, "Duplicate option\n");
                    } else {
                        seen[i] = 1;
                        f = 0;
                    }
                    break;
                }
            }
            failed |= f;
            if(f) {
                fprintf(stderr, "Unknown option\n");
            }
        } else {
            if(tncfg_type(cfg, child) == TYPE_DECIMAL)
            {
                fprintf(stderr, "Invalid property\n");
                failed = 1;
            }
            else if (tncfg_type(cfg, child) == TYPE_INTEGER)
            {
                int f = 1;
                for(int i=0;i<comps_count;i++)
                {
                    if(comps[i].type & TYPE_INTEGER && !strcmp(tncfg_tag(cfg,child), comps[i].string)) {
                        if(seen[i]) {
                            fprintf(stderr, "Duplicate parameter\n");
                        } else {
                            seen[i] = 1;
                            f = 0;
                        }
                        break;
                    }
                }
                failed |= f;
                if(f) {
                    fprintf(stderr, "Unknown parameter\n");
                }
            }
            else if (tncfg_type(cfg, child) == TYPE_STRING)
            {
                int f = 1;
                for(int i=0;i<comps_count;i++)
                {
                    if(comps[i].type & TYPE_STRING && !strcmp(tncfg_tag(cfg,child), comps[i].string)) {
                        if(seen[i] && !comps[i].multiple) {
                            fprintf(stderr, "Duplicate property\n");
                        } else {
                            seen[i] = 1;
                            f = 0;
                        }
                        break;
                    }
                }
                failed |= f;
                if(f) {
                    fprintf(stderr, "Unknown property\n");
                }
            }
            else if (tncfg_type(cfg, child) == TYPE_ENTITY)
            {
                int f = 1;
                for(int i=0;i<comps_count;i++)
                {
                    if(comps[i].type & TYPE_ENTITY && !strcmp(tncfg_tag(cfg,child), comps[i].string)) {
                        if(seen[i] && !comps[i].multiple) {
                            fprintf(stderr, "Duplicate entity\n");
                        } else {
                            seen[i] = 1;
                            f = 0;
                        }
                        break;
                    }
                }
                failed |= f;
                if(f) {
                    fprintf(stderr, "Unknown entity\n");
                }
            }
        }
        child = tncfg_entity_next(cfg, id);
    }
    for(int i=0; i<comps_count; i++)
    {
        if(comps[i].required && !seen[i]) {
            fprintf(stderr, "property %s is required\n", comps[i].string);
            failed = 1;
        }
    }
    return failed;
}

char *tncfg_get_string(tncfg *cfg, tncfg_id id, const char *name)
{
    tncfg_id child;
    child = tncfg_lookup_reset(cfg, id, name, TYPE_STRING);
    if (child != -1) {
        return cfg->data[child].data.string;
    } else {
        return ((char*)"");
    }
}
int tncfg_get_int(tncfg *cfg, tncfg_id id, const char *name, int64_t *value)
{
    tncfg_id child;
    child = tncfg_lookup_reset(cfg, id, name, TYPE_INTEGER);
    if (child != -1) {
        *value = cfg->data[child].data.integer;
        return 1;
    } else {
        return 0;
    }
}
int tncfg_get_decimal(tncfg *cfg, tncfg_id id, const char *name, double *value)
{
    tncfg_id child;
    child = tncfg_lookup_reset(cfg, id, name, TYPE_DECIMAL);
    if (child != -1) {
        *value = cfg->data[child].data.decimal;
        return 1;
    } else {
        return 0;
    }
}
tncfg_id tncfg_get_entity(tncfg *cfg, tncfg_id id, const char *name)
{
    return tncfg_lookup_reset(cfg, id, name, TYPE_ENTITY);
}