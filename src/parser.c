#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

typedef enum {
    TOK_IDENT,
    TOK_STRING,
    TOK_NUMBER,
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
} Token;

typedef struct {
    Token currentToken;
    FILE *inputFile;
} Parser;

// Function to get the next token from input
Token nextToken(Parser *parser) {
    int c;

    // Skip whitespace except for newline
    do {
        c = fgetc(parser->inputFile);
    } while (isspace(c) && c != '\n');

    if (c == EOF) {
        parser->currentToken.type = TOK_EOF;
        parser->currentToken.text = NULL;
        return parser->currentToken;
    }

    Token token;
    if (isalpha(c) || c == '_') {
        // Parse identifier
        char buffer[256];
        int i = 0;
        buffer[i++] = c;
        while (isalnum(c = fgetc(parser->inputFile)) || c == '_') {
            buffer[i++] = c;
        }
        buffer[i] = '\0';
        ungetc(c, parser->inputFile);
        token.type = TOK_IDENT;
        token.text = strdup(buffer);
    } else if (isdigit(c)) {
        // Parse integer or decimal number
        char buffer[256];
        int i = 0;
        buffer[i++] = c;

        int hasDecimal = 0;
        while (isdigit(c = fgetc(parser->inputFile)) || (c == '.' && !hasDecimal)) {
            if (c == '.') hasDecimal = 1;  // Allow only one decimal point
            buffer[i++] = c;
        }
        buffer[i] = '\0';
        ungetc(c, parser->inputFile);
        token.type = TOK_NUMBER;
        token.text = strdup(buffer);
    } else if (c == '"') {
        // Parse string with escape sequences
        char buffer[256];
        int i = 0;
        while ((c = fgetc(parser->inputFile)) != '"' && c != EOF) {
            if (c == '\\') {
                // Handle escape sequences
                c = fgetc(parser->inputFile);
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
                    // Unrecognized escape character, treat as literal
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
    return token;
}

// Expect a specific token type
void expect(Parser *parser, TokenType expectedType) {
    if (parser->currentToken.type != expectedType) {
        fprintf(stderr, "Parse error:expected token type %d, but got %d\n", expectedType, parser->currentToken.type);
        exit(1);
    }
    nextToken(parser);
}

// Forward declarations for recursive parsing functions
void parseDOC(Parser *parser);
void parseBODY(Parser *parser);
void parseENTITY(Parser *parser);
void parseCOMP(Parser *parser);

// DOC := BODY
void parseDOC(Parser *parser) {
    parseBODY(parser);
}

// ENTITY := '{' BODY '}'
void parseENTITY(Parser *parser) {
    expect(parser, TOK_LBRACE);
    parseBODY(parser);
    expect(parser, TOK_RBRACE);
}

// BODY := COMP*
void parseBODY(Parser *parser) {
    while (parser->currentToken.type == TOK_IDENT || parser->currentToken.type == TOK_PLUS || parser->currentToken.type == TOK_MINUS) {
        parseCOMP(parser);
    }
}

// COMP := <IDENT|'+'|'-'> <IDENT|STRING|NUMBER|ENTITY> ENDL
void parseCOMP(Parser *parser) {
    if (parser->currentToken.type == TOK_IDENT || parser->currentToken.type == TOK_PLUS || parser->currentToken.type == TOK_MINUS) {
        nextToken(parser);

        // Handle second part of COMP rule
        if (parser->currentToken.type == TOK_IDENT || parser->currentToken.type == TOK_STRING || parser->currentToken.type == TOK_NUMBER) {
            nextToken(parser);
        } else if (parser->currentToken.type == TOK_LBRACE) {
            parseENTITY(parser);
        } else {
            fprintf(stderr, "Parse error:expected IDENT, STRING, NUMBER, or ENTITY, but got %d\n", parser->currentToken.type);
            exit(1);
        }

        // Expect ENDL token
        expect(parser, TOK_ENDL);
    } else {
        fprintf(stderr, "Parse error:invalid start of COMP\n");
        exit(1);
    }
}

// Main function to initialize parser and start parsing
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input file>\n", argv[0]);
        return 1;
    }

    Parser parser;
    parser.inputFile = fopen(argv[1], "r");
    if (!parser.inputFile) {
        perror("Error opening file");
        return 1;
    }

    nextToken(&parser);  // Initialize first token
    parseDOC(&parser);   // Start parsing from DOC rule

    if (parser.currentToken.type == TOK_EOF) {
        printf("Parsing completed successfully.\n");
    } else {
        fprintf(stderr, "Parse error:unexpected token at end of input\n");
    }

    fclose(parser.inputFile);
    return 0;
}