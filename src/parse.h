#ifndef PARSE_H
#define PARSE_H

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

typedef struct value_t value_t;
typedef int32_t tncfg_id;

enum {
    TYPE_INTEGER = 0x1,
    TYPE_STRING = 0x2,
    TYPE_DECIMAL = 0x4,
    TYPE_ENTITY = 0x8,
    TYPE_OPTION = 0x10,
    TYPE_ELEMENT = 0x20,
};

struct value_t {
    char *tag;
    int type;
    union {
        struct {
            tncfg_id from; // inclusive
            tncfg_id to; // exclusive
            tncfg_id ptr;
        } entity;
        int64_t integer;
        double decimal;
        char *string;
    } data;
};

typedef struct {
    value_t *data;
    size_t size;
    size_t capacity;
} tncfg;

tncfg tncfg_parse(FILE *file);

tncfg_id tncfg_root(tncfg *cfg);
int tncfg_type(tncfg *cfg, tncfg_id id);
double tncfg_get_decimal(tncfg *cfg, tncfg_id id);
tncfg_id tncfg_entity_reset(tncfg *cfg, tncfg_id id);
tncfg_id tncfg_entity_next(tncfg *cfg, tncfg_id id);
int64_t tncfg_get_integer(tncfg *cfg, tncfg_id id);
const char *tncfg_get_string(tncfg *cfg, tncfg_id id);
int tncfg_tag_type(tncfg *cfg, tncfg_id id);
char *tncfg_tag(tncfg *cfg, tncfg_id id);
tncfg_id tncfg_lookup_next(tncfg *cfg, tncfg_id id, const char *name);
tncfg_id tncfg_lookup_reset(tncfg *cfg, tncfg_id id, const char *name);
void tncfg_destroy(tncfg *tncfg);

#endif