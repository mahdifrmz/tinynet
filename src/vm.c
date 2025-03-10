#include <stdint.h>

#define TN_TYPE_STRING
#define TN_TYPE_INTEGER
#define TN_TYPE_DECIMAL
#define TN_TYPE_ENTITY
#define TN_TYPE_OPTION
#define TN_TYPE_ELEMENT

typedef struct {
    union {
        char *string;
        double decimal;
        int64_t integer;
        tn_entity_header_t *entity;
    } as;
    int type;
} tn_value_t;

typedef struct {
    const char *name;
    int type;
    int name_unicity;
    int (*validator)(tn_entity_header_t, tn_value_t);
    void (*setter)(tn_entity_header_t, tn_value_t);
    int (*ref)(tn_entity_header_t);
} tn_attribute_t;

typedef struct {
    const char *name;
    tn_attribute_t *attrs;
    tn_attribute_t *attrs_len;
} tn_entity_t;

typedef struct {
    uint32_t opcode;
    uint32_t arg;
} tn_bytecode_t;

typedef struct {
    tn_entity_t *entity;
    const char *name;
} tn_entity_header_t;

typedef struct {
    tn_bytecode_t *prog;
    int prog_idx;
    int prog_len;
    tn_value_t *stack;
    int stack_idx;
} tn_vm_t;