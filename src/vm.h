#ifndef VM_H
#define VM_H

#include <stdint.h>

typedef struct tn_vm_entity_header_t tn_vm_entity_header;

typedef enum tn_vm_type_t {
    TN_VM_TYPE_STRING,
    TN_VM_TYPE_INTEGER,
    TN_VM_TYPE_DECIMAL,
    TN_VM_TYPE_ENTITY,
} tn_vm_type;

typedef enum tn_vm_opcode_t {
    TN_VM_OPCODE_CREATE_ENTITY,
    TN_VM_OPCODE_SET_ATTRIBUTE,
    TN_VM_OPCODE_CONSTANT,
    TN_VM_OPCODE_SET_OPTION,
} tn_vm_opcode;

typedef struct tn_vm_value_t {
    union {
        char *string;
        double decimal;
        int64_t integer;
        tn_vm_entity_header *entity;
    } as;
    int type;
} tn_vm_value;

typedef int(*tn_attribute_setter_cb)(tn_vm_entity_header*, tn_vm_value);
typedef int(*tn_option_setter_cb)(tn_vm_entity_header*);

typedef struct tn_entity_attribute_t {
    int index;
    const char *name;
    tn_vm_type type;
    int only_once;
    int mandatory;
    int name_unicity;
    int is_name;
    int (*validator)(tn_vm_entity_header*, tn_vm_value);
    tn_attribute_setter_cb setter;
} tn_entity_attribute;

typedef struct tn_entity_option_t {
    int index;
    const char *name;
    tn_option_setter_cb setter;
} tn_entity_option;

typedef struct tn_entity_t {
    int index;
    const char *name;
    tn_entity_option *options_v;
    tn_vm_entity_header *(*create)();
    int (*validator)(tn_vm_entity_header*);
    tn_entity_attribute *attrs_v;
} tn_entity;

typedef struct tn_vm_bytecode_t {
    uint32_t opcode;
    uint32_t arg;
    uint32_t line;
    uint32_t column;
} tn_vm_bytecode;

typedef struct tn_vm_entity_header_t {
    // missing: hash table of parent
    uint64_t options;
    uint64_t flags;
    tn_entity *entity;
    const char *name;
} tn_vm_entity_header;

typedef struct tn_vm_t {
    int has_error;
    int prog_counter;
    tn_vm_bytecode *prog_v;
    tn_vm_value *stack_v;
    tn_vm_value *constants_v;
} tn_vm;

extern tn_entity** tn_entities;

tn_entity *tn_root_entity();
void *tn_vm_top(tn_vm *vm);
void tn_vm_run(tn_vm *vm);
tn_vm *tn_vm_create();
uint32_t tn_vm_add_constant(tn_vm *vm, tn_vm_value val);

#define ENTITY_CREATOR(NAME) __##NAME##_create

#define TN_REGISTER_ENTITY_ALIAS(STRUCT,NAME,LITERAL)\
tn_vm_entity_header *ENTITY_CREATOR(NAME)();\
void __##NAME##_init(STRUCT *self);\
tn_entity __##NAME##_entity_descriptor = {\
    .name = LITERAL,\
    .create = __##NAME##_create,\
    .attrs_v = NULL,\
    .options_v = NULL,\
    .validator = NULL,\
};\
__attribute__((constructor))\
static void __##NAME##_descriptor_insert() {\
    __##NAME##_entity_descriptor.index = vec_len(tn_entities);\
    vec_push(tn_entities, &__##NAME##_entity_descriptor);\
}\
tn_vm_entity_header *ENTITY_CREATOR(NAME)()\
{\
    tn_vm_entity_header *obj = malloc(sizeof(STRUCT));\
    obj->options = 0;\
    obj->flags = 0;\
    obj->name = NULL;\
    obj->entity = &__##NAME##_entity_descriptor;\
    __##NAME##_init((STRUCT*)obj);\
    return obj;\
}\
void __##NAME##_init(STRUCT *self)

#define TN_REGISTER_ENTITY(NAME,LITERAL) TN_REGISTER_ENTITY_ALIAS(NAME,NAME,LITERAL)

#define TN_ATTR_FLAG_MANDATORY 0x01
#define TN_ATTR_FLAG_ONLY_ONCE 0x02
#define TN_ATTR_FLAG_NAME_UNICITY 0x04

#define TN_REGISTER_ALIAS_ATTRIBUTE(ENTITY,ALIAS,NAME,LITERAL,TYPE,FLAGS)\
static int __##ALIAS##_##NAME##_setter(ENTITY* ent, tn_vm_value val);\
__attribute__((constructor))\
static void __##ALIAS##_##NAME##_descriptor_insert() {\
    tn_entity_attribute tn_attr_descriptor = {\
        .name=LITERAL,\
        .type=TYPE,\
        .is_name=!strcmp("name",LITERAL),\
        .only_once=((FLAGS) & TN_ATTR_FLAG_ONLY_ONCE),\
        .mandatory= ((FLAGS) & TN_ATTR_FLAG_MANDATORY),\
        .name_unicity=((FLAGS) & TN_ATTR_FLAG_NAME_UNICITY),\
        .validator=NULL,\
        .setter=(tn_attribute_setter_cb) __##ALIAS##_##NAME##_setter,\
    };\
    tn_attr_descriptor.index = vec_len(__##ALIAS##_entity_descriptor.attrs_v);\
    vec_push(__##ALIAS##_entity_descriptor.attrs_v, tn_attr_descriptor);\
}\
static int __##ALIAS##_##NAME##_setter(ENTITY* ent, tn_vm_value val)

#define TN_REGISTER_ATTRIBUTE(ENTITY,NAME,LITERAL,TYPE,FLAGS) TN_REGISTER_ALIAS_ATTRIBUTE(ENTITY,ENTITY,NAME,LITERAL,TYPE,FLAGS)

#define TN_REGISTER_OPTION(ENTITY,NAME,LITERAL)\
static int __##ENTITY##_##NAME##_setter(ENTITY* ent);\
__attribute__((constructor))\
static void __##ENTITY##_##NAME##_descriptor_insert() {\
    tn_entity_option tn_opt_descriptor = {\
        .name=LITERAL,\
        .setter=(tn_option_setter_cb) __##ENTITY##_##NAME##_setter,\
    };\
    tn_opt_descriptor.index = vec_len(__##ENTITY##_entity_descriptor.options_v);\
    vec_push(__##ENTITY##_entity_descriptor.options_v, tn_opt_descriptor);\
}\
static int __##ENTITY##_##NAME##_setter(ENTITY* ent)

#endif