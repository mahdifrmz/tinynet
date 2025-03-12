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

typedef struct tn_entity_attribute_t {
    int index;
    const char *name;
    tn_vm_type type;
    int only_once;
    int mandatory;
    int name_unicity;
    int is_name;
    int (*validator)(tn_vm_entity_header*, tn_vm_value);
    void (*setter)(tn_vm_entity_header*, tn_vm_value);
} tn_entity_attribute;

typedef struct tn_entity_t {
    int index;
    const char *name;
    const char **options_v;
    tn_vm_entity_header *(*create)();
    int (*validator)(tn_vm_entity_header*);
    tn_entity_attribute *attrs_v;
} tn_entity;

typedef struct tn_vm_bytecode_t {
    uint32_t opcode;
    uint32_t arg;
    uint32_t line;
    uint32_t pos;
} tn_vm_bytecode;

typedef struct tn_vm_entity_header_t {
    // missing: hash table of parent
    uint64_t options;
    uint64_t flags;
    tn_entity *entity;
    const char *name;
} tn_vm_entity_header;

typedef struct tn_vm_t {
    tn_entity *entities_v;
    int prog_counter;
    tn_vm_bytecode *prog_v;
    tn_vm_value *stack_v;
    tn_vm_value *constants_v;
} tn_vm;

#define TN_REGISTER_ENTITY(NAME)\
tn_vm_entity_header *NAME##_create();\
tn_entity NAME##_entity_descriptor = {\
    .name = #NAME,\
    .attrs_v = NULL,\
    .create = NAME##_create,\
    .validator = NULL,\
};\
tn_vm_entity_header *NAME##_create()\
{\
    tn_vm_entity_header *obj = malloc(sizeof(NAME));\
    obj->options = 0;\
    obj->flags = 0;\
    obj->name = NULL;\
    obj->entity = &NAME##_entity_descriptor;\
    return obj;\
}

#define TN_ATTR_FLAG_MANDATORY 0x01
#define TN_ATTR_FLAG_ONLY_ONCE 0x02
#define TN_ATTR_FLAG_NAME_UNICITY 0x04

#define TN_REGISTER_ATTRIBUTE(ENTITY,NAME,TYPE,TAG,FLAGS)\
static void ENTITY##_##NAME##_descriptor_setter(tn_vm_entity_header* ent, tn_vm_value val) {\
    ENTITY *obj = (tn_object_host*)ent;\
    obj->header.NAME = val.as.TAG;\
}\
__attribute__((constructor))\
static void ENTITY##_##NAME##_descriptor_insert() {\
    tn_entity_attribute tn_attr_descriptor_host_name = {\
        .name=#NAME,\
        .type=TYPE,\
        .only_once=((FLAGS) & TN_ATTR_FLAG_ONLY_ONCE),\
        .mandatory= ((FLAGS) & TN_ATTR_FLAG_MANDATORY),\
        .name_unicity=((FLAGS) & TN_ATTR_FLAG_NAME_UNICITY),\
        .validator=NULL,\
        .setter=ENTITY##_##NAME##_descriptor_setter,\
    };\
    vec_push(ENTITY##_entity_descriptor.attrs_v, tn_attr_descriptor_host_name);\
}