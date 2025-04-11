#ifndef ENTITY_H
#define ENTITY_H

#define MAX_SIM_NAME 128

typedef struct tn_root_t tn_root;
typedef struct tn_host_t tn_host;
typedef struct tn_intf_t tn_intf;
typedef struct tn_cmd_t tn_cmd;
typedef struct tn_cmdargv_t tn_cmdargv;
typedef struct tn_cmdlist_t tn_cmdlist;

struct tn_cmdargv_t {
    tn_vm_entity_header header;
    char **args_v;
};

struct tn_cmd_t {
    tn_vm_entity_header header;
    tn_cmd *ll_next;
    tn_cmd *ll_prev;
    tn_cmdlist *list;
    int is_daemon;
    tn_cmdargv *argv;
    int expected_status;
};

struct tn_cmdlist_t {
    tn_vm_entity_header header;
    tn_host *host;
    tn_cmd **cmds_v;
    char *name;
    int current_idx;
    int current_pid;
    int is_test;
};

struct tn_intf_t {
    tn_vm_entity_header header;
    tn_host *host;
    const char *name;
    int is_added;
    struct nl_addr **ip_v;
    tn_intf *peer;
    char *peer_intf_s;
    char *peer_host_s;
};

struct tn_host_t {
    tn_vm_entity_header header;
    tn_root *root;
    tn_intf **intf_v;
    tn_cmdlist **cmdlists_v;
    const char *name;
    int is_switch;
};

struct tn_root_t {
    tn_vm_entity_header header;
    uint32_t checksum;
    char name[MAX_SIM_NAME];
    int has_error;
    FILE *pid_file;
    tn_host **hosts_v;
};

#endif