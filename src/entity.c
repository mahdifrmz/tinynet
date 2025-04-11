#include "vm.h"
#include "vec.h"
#include "string.h"
#include "string.h"
#include "stdio.h"
#include "entity.h"
#include <stdarg.h>
#include <netlink/netlink.h>
#include <netlink/route/addr.h>

void tn_cmdlist_set_line(tn_cmdlist *list, char *str);
int readRef(const char* refstr,int field_count,...);

TN_REGISTER_ENTITY(tn_cmdargv, "argv")
{
    self->args_v = NULL;
}
TN_REGISTER_ATTRIBUTE(tn_cmdargv, element, "-", TN_VM_TYPE_STRING, 0)
{
    vec_push(ent->args_v, val.as.string);
    return 0;
}

TN_REGISTER_ENTITY(tn_cmd, "exec")
{
    self->argv = NULL;
    self->expected_status = 0;
    self->ll_next = self->ll_prev = NULL;
    self->list = NULL;
    self->is_daemon = 0;
}
TN_REGISTER_ATTRIBUTE(tn_cmd, argv, "argv", TN_VM_TYPE_ENTITY, 
    TN_ATTR_FLAG_ONLY_ONCE | TN_ATTR_FLAG_MANDATORY)
{
    tn_cmdargv *argv = (tn_cmdargv*)val.as.entity;
    vec_push(argv->args_v, NULL);
    ent->argv = argv;
    return 0;
}
TN_REGISTER_ATTRIBUTE(tn_cmd, expected_status, "expect-status", TN_VM_TYPE_INTEGER, 
    TN_ATTR_FLAG_ONLY_ONCE)
{
    ent->expected_status = val.as.integer;
    return 0;
}
TN_REGISTER_OPTION(tn_cmd, isdaemon, "daemon")
{
    ent->is_daemon = 1;
    return 0;
}

TN_REGISTER_ENTITY(tn_cmdlist, "cmd")
{
    self->current_pid = 0;
    self->current_idx = 0;
    self->cmds_v = NULL;
    self->is_test = 0;
    self->name = NULL;
}
TN_REGISTER_ATTRIBUTE(tn_cmdlist, line, "line", TN_VM_TYPE_STRING, 0)
{
    tn_cmdlist_set_line(ent, val.as.string);
    return 0;
}
TN_REGISTER_ATTRIBUTE(tn_cmdlist, exec, "exec", TN_VM_TYPE_ENTITY, 0)
{
    tn_cmd *cmd = (tn_cmd *)val.as.entity;
    cmd->list = ent;
    vec_push(ent->cmds_v, cmd);
    return 0;
}

TN_REGISTER_ENTITY_ALIAS(tn_cmdlist, tn_testlist, "test")
{
    self->current_pid = 0;
    self->current_idx = 0;
    self->cmds_v = NULL;
    self->is_test = 1;
    self->name = NULL;
}
TN_REGISTER_ALIAS_ATTRIBUTE(tn_cmdlist, tn_testlist, line, "line", TN_VM_TYPE_STRING, 0)
{
    tn_cmdlist_set_line(ent, val.as.string);
    return 0;
}
TN_REGISTER_ALIAS_ATTRIBUTE(tn_cmdlist, tn_testlist, name, "name", TN_VM_TYPE_STRING, TN_ATTR_FLAG_MANDATORY)
{
    ent->name = val.as.string;
    return 0;
}
TN_REGISTER_ALIAS_ATTRIBUTE(tn_cmdlist, tn_testlist, exec, "exec", TN_VM_TYPE_ENTITY, 0)
{
    tn_cmd *cmd = (tn_cmd *)val.as.entity;
    cmd->list = ent;
    vec_push(ent->cmds_v, cmd);
    return 0;
}

TN_REGISTER_ENTITY(tn_intf,"iface")
{
    self->peer = NULL;
    self->peer_host_s = NULL;
    self->peer_intf_s = NULL;
    self->ip_v = NULL;
    self->name = NULL;
    self->is_added = 0;
}
TN_REGISTER_ATTRIBUTE(tn_intf,name,"name",TN_VM_TYPE_STRING,
    TN_ATTR_FLAG_MANDATORY|
    TN_ATTR_FLAG_ONLY_ONCE)
{
    tn_intf *intf = (tn_intf *)ent;
    intf->name = val.as.string;
    return 0;
}
TN_REGISTER_ATTRIBUTE(tn_intf,peer,"peer",TN_VM_TYPE_STRING,
    TN_ATTR_FLAG_ONLY_ONCE)
{
    tn_intf *intf = (tn_intf *)ent;
    if(readRef(val.as.string,2,&intf->peer_host_s,&intf->peer_intf_s)){
        // throw err
    }
    return 0;
}
TN_REGISTER_ATTRIBUTE(tn_intf,ip,"ip",TN_VM_TYPE_STRING,0)
{
    int err;
    tn_intf *intf = (tn_intf *)ent;
    struct nl_addr *addr;
    if ((err = nl_addr_parse(val.as.string, AF_INET, &addr)) < 0) {
        // throw error
        fprintf(stderr,"invalid ip address '%s'\n", val.as.string);
        return 1;
    }
    vec_push(intf->ip_v, addr);
    return 0;
}

TN_REGISTER_ENTITY(tn_host,"host")
{
    self->name = NULL;
    self->intf_v = NULL;
    self->cmdlists_v = NULL;
    self->is_switch = 0;
}
TN_REGISTER_ATTRIBUTE(tn_host,name,"name",TN_VM_TYPE_STRING,
    TN_ATTR_FLAG_MANDATORY|
    TN_ATTR_FLAG_ONLY_ONCE)
{
    tn_host *host = (tn_host *)ent;
    host->name = val.as.string;
    return 0;
}
TN_REGISTER_ATTRIBUTE(tn_host,intf,"iface",TN_VM_TYPE_ENTITY,
    TN_ATTR_FLAG_NAME_UNICITY)
{
    tn_host *host = (tn_host *)ent;
    tn_intf *intf = (tn_intf *)val.as.entity;
    intf->host = host;
    vec_push(host->intf_v,intf);
    return 0;
}

TN_REGISTER_ATTRIBUTE(tn_host,cmd,"cmd",TN_VM_TYPE_ENTITY,0)
{
    tn_cmdlist *cmdlist = (tn_cmdlist *)val.as.entity;
    cmdlist->host = ent;
    vec_push(ent->cmdlists_v, cmdlist);
    return 0;
}

TN_REGISTER_ATTRIBUTE(tn_host,test,"test",TN_VM_TYPE_ENTITY,0)
{
    tn_cmdlist *cmdlist = (tn_cmdlist *)val.as.entity;
    cmdlist->host = ent;
    vec_push(ent->cmdlists_v, cmdlist);
    return 0;
}

TN_REGISTER_ENTITY(tn_root,"root")
{
    self->hosts_v = NULL;
    self->has_error = 0;
    self->pid_file = NULL;
}

TN_REGISTER_ATTRIBUTE(tn_root,host,"host",TN_VM_TYPE_ENTITY,
    TN_ATTR_FLAG_NAME_UNICITY)
{
    tn_root *root = (tn_root *)ent;
    tn_host *host = (tn_host *)val.as.entity;
    host->root = root;
    vec_push(root->hosts_v, host);
    return 0;
}

void tn_cmdlist_set_line(tn_cmdlist *list, char *str)
{
    char *buf = NULL;
    tn_cmdargv *argv = (tn_cmdargv*)ENTITY_CREATOR(tn_cmdargv)();
    for(char *p = str;; p++)
    {
        if (*p == 0 || *p == ' ') {
            if(vec_len(buf)) {
                vec_push(buf, 0);
                vec_push(argv->args_v, buf);
                buf = NULL;
            }
            if(*p == 0) {
                break;
            }
        } else {
            vec_push(buf, *p);
        }
    }
    vec_push(argv->args_v, NULL);
    tn_cmd *cmd = (tn_cmd *)ENTITY_CREATOR(tn_cmd)();
    cmd->argv = argv;
    cmd->list = list;
    vec_push(list->cmds_v, cmd);
}

int readRef(const char* refstr,int field_count,...)
{
    va_list args;
    int ret = 0;
    va_start(args, field_count);
    const char* p = refstr;
    for(int i=0;i<field_count;i++) {
        char *buf = NULL;
        while(*p != '/' && *p != 0) {
            vec_push(buf, *(p++));
        }
        if(*p == '/') {
            p++;
        }
        if(vec_len(buf) > 0) {
            vec_push(buf, 0);
            char **var = va_arg(args, char**);
            *var = buf;
        } else {
            ret = 1;
            break;
        }
    }
    va_end(args);
    return ret;
}
