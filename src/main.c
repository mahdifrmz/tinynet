#define _GNU_SOURCE
#include <getopt.h>
#include <stdio.h>
#include <toml.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <sched.h>
#include <setjmp.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <net/if.h>
#include <errno.h>
#include <dirent.h>
#include <netlink/netlink.h>
#include <netlink/route/rtnl.h>
#include <netlink/route/link.h>
#include <netlink/route/addr.h>
#include <netlink/route/link/veth.h>
#include <assert.h>
#include "vec.h"
#include "parse.h"
#include "vm.h"

#define NETNS_MOUNT_DIR "/run/tomnet/sim"
#define LOCKFILE_PATH "/run/tomnet/lock"

#define MAX_SIM_NAME 128
#define MAX_HOST_NAME 256
#define MAX_HOST_NAME_STR "256"
#define MAX_IF_NAME 15
#define MAX_IF_NAME_STR "15"

#define ARRAY_LEN(A) (sizeof(A)/sizeof(*A))

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

typedef struct tn_root_t tn_root;
typedef struct tn_host_t tn_host;
typedef struct tn_intf_t tn_intf;

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

struct tn_host_t {
    tn_vm_entity_header header;
    tn_root *root;
    tn_intf **intf_v;
    const char *name;
    int is_switch;
};
TN_REGISTER_ENTITY(tn_host,"host")
{
    self->name = NULL;
    self->intf_v = NULL;
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

struct tn_root_t {
    tn_vm_entity_header header;
    uint32_t checksum;
    char name[MAX_SIM_NAME];
    int has_error;
    tn_host **hosts_v;
};
TN_REGISTER_ENTITY(tn_root,"root")
{
    self->hosts_v = NULL;
    self->has_error = 0;
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

tn_host *tn_lookup_host(tn_root *root, const char *name) {
    tn_host **host;
    if(!name[0]) {
        return NULL;
    }
    vec_foreach(host, root->hosts_v) {
        if(!strcmp(name,(*host)->name)) {
            return *host;
        }
    }
    return NULL;
}

tn_intf *tn_lookup_intf(tn_host* host, const char *name) {
    tn_intf **intf;
    if(!name[0]) {
        return NULL;
    }
    vec_foreach(intf, host->intf_v) {
        if(!strcmp(name,(*intf)->name)) {
            return *intf;
        }
    }
    return NULL;
}

FILE *tn_host_ns_file(tn_host *host)
{
    char buf[256];
    snprintf(buf,sizeof(buf), NETNS_MOUNT_DIR "/%s/hosts/%s", host->root->name, host->name);
    return fopen(buf,"r");
}

void tn_parse_error(tn_root *root, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
    root->has_error = 1;
}

unsigned int xcrc32_next (unsigned char c, unsigned int crc);

uint32_t checksum(FILE *f) {
    uint32_t crc = 0xffffffff;
    char c;
    while((c = fgetc(f)) != EOF)
    {
        crc = xcrc32_next(c, crc);
    }
    fseek(f, 0, SEEK_SET);
    return crc;
}

void tn_resolve_peers(tn_root *root)
{
    tn_host *host, **h, *other_host;
    tn_intf *intf, **f, *other_intf;
    vec_foreach(h, root->hosts_v) {
        host = *h;
        vec_foreach(f, host->intf_v) {
            intf = *f;
            if(intf->peer_host_s) {
                other_host = tn_lookup_host(root, intf->peer_host_s);
                if(!other_host) {
                    // throw error
                }
                other_intf = tn_lookup_intf(other_host, intf->peer_intf_s);
                if(!other_intf) {
                    // throw error
                }
                if(intf->peer && intf->peer != other_intf) {
                    // throw
                }
                intf->peer = other_intf;
            }
        }
    }
}

tn_root *tn_eval(const char *file_path) {
    FILE *file = fopen(file_path, "rb");
    tn_root *root;
    if(!file) {
        fprintf(stderr, "failed to open file: %s\n", file_path);
    } else {
        tn_vm *vm = tncfg_parse(file);
        tn_vm_run(vm);
        root = (tn_root *)tn_vm_top(vm);
        root->has_error = vm->has_error;
        if(root->has_error){
            return root;
        }
        tn_resolve_peers(root);
        if(root->has_error){
            return root;
        }
        fseek(file, 0, SEEK_SET);
        root->checksum = checksum(file);
        fclose(file);
    }
    return root;
}

int touch(const char *path)
{
    FILE *file = fopen(path, "w+");
    if(!file) {
        return 0;
    }
    fclose(file);
    return 1;
}

void tn_create_host(tn_host *host)
{
    int pid = fork();
    if(!pid) {
        int err;
        // create new netns
        if(unshare(CLONE_NEWNET) == -1) {
            perror("FATAL: failed to create netns");
            exit(1);
        }
        // bind mount the netns
        int mypid = getpid();
        char target_path[256];
        char source_path[256];
        snprintf(source_path, sizeof(source_path), "/proc/%d/ns/net", mypid);
        snprintf(target_path, sizeof(target_path), NETNS_MOUNT_DIR "/%s/hosts/%s", host->root->name, host->name);
        if(!touch(target_path) || mount(source_path, target_path, "proc", MS_BIND | MS_SHARED, NULL) == -1) {
            perror("FATAL: failed to mount netns");
            exit(1);
        }
        // open netlink
        struct nl_sock *nlsock = nl_socket_alloc();
        if((err = nl_connect(nlsock,NETLINK_ROUTE)) < 0) {
            fprintf(stderr, "can't create rt_netlink socket: %s\n", nl_geterror(err));
            exit(1);
        }
        // up the loopback interface
        struct rtnl_link *lo;
        struct rtnl_link *change = rtnl_link_alloc();
        if((err = rtnl_link_get_kernel(nlsock, 0, "lo", &lo)) < 0) {
            fprintf(stderr, "FATAL: failed to fetch link: %s\n", nl_geterror(err));
            exit(1);
        }
        rtnl_link_set_flags(change, IFF_UP);
        if((err = rtnl_link_change(nlsock, lo, change, 0)) < 0) {
            fprintf(stderr, "FATAL: failed to up link: %s\n", nl_geterror(err));
            exit(1);
        }
        // clean up        
        rtnl_link_put(lo);
        nl_close(nlsock);
        nl_socket_free(nlsock);

        exit(0);
    } else {
        int st;
        waitpid(pid, &st, 0);
        if (WEXITSTATUS(st)) {
            exit(1);
        }
    }
}

void tn_up_hosts(tn_host *host)
{
    FILE *nsfile;
    int err;
    int pid = fork();
    if(!pid) {
        nsfile = tn_host_ns_file(host);
        if(!nsfile) {
            perror("Failed to attach to namespace");
            exit(1);
        }
        if (setns(fileno(nsfile), CLONE_NEWNET) == -1) {
            perror("Failed to attach to namespace");
            exit(1);
        }
        fclose(nsfile);
        
        struct nl_cache *cache;
        struct nl_sock *nlsock = nl_socket_alloc();
        if(( err = nl_connect(nlsock,NETLINK_ROUTE)) < 0) {
            fprintf(stderr, "Can't create rt_netlink socket : %s\n", nl_geterror(err));
            exit(1);
        }
        if((err = rtnl_link_alloc_cache(nlsock, AF_UNSPEC, &cache)) < 0) {
            fprintf(stderr, "Failed to get link info : %s\n", nl_geterror(err));
            exit(1);
        }
        struct rtnl_link *change = rtnl_link_alloc();
        rtnl_link_set_flags(change, IFF_UP);
        struct rtnl_link *link = (struct rtnl_link *) nl_cache_get_first(cache);
        while(link) {
            if ((err = rtnl_link_change(nlsock, link, change, 0)) < 0) {
                fprintf(stderr, "Failed to up interface '%s' : %s\n", rtnl_link_get_name(link), nl_geterror(err));
                exit(1);
            }
            if(rtnl_link_get_type(link)) {
                const char *name = rtnl_link_get_name(link);
                tn_intf *intf = tn_lookup_intf(host, name);
                struct nl_addr **ip;
                vec_foreach(ip,intf->ip_v) {
                    struct rtnl_addr *rt_addr = rtnl_addr_alloc();
                    rtnl_addr_set_local(rt_addr, *ip);
                    rtnl_addr_set_prefixlen(rt_addr, nl_addr_get_prefixlen(*ip));
                    rtnl_addr_set_ifindex(rt_addr, rtnl_link_get_ifindex(link));
                    if((err = rtnl_addr_add(nlsock, rt_addr, NLM_F_CREATE)) < 0) {
                        fprintf(stderr, "Failed to set ip on interface '%s' : %s\n", name, nl_geterror(err));
                        exit(1);
                    }
                }
            }
            link = (struct rtnl_link *) nl_cache_get_next((struct nl_object *)link);
        }
        nl_close(nlsock);
        nl_socket_free(nlsock);
        rtnl_link_put(change);
        nl_cache_free(cache);
        exit(0);
    } else {
        int st;
        waitpid(pid, &st, 0);
        if (WEXITSTATUS(st)) {
            exit(1);
        }
    }
}

void tn_create_intf(tn_intf *intf, struct nl_sock *nlsock)
{
    int err;
    struct rtnl_link *dev, *pdev;
    FILE *nsfile, *pnsfile;
    tn_intf *peer;
    if(intf->is_added) {
        return;
    }
    if(intf->peer) {
        peer = intf->peer;
        intf->is_added = 1;
        peer->is_added = 1;
        dev = rtnl_link_veth_alloc();
        pdev = rtnl_link_veth_get_peer(dev);
        // set attribs
        rtnl_link_set_name(dev, intf->name);
        rtnl_link_set_name(pdev, peer->name);
        // set netns
        nsfile = tn_host_ns_file(intf->host);
        pnsfile = tn_host_ns_file(peer->host);
        rtnl_link_set_ns_fd(dev, fileno(nsfile));
        rtnl_link_set_ns_fd(pdev, fileno(pnsfile));
        // send req
        if ((err = rtnl_link_add(nlsock, dev, NLM_F_CREATE)) < 0) {
            fprintf(stderr, "can't create interface: %s\n", nl_geterror(err));
            exit(1);
        }
        // clean up
        rtnl_link_veth_release(dev);
        fclose(nsfile);
        fclose(pnsfile);
    } else {
        intf->is_added = 1;
        dev = rtnl_link_alloc();
        // set attribs
        rtnl_link_set_name(dev, intf->name);
        rtnl_link_set_type(dev, "dummy");
        // set netns
        nsfile = tn_host_ns_file(intf->host);
        rtnl_link_set_ns_fd(dev, fileno(nsfile));
        // send req
        if ((err = rtnl_link_add(nlsock, dev, NLM_F_CREATE)) < 0) {
            fprintf(stderr, "can't create interface: %s\n", nl_geterror(err));
            exit(1);
        }
        // clean up
        rtnl_link_put(dev);
        fclose(nsfile);
    }
}

/*
    - /run/tomnet
        - sim
            - 73847632874843
                - hosts
                    - h1
                    - h2
                    - h3
            - user-provided-name
                - hosts
                    - h1
                    - h2
        - lockfile
*/

FILE *tn_lock()
{
    int mode = 0664;
    mkdir("/run/tomnet", mode);
    FILE *lockfile = fopen(LOCKFILE_PATH,"w+");
    if(!lockfile) {
        perror("Failed to gain lock");
        exit(1);
    }
    if(mkdir("/run/tomnet/sim", mode) == 0) {
        if (mount("", "/run/tomnet/sim", "tmpfs", MS_SHARED | MS_REC, NULL) < -1) {
            perror("Failed to mount Tomnet tmpfs");
            exit(1);
        }
    }
    lockf(fileno(lockfile), F_LOCK, 0);
    return lockfile;
}

void tn_unlock(FILE *lockfile)
{
    lockf(fileno(lockfile), F_ULOCK, 0);
    fclose(lockfile);
}

enum {
    OP_UNKNOWN,
    OP_UP,
    OP_DOWN,
    OP_LIST,
    OP_RUN,
    OP_SHOW,
    OP_PARSE
};

typedef struct {
    int operation;
    char *path;
    char *name;
    char *host;
    char *run_program;
    char **run_argv;
    int run_argc;
} tn_args;

void cli_list(tn_args args)
{
    DIR *dir = opendir(NETNS_MOUNT_DIR);
    (void)args;
    if(dir) {
        struct dirent *ent;
        int i = 0;
        while((ent = readdir(dir))) {
            if (i >= 2) {
               printf("%s\n",ent->d_name);
            }
            i++;
        }
    }
}

void cli_show(tn_args args)
{
    char path_buf[512];
    snprintf(path_buf, sizeof(path_buf), NETNS_MOUNT_DIR "/%s/hosts/", args.name);
    DIR *dir = opendir(path_buf);
    if(dir) {
        struct dirent *ent;
        int i = 0;
        while((ent = readdir(dir))) {
            if (i >= 2) {
                printf("%s\n",ent->d_name);
            }
            i++;
        }
    } else {
        fprintf(stderr, "Simulation '%s' does not exist\n", args.name);
        exit(1);
    }
}

void cli_run(tn_args args)
{
    FILE *nsfile;
    DIR *simdir;
    char path_buf[512];
    int len, pid = 0;
        len = snprintf(path_buf, sizeof(path_buf), NETNS_MOUNT_DIR "/%s", args.name);
        simdir = opendir(path_buf);
        if(!simdir) {
            fprintf(stderr, "Simulation '%s' not found\n", args.name);
            exit(1);
        }
        snprintf(path_buf + len, sizeof(path_buf) - len, "/hosts/%s", args.host);
        nsfile = fopen(path_buf, "r");
        if(!nsfile) {
            fprintf(stderr, "Host '%s' in simulation '%s' not found\n", args.host, args.name);
            exit(1);
        }
        if (setns(fileno(nsfile), CLONE_NEWNET) == -1) {
            perror("Failed to attach to namespace");
            exit(1);
        }
        fclose(nsfile);
        if(execvp(args.run_program, args.run_argv)) {
            perror("Failed to execute");
            exit(1);
        }
    if(!pid) {
    } else {
        int st;
        waitpid(pid, &st, 0);
        if (WEXITSTATUS(st)) {
            exit(WEXITSTATUS(st));
        }
    } 
}

void cli_down(tn_args args)
{
    FILE *lockfile;
    char path_buf[512];
    int len = snprintf(path_buf, sizeof(path_buf), NETNS_MOUNT_DIR "/%s/hosts/", args.name);
    lockfile = tn_lock();
    DIR *dir = opendir(path_buf);
    if(dir) {
        struct dirent *ent;
        int i = 0;
        while((ent = readdir(dir))) {
            if (i >= 2) {
                sprintf(path_buf + len, "%s", ent->d_name);
                if(umount(path_buf) < 0) {
                    perror("FATAL");
                    exit(1);
                }
                if(remove(path_buf) < 0) {
                    perror("FATAL");
                    exit(1);
                }
            }
            i++;
        }
        path_buf[len] = 0;
        rmdir(path_buf);
        snprintf(path_buf, sizeof(path_buf), NETNS_MOUNT_DIR "/%s/", args.name);
        rmdir(path_buf);
        tn_unlock(lockfile);
    } else {
        fprintf(stderr, "Simulation is not running\n");
        exit(1);
    }
}

void cli_up(tn_args args)
{
    tn_host **host;
    tn_intf **intf;
    struct nl_sock *nlsock;
    tn_root *root;
    FILE *lockfile;
    int err, len;
    char buf[64];

    root = tn_eval(args.path);
    if(root->has_error) {
        exit(1);
    }
    nlsock = nl_socket_alloc();
    if(nl_connect(nlsock,NETLINK_ROUTE) != 0) {
        printf("Can't create rt_netlink socket\n");
        exit(1);
    }
    if(args.name) {
        len = snprintf(root->name, sizeof(root->name), "%s", args.name);
    } else {
        len = snprintf(root->name, sizeof(root->name), "%08x", root->checksum);
    }
    len = snprintf(buf, sizeof(buf), NETNS_MOUNT_DIR "/%s", root->name);
    lockfile = tn_lock();
    if((err = mkdir(buf,774)) < 0)
    {
        if(errno == EEXIST) {
            fprintf(stderr,"Simulation already up\n");
            if(!args.name) {
                fprintf(stderr,"If you want to run it anyway, run again with '-n <NAME>'\n");
            }
        } else {
            perror("Failed to start simulation");
        }
        exit(1);
    }
    snprintf(buf + len, sizeof(buf) - len, "/hosts");
    mkdir(buf,774);
    vec_foreach(host, root->hosts_v) {
        tn_create_host(*host);
    }
    vec_foreach(host, root->hosts_v) {
        vec_foreach(intf, (*host)->intf_v) {
            tn_create_intf(*intf, nlsock);
        }
    }
    vec_foreach(host, root->hosts_v) {
        tn_up_hosts(*host);
    }
    tn_unlock(lockfile);
    nl_close(nlsock);
    nl_socket_free(nlsock);
    if(!args.name) {
        fprintf(stderr,"%s\n", root->name);
    }
}

void print_help()
{
    printf(
        "Usage: tomnet <up|parse> CONFIG\n"
        "       tomnet <down|show> SIM\n"
        "       tomnet run SIM HOST CMD...\n"
        "       tomnet list\n"
        "\n"
        "   options:\n"
        "       -n  --name              assign name to new simulation\n"
    );
}

int parse_op(const char *str) {
    if(!strcmp(str,"up"))
        return OP_UP;
    if(!strcmp(str,"down"))
        return OP_DOWN;
    if(!strcmp(str,"run"))
        return OP_RUN;
    if(!strcmp(str,"list"))
        return OP_LIST;
    if(!strcmp(str,"show"))
        return OP_SHOW;
    if(!strcmp(str,"parse"))
        return OP_PARSE;
    return OP_UNKNOWN;
}

int main(int argc, char **argv)
{
    tn_args args;
    int option_index, c;

    struct option long_options[] = {
      {"name",  required_argument, 0, 'n'},
      {0, 0, 0, 0}
    };

    if(geteuid() != 0) {
        fprintf(stderr,"Tomnet requires root priviledges, run again as root");
        return 1;
    }

    args.path = NULL;
    args.name = NULL;
    args.host = NULL;
    args.run_program = NULL;
    args.run_argv = NULL;
    args.run_argc = 0;

    if(argc == 1) {
        print_help();
        return 1;
    }
    args.operation = parse_op(argv[1]);
    if(args.operation == OP_UNKNOWN) {
        fprintf(stderr, "Unknown operation '%s'\n", argv[1]);
        print_help();
        return 1;
    }
    argv++;
    argc--;

    while(1) {
        c = getopt_long(argc, argv, "n:", long_options, &option_index);
        if (c == -1)
            break;
        switch(c) {
            case 0:
                break;
            case 'n':
                args.name = optarg;
                break;
            default:
                fprintf(stderr, "Unknown option: '-%c'\n", c);
                break;
        }
    }

#define expect_arg(NAME, FIELD)    \
    if(optind < argc) { \
        args.FIELD = argv[optind++];   \
    } else {    \
        fprintf(stderr, NAME " expected.\n");    \
        print_help();   \
        return 1;   \
    }
    
    if(args.operation == OP_UP) {
        expect_arg("TOML file", path);
        cli_up(args);
    } else if(args.operation == OP_DOWN) {
        expect_arg("Simulation name", name);
        cli_down(args);
    } else if(args.operation == OP_RUN) {
        expect_arg("Simulation name", name);
        expect_arg("Host name", host);
        expect_arg("Command", run_program);
        args.run_argv = argv + optind - 1;
        args.run_argc = argc - optind;
        cli_run(args);
    } else if(args.operation == OP_SHOW) {
        expect_arg("Simulation name", name);
        cli_show(args);
    } else if(args.operation == OP_LIST) {
        cli_list(args);
    }
    return 0;
}