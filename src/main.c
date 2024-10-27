#define _GNU_SOURCE
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
#include "ll.h"

#define NETNS_MOUNT_DIR "/run/tomnet/sim"
#define LOCKFILE_PATH "/run/tomnet/lock"

#define MAX_HOST_NAME 256
#define MAX_HOST_NAME_STR "256"
#define MAX_IF_NAME 15
#define MAX_IF_NAME_STR "15"

typedef struct tn_intf_t tn_intf_t;
typedef struct tn_host_t tn_host_t;
typedef struct tn_db_t tn_db_t;

struct tn_intf_t {
    char *name;
    int is_valid;
    int is_added;
    tn_host_t *host;
    tn_intf_t *created_for;
    tn_intf_t *link;
    tn_intf_t *ll_prev;
    tn_intf_t *ll_next;
    struct nl_addr *ip;
};

struct tn_host_t {
    char *name;
    int is_switch;
    int is_valid;
    tn_db_t *db;
    tn_intf_t *created_for;
    tn_intf_t *intfs_ll;
    tn_host_t *ll_next;
    tn_host_t *ll_prev;
};

struct tn_db_t {
    int pre_peered_count;
    int is_valid;
    tn_host_t *hosts_ll;
    uint32_t checksum;
};

typedef struct {
    tn_db_t *db;
    tn_host_t *cur_host;
} tn_parser_t;

tn_host_t *tn_lookup_host(tn_db_t *db, const char *name) {
    size_t idx;
    tn_host_t *host;
    if(!name[0]) {
        return NULL;
    }
    ll_foreach(db->hosts_ll, host, idx) {
        if(!strcmp(name,host->name)) {
            return host;
        }
    }
    return NULL;
}

tn_intf_t *tn_lookup_intf(tn_host_t* host, const char *name) {
    size_t idx;
    tn_intf_t *intf;
    if(!name[0]) {
        return NULL;
    }
    ll_foreach(host->intfs_ll, intf, idx) {
        if(!strcmp(name,intf->name)) {
            return intf;
        }
    }
    return NULL;
}

tn_host_t *tn_add_host(tn_db_t *db, const char *name) {
    tn_host_t *host = NULL;
    tn_host_t *lookup = tn_lookup_host(db, name);
    if (!lookup || !lookup->created_for) {
        host = malloc(sizeof(tn_host_t));
        host->name = strdup(name);
        host->is_switch = 0;
        host->intfs_ll = NULL;
        host->created_for = NULL;
        host->is_valid = !lookup && name[0];
        host->db = db;
        ll_bpush(db->hosts_ll, host);
    } else {
        host = lookup;
        db->pre_peered_count--;
    }
    host->created_for = NULL;
    return host;
}

tn_intf_t *tn_add_intf(tn_db_t *db, tn_host_t* host, const char *name) {
    tn_intf_t *intf = NULL; 
    tn_intf_t *lookup = tn_lookup_intf(host, name);
    if (!lookup || !lookup->created_for) {
        intf = malloc(sizeof(tn_intf_t));
        intf->name = strdup(name);
        intf->host = host;
        intf->created_for = NULL;
        intf->is_valid = !lookup && name[0];
        intf->ip = NULL;
        intf->link = NULL;
        intf->is_added = 0;
        ll_bpush(host->intfs_ll, intf);
    } else {
        db->pre_peered_count--;
        intf = lookup;
    }
    intf->created_for = NULL;
    return intf;
}

void tn_db_link(tn_db_t *db, tn_intf_t *intf, const char *peer_name, const char *peer_intf_name) {
    tn_host_t *peer = tn_lookup_host(db, peer_name);
    if(!peer) {
        peer = malloc(sizeof(tn_host_t));
        peer->name = strdup(peer_name);
        peer->is_switch = 0;
        peer->intfs_ll = NULL;
        peer->created_for = intf;
        peer->is_valid = 1;
        peer->db = db;
        ll_bpush(db->hosts_ll, peer);
        db->pre_peered_count++;
    }
    tn_intf_t *peer_intf = tn_lookup_intf(peer, peer_intf_name);
    if(!peer_intf) {
        peer_intf = malloc(sizeof(tn_intf_t));
        peer_intf->name = strdup(peer_intf_name);
        peer_intf->host = peer;
        peer_intf->link = intf;
        peer_intf->ip = NULL;
        peer_intf->created_for = intf;
        peer_intf->is_added = 0;
        peer_intf->is_valid = 1;
        ll_bpush(peer->intfs_ll, peer_intf);
        db->pre_peered_count++;
    }
    intf->link = peer_intf;
    peer_intf->link = intf;
}

FILE *tn_host_ns_file(tn_host_t *host)
{
    char buf[256];
    snprintf(buf,sizeof(buf), NETNS_MOUNT_DIR "/%08x/hosts/%s", host->db->checksum, host->name);
    return fopen(buf,"r");
}

void tn_parse_error(tn_parser_t *parser, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
    parser->db->is_valid = 0;
}
struct tn_intf_t *tn_lookup_intf_ip(tn_host_t *host, struct nl_addr *addr)
{
    tn_intf_t *intf;
    size_t _i;
    ll_foreach(host->intfs_ll, intf, _i) {
        if(intf->ip && nl_addr_cmp(intf->ip, addr) == 0) {
            return intf;
        }
    }
    return NULL;
}
void tn_parse_intf(tn_parser_t *parser, toml_table_t *tintf) {
    int err;
    toml_datum_t name = toml_string_in(tintf, "name");
    if(!name.ok || !name.u.s[0]) {
        tn_parse_error(parser, "Interface must have a name");
    }
    tn_intf_t *intf = tn_add_intf(parser->db, parser->cur_host, name.ok ? name.u.s : "");
    if(!intf->is_valid) {
        tn_parse_error(parser, "Interface name must be unique");
    }
    toml_datum_t ip = toml_string_in(tintf, "ip");
    if(ip.ok) {
        struct nl_addr *addr;
        if ((err = nl_addr_parse(ip.u.s, AF_INET, &addr)) < 0) {
            tn_parse_error(parser, "Invalid IP format");
        } else if (tn_lookup_intf_ip(parser->cur_host, addr)) {
            tn_parse_error(parser, "IP already set on another interface");
        } else {
            intf->ip = addr;
        }
    }
    toml_datum_t link = toml_string_in(tintf, "peer");
    if(link.ok && link.u.s[0]) {
        toml_datum_t link_if = toml_string_in(tintf, "peer-if");
        if(!link_if.ok || !link_if.u.s[0]) {
            tn_parse_error(parser, "Peer interface must be specified");
        } else {
            if(intf->link) {
                if(strcmp(intf->link->host->name, link.u.s) || strcmp(intf->link->name, link_if.u.s)) {
                    tn_parse_error(parser, "Interface already linked to another interface");
                }
            } else {
                tn_db_link(parser->db, intf, link.u.s, link_if.u.s);
            }
        }
    }
}

void tn_parse_host(tn_parser_t *parser, toml_table_t *thost) {
    toml_datum_t name = toml_string_in(thost, "name");
    if(!name.ok) {
        tn_parse_error(parser, "Host must have a name");
    }
    if(strlen(name.u.s) > MAX_HOST_NAME)
    {
        tn_parse_error(parser, "Host name maximum length is " MAX_HOST_NAME_STR);
    }
    tn_host_t *host = tn_add_host(parser->db, name.u.s);
    if(!host->is_valid) {
        tn_parse_error(parser, "Host name must be unique");
    }
    parser->cur_host = host;
    toml_array_t *intfs = toml_array_in(thost, "if");
    if(intfs) {
        int intfs_count = toml_array_nelem(intfs);
        for(int i=0; i<intfs_count; i++) {
            toml_table_t *tintf = toml_table_at(intfs, i);
            tn_parse_intf(parser, tintf);
        }
    }
    parser->cur_host = NULL;
}

void tn_parse_root(tn_parser_t *parser, toml_table_t *root) {
    toml_array_t *hosts = toml_array_in(root, "host");
    if(!hosts)
        return;
    int host_count = toml_array_nelem(hosts);
    for(int i=0; i<host_count; i++) {
        toml_table_t *host = toml_table_at(hosts, i);
        tn_parse_host(parser, host);
    }
}

tn_db_t *tn_db_new() {
    tn_db_t *db = malloc(sizeof(tn_db_t));
    db->hosts_ll = NULL;
    db->is_valid = 1;
    db->pre_peered_count = 0;
    db->checksum = 0;
    return db;
}

void tn_db_destroy(tn_db_t *db) {
    tn_host_t *host;
    tn_intf_t *intf;
    while(db->hosts_ll) {
        ll_fpop(db->hosts_ll, host);
        while(host->intfs_ll) {
            ll_fpop(host->intfs_ll, intf);
            free(intf->name);
            free(intf);        
        }
        free(host->name);
        free(host);
    }
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

tn_db_t *tn_parse(const char *file_path) {
    tn_parser_t parser;
    parser.cur_host = NULL;
    parser.db = tn_db_new();
    char errbuf[256];
    memset(errbuf, 0, sizeof(errbuf));
    FILE *file = fopen(file_path, "rb");
    if(!file) {
        tn_parse_error(&parser, "failed to open file: %s\n", file_path);
    } else {
        parser.db->checksum = checksum(file);
        toml_table_t *root = toml_parse_file(file, errbuf, sizeof(errbuf));
        if(!root) {
            tn_parse_error(&parser, "incorrect TOML format in file: %s\n%s\n", file_path, errbuf);
        }
        tn_parse_root(&parser, root);
        if(parser.db->pre_peered_count) {
            tn_host_t *host;
            tn_intf_t *intf;
            size_t _i, _j;
            ll_foreach(parser.db->hosts_ll, host, _j) {
                if(host->created_for) {
                    tn_parse_error(&parser, "Host %s refered to as peer, but not created explicitly\n", host->name);
                }
                ll_foreach(host->intfs_ll, intf, _i) {
                    tn_parse_error(&parser, "Interface %s/%s refered to as peer interface, but not created explicitly\n", host->name, intf->name);
                }    
            }
            parser.db->is_valid = 0;
        }
        if(!parser.db->is_valid) {
            tn_db_destroy(parser.db);
        }
    }
    return parser.db;
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

void tn_create_host(tn_host_t *host)
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
        snprintf(target_path, sizeof(target_path), NETNS_MOUNT_DIR "/%08x/hosts/%s", host->db->checksum, host->name);
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

void tn_up_hosts(tn_host_t *host)
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
                tn_intf_t *intf = tn_lookup_intf(host, name);
                if(intf->ip) {
                    struct rtnl_addr *rt_addr = rtnl_addr_alloc();
                    rtnl_addr_set_local(rt_addr, intf->ip);
                    rtnl_addr_set_prefixlen(rt_addr, nl_addr_get_prefixlen(intf->ip));
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

void tn_create_intf(tn_intf_t *intf, struct nl_sock *nlsock)
{
    int err;
    struct rtnl_link *dev, *pdev;
    FILE *nsfile, *pnsfile;
    tn_intf_t *peer;
    if(intf->is_added) {
        return;
    }
    if(intf->link) {
        peer = intf->link;
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
        if (rtnl_link_add(nlsock, dev, NLM_F_CREATE)) {
            printf("can't create interface");
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

void tn_sim_mkdir(tn_db_t *db)
{
    int err;
    char buf[64];
    snprintf(buf, sizeof(buf), NETNS_MOUNT_DIR "/%08x", db->checksum);
    if((err = mkdir(buf,774)) < 0)
    {
        if(errno == EEXIST) {
            fprintf(stderr,"Simulation already up; if you want to run it anyway, run again with '-n <NAME>'\n");
        } else {
            perror("Failed to start simulation");
        }
        exit(1);
    }
    snprintf(buf, sizeof(buf), NETNS_MOUNT_DIR "/%08x/hosts", db->checksum);
    mkdir(buf,774);
}

enum {
    OP_UP,
    OP_DOWN,
    OP_LIST,
};

void print_help()
{
    printf(
        "Usage: tomnet [operation] <toml file>\n"
        "       tomnet list\n"
        "\n"
        "   operation:\n"
        "       up (default)\n"
        "       down\n"
    );
}

int argparse_op(const char *str) {
    if(!strcmp(str,"up"))
        return OP_UP;
    if(!strcmp(str,"down"))
        return OP_DOWN;
    if(!strcmp(str,"list"))
        return OP_LIST;
    fprintf(stderr, "Unknown operation '%s'\n", str);
    print_help();
    exit(1);
}

void argparse(int argc, char **argv, int *op, char **path)
{
    if(argc < 2) {
        print_help();
        exit(1);
    }
    else if(argc == 2) {
        *op = argparse_op(argv[1]);
        if(*op != OP_LIST) {
            print_help();
            exit(1);
        }
    }
    else {
        *path = argv[2];
        *op = argparse_op(argv[1]);
    }
}

int main(int argc, char **argv)
{
    tn_host_t *host;
    tn_intf_t *intf;
    size_t _i, _j;
    struct nl_sock *nlsock;
    tn_db_t *db;
    FILE *lockfile;
    int op;
    char *path;

    argparse(argc, argv, &op, &path);

    if(geteuid() != 0) {
        fprintf(stderr,"Tomnet requires root priviledges, run again as root");
        exit(1);
    }

    if(op == OP_LIST) {
        DIR *dir = opendir(NETNS_MOUNT_DIR);
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
    } else if (op == OP_DOWN) {
        FILE *tomlfile = fopen(path, "r");
        if(!tomlfile) {
            fprintf(stderr, "failed to open file '%s'", path);
            exit(1);
        }
        uint32_t cs = checksum(tomlfile);
        fclose(tomlfile); 
        lockfile = tn_lock();
        char path_buf[512];
        int len = snprintf(path_buf, sizeof(path_buf), NETNS_MOUNT_DIR "/%08x/hosts/", cs);
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
            snprintf(path_buf, sizeof(path_buf), NETNS_MOUNT_DIR "/%08x/", cs);
            rmdir(path_buf);
            tn_unlock(lockfile);
        } else {
            fprintf(stderr, "Simulation is not running\n");
            return 1;
        }
    } else {
        db = tn_parse(path);
        if(!db->is_valid) {
            return 1;
        }
        nlsock = nl_socket_alloc();
        if(nl_connect(nlsock,NETLINK_ROUTE) != 0) {
            printf("Can't create rt_netlink socket\n");
            return 1;
        }
        lockfile = tn_lock();
        tn_sim_mkdir(db);
        ll_foreach(db->hosts_ll, host, _j) {
            tn_create_host(host);
        }
        ll_foreach(db->hosts_ll, host, _j) {
            ll_foreach(host->intfs_ll, intf, _i) {
                tn_create_intf(intf, nlsock);
            }
        }
        ll_foreach(db->hosts_ll, host, _j) {
            tn_up_hosts(host);
        }
        tn_unlock(lockfile);
        nl_close(nlsock);
        nl_socket_free(nlsock);
        return !db->is_valid;
    }
    return 0;
}