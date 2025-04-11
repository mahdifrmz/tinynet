#define _GNU_SOURCE
#include <getopt.h>
#include <stdio.h>
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
#include <sys/sysinfo.h>
#include <net/if.h>
#include <errno.h>
#include <dirent.h>
#include <netlink/netlink.h>
#include <netlink/route/rtnl.h>
#include <netlink/route/link.h>
#include <netlink/route/addr.h>
#include <netlink/route/link/veth.h>
#include <fcntl.h>
#include <assert.h>
#include "ll.h"
#include "vec.h"
#include "parse.h"
#include "entity.h"
#include "vm.h"

#define COLOR_RED   "\x1B[31m"
#define COLOR_GREEN   "\x1B[32m"
#define COLOR_YELLOW   "\x1B[33m"
#define COLOR_BLUE   "\x1B[34m"
#define COLOR_MAGENTA   "\x1B[35m"
#define COLOR_CYAN   "\x1B[36m"
#define COLOR_WHITE   "\x1B[37m"
#define COLOR_RESET "\x1B[0m"

#define NETNS_MOUNT_DIR "/run/tinynet/sim"
#define LOCKFILE_PATH "/run/tinynet/lock"

#define MAX_HOST_NAME 256
#define MAX_HOST_NAME_STR "256"
#define MAX_IF_NAME 15
#define MAX_IF_NAME_STR "15"

#define ARRAY_LEN(A) (sizeof(A)/sizeof(*A))

typedef struct {
    int operation;
    int verbose;
    char *path;
    char *name;
    char *host;
    char *run_program;
    char **run_argv;
    int run_argc;
} tn_args;

enum {
    OP_UNKNOWN,
    OP_UP,
    OP_DOWN,
    OP_LIST,
    OP_RUN,
    OP_SHOW,
    OP_PARSE,
    OP_TEST
};

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
                    fprintf(stderr, "[Link Error]: no host '%s' | host:%s , iface:%s",
                        intf->peer_host_s,
                        host->name,
                        intf->name);
                    root->has_error = 1;
                    continue;
                }
                other_intf = tn_lookup_intf(other_host, intf->peer_intf_s);
                if(!other_intf) {
                    fprintf(stderr, "[Link Error]: no interface '%s' in host '%s' | host:%s , iface:%s", 
                        intf->peer_intf_s, 
                        intf->peer_host_s, 
                        host->name, 
                        intf->name);
                    root->has_error = 1;
                    continue;
                }
                if(intf->peer && intf->peer != other_intf) {
                    fprintf(stderr, "[Link Error] alreay connected to %s/%s | host:%s , iface:%s", 
                        intf->peer->host->name, 
                        intf->peer->name,
                        host->name,
                        intf->name);
                    root->has_error = 1;
                    continue;
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
        exit(1);
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

void command_exec(const char *sim_name, const char *host_name, char *program, char **argv)
{
    FILE *nsfile;
    DIR *simdir;
    char path_buf[512];
    int len;
    len = snprintf(path_buf, sizeof(path_buf), NETNS_MOUNT_DIR "/%s", sim_name);
    simdir = opendir(path_buf);
    if(!simdir) {
        fprintf(stderr, "Simulation '%s' not found\n", sim_name);
        exit(1);
    }
    snprintf(path_buf + len, sizeof(path_buf) - len, "/hosts/%s", host_name);
    nsfile = fopen(path_buf, "r");
    if(!nsfile) {
        fprintf(stderr, "Host '%s' in simulation '%s' not found\n", host_name, sim_name);
        exit(1);
    }
    if (setns(fileno(nsfile), CLONE_NEWNET) == -1) {
        perror("Failed to attach to namespace");
        exit(1);
    }
    fclose(nsfile);
    execvp(program, argv);
    exit(127);
}

void close_fd(int fd)
{
    int new_fd = fd;
    do {
        close(new_fd);
        new_fd = open("/dev/null", O_WRONLY);
    } while(new_fd != fd);
}

int tn_execute_cmd(tn_root *root, tn_cmd *cmd, tn_args *args)
{
    tn_host *host = cmd->list->host;
    int pid = fork();
    if(!pid) {
        if (!args->verbose) {
            close_fd(STDOUT_FILENO);
            close_fd(STDERR_FILENO);
        }
        if(cmd->is_daemon) {
            setsid();
        }
        command_exec(host->root->name, host->name, cmd->argv->args_v[0], cmd->argv->args_v);
        return -1; // never reaches
    } else {
        return pid;
    }
}

void print_command_error(tn_cmd *cmd, int st)
{
    char **buf;
    int is_first = 1;
    fprintf(stderr, "TinyNet: command '");
    vec_foreach(buf, cmd->argv->args_v) {
        if(!*buf) {
            break;
        }
        if(!is_first) {
            fprintf(stderr, " ");
        }
        fprintf(stderr, "%s", *buf);
        is_first = 0;
    }
    if(WEXITSTATUS(st) == 127) {
        fprintf(stderr, "' in host '%s' does not exist\n", cmd->list->host->name);
    } else {
        fprintf(stderr, "' in host '%s' failed with status code '%d'\n", cmd->list->host->name, WEXITSTATUS(st));
    }
}

int tn_execute_lists_sequential(tn_root *root, tn_args *args, int is_test_run)
{
    tn_host **h, *host;
    tn_cmdlist **l, *list;
    tn_cmd **c, *cmd;
    int pid, st, failure = 0, list_failure;
    vec_foreach(h, root->hosts_v) {
        host = *h;
        vec_foreach(l, host->cmdlists_v) {
            list = *l;
            if(list->is_test != is_test_run) {
                continue;
            }
            list_failure = 0;
            vec_foreach(c, list->cmds_v) {
                cmd = *c;
                pid = tn_execute_cmd(root,cmd,args);
                if(!cmd->is_daemon) {
                    waitpid(pid,&st,0);
                    if(WEXITSTATUS(st) != cmd->expected_status) {
                        failure = 1;
                        print_command_error(cmd, st);
                        list_failure = 1;
                        break;
                    }
                } else {
                    fprintf(root->pid_file, "%d\n", pid);
                }
            }
            if(list->is_test) {
                if(list_failure) {
                    fprintf(stderr, "TinyNet: test '%s'" COLOR_RED " failed.\n" COLOR_RESET, list->name);
                } else {
                    fprintf(stderr, "TinyNet: test '%s'" COLOR_GREEN " passed.\n" COLOR_RESET, list->name);
                }
            }
        }
    }
    return failure;
}

int tn_execute_lists_parallel(tn_root *root, tn_args *args, int is_test_run)
{
    tn_cmdlist **cmdlists_v = NULL, **c, *list;
    tn_host **h;
    tn_cmd *queue = NULL, *cmd = NULL;
    int cpu_count = get_nprocs();
    int proc_count = 0;
    int pid, st, failure = 0;

    vec_foreach(h, root->hosts_v) {
        vec_foreach(c, (*h)->cmdlists_v) {
            list = *c;
            if (list->is_test == is_test_run) {
                vec_push(cmdlists_v, *c);
            }
        }
    }
    vec_foreach(c, cmdlists_v) {
        list = *c;
        if(vec_len(list->cmds_v)) {
            ll_bpush(queue, list->cmds_v[0]);
            list->current_idx++;
        }
    }
    while(proc_count || queue) {
        while(proc_count < cpu_count && queue) {
            ll_fpop(queue, cmd);
            pid = tn_execute_cmd(root,cmd,args);            
            fprintf(root->pid_file, "%d\n", pid);
            if (cmd->is_daemon) {
                if(cmd->list->current_idx < vec_len(cmd->list->cmds_v)) {
                    ll_bpush(queue, cmd->list->cmds_v[cmd->list->current_idx]);
                    cmd->list->current_idx ++;
                } else {
                    if (list->is_test) {
                        fprintf(stderr, "TinyNet: test '%s'" COLOR_GREEN " passed.\n" COLOR_RESET, list->name);
                    }
                }
                cmd->list->current_pid = -1;
            } else {
                proc_count++;
                cmd->list->current_pid = pid;
            }
        }
        if(!proc_count) {
            break;
        }
        pid = wait(&st);
        vec_foreach(c, cmdlists_v) {
            list = *c;
            if(list->current_pid == pid) {
                list->current_pid = -1;
                cmd = list->cmds_v[list->current_idx-1];
                proc_count--;
                if(WEXITSTATUS(st) != cmd->expected_status) {
                    failure = 1;
                    print_command_error(cmd, st);
                    if (list->is_test) {
                        fprintf(stderr, "TinyNet: test '%s'" COLOR_RED " failed.\n" COLOR_RESET, list->name);
                    }
                } else {
                    if(list->current_idx < vec_len(list->cmds_v)) {
                        ll_bpush(queue, list->cmds_v[list->current_idx]);
                        list->current_idx ++;
                    } else {
                        if (list->is_test) {
                            fprintf(stderr, "TinyNet: test '%s'" COLOR_GREEN " passed.\n" COLOR_RESET, list->name);
                        }
                    }
                }
                break;
            }
        }
    }
    return failure;
}

void assure_root_user()
{
    if(geteuid() != 0) {
        fprintf(stderr,"tinynet requires root priviledges, run again as root");
        exit(1);
    }
}

/*
    - /run/tinynet
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
    mkdir("/run/tinynet", mode);
    FILE *lockfile = fopen(LOCKFILE_PATH,"w+");
    if(!lockfile) {
        perror("Failed to gain lock");
        exit(1);
    }
    if(mkdir("/run/tinynet/sim", mode) == 0) {
        if (mount("", "/run/tinynet/sim", "tmpfs", MS_SHARED | MS_REC, NULL) < -1) {
            perror("Failed to mount tinynet tmpfs");
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

void cli_list(tn_args args)
{
    assure_root_user();
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
    assure_root_user();
    command_exec(args.name, args.host, args.run_program, args.run_argv);
}

void cli_down(tn_args args)
{
    FILE *lockfile, *pid_file;
    char path_buf[512];
    assure_root_user();
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

        // read daemons.pid
        snprintf(path_buf, sizeof(path_buf), NETNS_MOUNT_DIR "/%s/daemons.pid", args.name);
        pid_file = fopen(path_buf,"r+");
        int count = 2, pid;
        char _c;
        while(count == 2) {
            count = fscanf(pid_file, "%d%c", &pid, &_c);
            kill(pid, SIGKILL);
        }
        
        fclose(pid_file);
        unlink(path_buf);

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
    int err, len, failure;
    char buf[512];

    root = tn_eval(args.path);
    if(root->has_error) {
        exit(1);
    }
    assure_root_user();
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
    // execute commands
    snprintf(buf, sizeof(buf), NETNS_MOUNT_DIR "/%s/daemons.pid", root->name);
    root->pid_file = fopen(buf, "w+");
    if(args.verbose) {
        failure = tn_execute_lists_sequential(root, &args, 0);
        if(args.operation == OP_TEST) {
            failure |= tn_execute_lists_sequential(root, &args, 1);
        }
    } else {
        failure = tn_execute_lists_parallel(root, &args, 0);
        if(args.operation == OP_TEST) {
            failure |= tn_execute_lists_parallel(root, &args, 1);
        }
    }
    fclose(root->pid_file);

    tn_unlock(lockfile);
    nl_close(nlsock);
    nl_socket_free(nlsock);
    if(args.operation == OP_UP && !args.name && args.operation != OP_TEST && !failure) {
        printf("%s\n", root->name);
    }
    if(failure || args.operation == OP_TEST) {
        args.name = root->name;
        cli_down(args);
    }
    exit(failure);
}

void print_help()
{
    printf(
        "Usage: tinynet <up|parse> CONFIG\n"
        "       tinynet <down|show> SIM\n"
        "       tinynet run SIM HOST CMD...\n"
        "       tinynet list\n"
        "\n"
        "   options:\n"
        "       -n  --name              assign name to new simulation\n"
    );
}

int parse_op(const char *str) {
    if(!strcmp(str,"up"))
        return OP_UP;
    if(!strcmp(str,"test"))
        return OP_TEST;
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

    args.path = NULL;
    args.name = NULL;
    args.host = NULL;
    args.run_program = NULL;
    args.run_argv = NULL;
    args.run_argc = 0;
    args.verbose = 0;

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
        c = getopt_long(argc, argv, "Vn:", long_options, &option_index);
        if (c == -1)
            break;
        switch(c) {
            case 0:
                break;
            case 'n':
                args.name = optarg;
                break;
            case 'V':
                args.verbose = 1;
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
        expect_arg("Topology file", path);
        cli_up(args);
    } else if(args.operation == OP_TEST) {
        expect_arg("Topology file", path);
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