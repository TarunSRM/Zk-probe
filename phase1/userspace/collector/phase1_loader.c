#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <net/if.h>

#include <openssl/sha.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define DETECTOR_VERSION "phase1-v0.1.0"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

struct zk_flow_stats {
    __u64 packets;
    __u64 bytes;
    __u64 syn;
};

struct phase1_snapshot {
    __u64 timestamp_ns;
    __u64 execve_count;
    __u32 flow_count;
    __u64 total_packets;
    __u64 total_bytes;
    __u64 syn_packets;
    unsigned char hash[32];
};

static void hash_snapshot(struct phase1_snapshot *s)
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    SHA256_Update(&ctx, &s->timestamp_ns, sizeof(s->timestamp_ns));
    SHA256_Update(&ctx, &s->execve_count, sizeof(s->execve_count));
    SHA256_Update(&ctx, &s->flow_count, sizeof(s->flow_count));
    SHA256_Update(&ctx, &s->total_packets, sizeof(s->total_packets));
    SHA256_Update(&ctx, &s->total_bytes, sizeof(s->total_bytes));
    SHA256_Update(&ctx, &s->syn_packets, sizeof(s->syn_packets));

    SHA256_Final(s->hash, &ctx);
}

static void print_usage(const char *prog)
{
    fprintf(stderr, "Phase 1 Invariant Collector - %s\n\n", DETECTOR_VERSION);
    fprintf(stderr, "Usage: %s [OPTIONS]\n\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -i, --interface <name>    Network interface to monitor (default: eth0)\n");
    fprintf(stderr, "  -b, --bpf-dir <path>      Directory containing BPF objects (default: ../../build/bpf)\n");
    fprintf(stderr, "  -s, --interval <seconds>  Snapshot interval in seconds (default: 1)\n");
    fprintf(stderr, "  -h, --help                Show this help message\n\n");
    fprintf(stderr, "Example:\n");
    fprintf(stderr, "  %s --interface ens33 --bpf-dir /path/to/bpf\n\n", prog);
}

int main(int argc, char **argv)
{
    const char *interface = "eth0";
    const char *bpf_dir = "../../build/bpf";
    int interval_sec = 1;
    
    /* Parse command-line arguments */
    int opt;
    struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"bpf-dir", required_argument, 0, 'b'},
        {"interval", required_argument, 0, 's'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    while ((opt = getopt_long(argc, argv, "i:b:s:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'i':
                interface = optarg;
                break;
            case 'b':
                bpf_dir = optarg;
                break;
            case 's':
                interval_sec = atoi(optarg);
                if (interval_sec <= 0) {
                    fprintf(stderr, "Error: Invalid interval '%s'\n", optarg);
                    return 1;
                }
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Build BPF object paths */
    char exec_path[512];
    char xdp_path[512];
    snprintf(exec_path, sizeof(exec_path), "%s/tracepoints/execve_counter.bpf.o", bpf_dir);
    snprintf(xdp_path, sizeof(xdp_path), "%s/xdp/xdp_counter.bpf.o", bpf_dir);

    /* ---- Open execve_counter BPF object ---- */
    struct bpf_object *exec_obj;
    exec_obj = bpf_object__open_file(exec_path, NULL);
    if (libbpf_get_error(exec_obj)) {
        fprintf(stderr, "Failed to open execve_counter BPF object at %s\n", exec_path);
        fprintf(stderr, "Make sure BPF objects are built: cd phase1 && make\n");
        return 1;
    }
    if (bpf_object__load(exec_obj)) {
        fprintf(stderr, "Failed to load execve_counter BPF object\n");
        return 1;
    }
    struct bpf_link *tp_link = bpf_program__attach_tracepoint(
        bpf_object__find_program_by_name(exec_obj, "trace_execve"),
        "syscalls", "sys_enter_execve"
    );
    if (libbpf_get_error(tp_link)) {
        fprintf(stderr, "Failed to attach execve tracepoint\n");
        return 1;
    }
    int exec_fd = bpf_object__find_map_fd_by_name(exec_obj, "execve_map");
    if (exec_fd < 0) {
        fprintf(stderr, "Failed to find execve_map\n");
        return 1;
    }

    /* ---- Open xdp_counter BPF object ---- */
    struct bpf_object *xdp_obj;
    xdp_obj = bpf_object__open_file(xdp_path, NULL);
    if (libbpf_get_error(xdp_obj)) {
        fprintf(stderr, "Failed to open xdp_counter BPF object at %s\n", xdp_path);
        fprintf(stderr, "Make sure BPF objects are built: cd phase1 && make\n");
        return 1;
    }
    if (bpf_object__load(xdp_obj)) {
        fprintf(stderr, "Failed to load xdp_counter BPF object\n");
        return 1;
    }
    
    int ifindex = if_nametoindex(interface);
    if (ifindex == 0) {
        fprintf(stderr, "Interface '%s' not found\n", interface);
        fprintf(stderr, "Available interfaces: ip link show\n");
        return 1;
    }
    
    struct bpf_link *xdp_link = bpf_program__attach_xdp(
        bpf_object__find_program_by_name(xdp_obj, "xdp_counter"),
        ifindex
    );
    if (libbpf_get_error(xdp_link)) {
        fprintf(stderr, "Failed to attach XDP program to interface %s\n", interface);
        fprintf(stderr, "Make sure you have CAP_NET_ADMIN privileges\n");
        return 1;
    }
    int flow_fd = bpf_object__find_map_fd_by_name(xdp_obj, "flow_map");
    if (flow_fd < 0) {
        fprintf(stderr, "Failed to find flow_map\n");
        return 1;
    }

    fprintf(stderr, "Phase-1 invariant collector running (%s)\n", DETECTOR_VERSION);
    fprintf(stderr, "Interface: %s (ifindex=%d)\n", interface, ifindex);
    fprintf(stderr, "Snapshot interval: %d second(s)\n", interval_sec);
    fprintf(stderr, "Press Ctrl+C to stop\n");
    fprintf(stderr, "----------------------------------------\n");

    /* Compute detector version hash */
    unsigned char detector_hash[32];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, DETECTOR_VERSION, strlen(DETECTOR_VERSION));
    SHA256_Final(detector_hash, &ctx);

    while (!exiting) {
        struct phase1_snapshot snap = {0};
        struct timespec ts;

        clock_gettime(CLOCK_MONOTONIC, &ts);
        snap.timestamp_ns = ts.tv_sec * 1000000000ULL + ts.tv_nsec;

        /* ---- execve map ---- */
        __u32 key = 0;
        if (bpf_map_lookup_elem(exec_fd, &key, &snap.execve_count) != 0) {
            snap.execve_count = 0;
        }

        /* ---- flow map ---- */
        __u32 cur = 0, next;
        struct zk_flow_stats stats;

        while (bpf_map_get_next_key(flow_fd, &cur, &next) == 0) {
            if (bpf_map_lookup_elem(flow_fd, &next, &stats) == 0) {
                snap.flow_count++;
                snap.total_packets += stats.packets;
                snap.total_bytes += stats.bytes;
                snap.syn_packets += stats.syn;
            }
            cur = next;
        }

        hash_snapshot(&snap);

        /* Output snapshot in Phase 1 format */
        printf(
            "T=%" PRIu64 " execve=%" PRIu64
            " flows=%" PRIu32 " packets=%" PRIu64
            " bytes=%" PRIu64 " syn=%" PRIu64 " hash=",
            (uint64_t)snap.timestamp_ns,
            (uint64_t)snap.execve_count,
            (uint32_t)snap.flow_count,
            (uint64_t)snap.total_packets,
            (uint64_t)snap.total_bytes,
            (uint64_t)snap.syn_packets
        );
        for (int i = 0; i < 32; i++)
            printf("%02x", snap.hash[i]);
        printf(" detector=");
        for (int i = 0; i < 32; i++)
            printf("%02x", detector_hash[i]);
        printf("\n");
        
        fflush(stdout);

        /* Clear maps for next interval to get per-second counts instead of cumulative */
        /* Clear flow_map */
        __u32 del_key = 0, del_next;
        while (bpf_map_get_next_key(flow_fd, &del_key, &del_next) == 0) {
            bpf_map_delete_elem(flow_fd, &del_next);
            del_key = del_next;
        }
        
        /* Clear execve_map */
        __u32 exec_key = 0;
        __u64 zero = 0;
        bpf_map_update_elem(exec_fd, &exec_key, &zero, BPF_ANY);

        sleep(interval_sec);
    }

    fprintf(stderr, "\nShutting down gracefully...\n");
    bpf_link__destroy(tp_link);
    bpf_link__destroy(xdp_link);
    bpf_object__close(exec_obj);
    bpf_object__close(xdp_obj);

    return 0;
}