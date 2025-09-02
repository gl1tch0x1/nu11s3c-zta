/*
 * eBPF Integration for AppArmor Zero Trust Architecture
 * 
 * This eBPF program provides advanced runtime monitoring and policy enforcement
 * for the AppArmor Zero Trust system.
 */

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_EVENTS 1000
#define MAX_PATH_LEN 256
#define MAX_ARGS 10
#define MAX_NETWORK_RULES 100

/* Event types for monitoring */
enum event_type {
    EVENT_SYSCALL_ENTER = 1,
    EVENT_SYSCALL_EXIT,
    EVENT_FILE_ACCESS,
    EVENT_NETWORK_ACCESS,
    EVENT_PROCESS_CREATE,
    EVENT_PROCESS_EXIT,
    EVENT_ANOMALY_DETECTED,
    EVENT_VIOLATION,
};

/* System call information */
struct syscall_info {
    __u64 timestamp;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u32 syscall_nr;
    __s32 result;
    __u64 duration;
    char comm[TASK_COMM_LEN];
    char exe_path[MAX_PATH_LEN];
    char args[MAX_ARGS][MAX_PATH_LEN];
};

/* File access information */
struct file_access_info {
    __u64 timestamp;
    __u32 pid;
    __u32 uid;
    __u32 gid;
    __u32 operation;  // 1=read, 2=write, 3=execute, 4=create, 5=delete
    char file_path[MAX_PATH_LEN];
    __u64 file_size;
    __u32 permissions;
};

/* Network access information */
struct network_access_info {
    __u64 timestamp;
    __u32 pid;
    __u32 uid;
    __u32 gid;
    __u32 protocol;  // 1=TCP, 2=UDP, 3=ICMP, 4=RAW
    __u16 port;
    __u32 address;
    __u32 direction;  // 1=inbound, 2=outbound
    char comm[TASK_COMM_LEN];
};

/* Process information */
struct process_info {
    __u64 timestamp;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u32 event_type;  // 1=create, 2=exit
    char comm[TASK_COMM_LEN];
    char exe_path[MAX_PATH_LEN];
    char args[MAX_ARGS][MAX_PATH_LEN];
};

/* Anomaly detection information */
struct anomaly_info {
    __u64 timestamp;
    __u32 pid;
    __u32 uid;
    __u32 gid;
    __u32 anomaly_type;
    __u32 severity;  // 1=low, 2=medium, 3=high, 4=critical
    __u32 confidence;
    char description[128];
    char comm[TASK_COMM_LEN];
};

/* Security violation information */
struct violation_info {
    __u64 timestamp;
    __u32 pid;
    __u32 uid;
    __u32 gid;
    __u32 violation_type;
    __u32 severity;
    char resource[MAX_PATH_LEN];
    char action[64];
    char comm[TASK_COMM_LEN];
};

/* Unified event structure */
struct apparmor_event {
    __u32 event_type;
    __u32 data_len;
    union {
        struct syscall_info syscall;
        struct file_access_info file_access;
        struct network_access_info network_access;
        struct process_info process;
        struct anomaly_info anomaly;
        struct violation_info violation;
    } data;
};

/* Network microsegmentation rules */
struct network_rule {
    __u32 protocol;
    __u16 port;
    __u32 address;
    __u32 netmask;
    __u32 action;  // 1=allow, 2=deny, 3=audit
    __u32 priority;
};

/* Conditional policy rules */
struct conditional_rule {
    __u32 condition_type;
    __u32 condition_value;
    __u32 action;
    __u32 priority;
    __u32 confidence;
};

/* AppArmor profile information */
struct apparmor_profile {
    __u32 profile_id;
    __u32 enforcement_mode;  // 1=enforce, 2=complain, 3=audit
    __u32 risk_score;
    __u32 rule_count;
    __u32 violation_count;
    char profile_name[64];
};

/* Statistics and counters */
struct apparmor_stats {
    __u64 total_events;
    __u64 syscall_events;
    __u64 file_events;
    __u64 network_events;
    __u64 process_events;
    __u64 anomaly_events;
    __u64 violation_events;
    __u64 denied_operations;
    __u64 allowed_operations;
    __u64 audited_operations;
};

/* Maps for data storage and communication */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct apparmor_profile);
    __uint(max_entries, 1000);
} profiles SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct network_rule);
    __uint(max_entries, MAX_NETWORK_RULES);
} network_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct conditional_rule);
    __uint(max_entries, 1000);
} conditional_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1000);
} process_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct apparmor_stats);
    __uint(max_entries, 1);
} global_stats SEC(".maps");

/* Helper functions */
static inline __u64 get_timestamp(void) {
    return bpf_ktime_get_ns();
}

static inline int get_current_pid(void) {
    return bpf_get_current_pid_tgid() >> 32;
}

static inline int get_current_uid(void) {
    return bpf_get_current_uid_gid() & 0xFFFFFFFF;
}

static inline int get_current_gid(void) {
    return bpf_get_current_uid_gid() >> 32;
}

static inline void get_current_comm(char *comm) {
    bpf_get_current_comm(comm, TASK_COMM_LEN);
}

/* Network rule matching */
static inline int match_network_rule(__u32 protocol, __u16 port, __u32 address) {
    struct network_rule *rule;
    __u32 key;
    
    for (key = 0; key < MAX_NETWORK_RULES; key++) {
        rule = bpf_map_lookup_elem(&network_rules, &key);
        if (!rule) continue;
        
        if (rule->protocol == protocol && 
            (rule->port == 0 || rule->port == port) &&
            (rule->address == 0 || (address & rule->netmask) == (rule->address & rule->netmask))) {
            return rule->action;
        }
    }
    
    return 2; // Default deny
}

/* Conditional rule evaluation */
static inline int evaluate_conditional_rule(__u32 condition_type, __u32 condition_value) {
    struct conditional_rule *rule;
    __u32 key;
    
    for (key = 0; key < 1000; key++) {
        rule = bpf_map_lookup_elem(&conditional_rules, &key);
        if (!rule) continue;
        
        if (rule->condition_type == condition_type) {
            // Simple condition evaluation - can be extended
            if (condition_value >= rule->condition_value) {
                return rule->action;
            }
        }
    }
    
    return 1; // Default allow
}

/* Anomaly detection */
static inline int detect_anomaly(__u32 pid, __u32 syscall_nr, __u64 timestamp) {
    __u64 *last_call_time;
    __u32 *call_count;
    __u64 current_time = get_timestamp();
    
    // Check for rapid system calls (potential DoS)
    last_call_time = bpf_map_lookup_elem(&process_stats, &pid);
    if (last_call_time) {
        if (current_time - *last_call_time < 1000000) { // Less than 1ms
            return 1; // Anomaly detected
        }
    }
    
    // Update last call time
    bpf_map_update_elem(&process_stats, &pid, &current_time, BPF_ANY);
    
    return 0; // No anomaly
}

/* Update global statistics */
static inline void update_stats(__u32 event_type) {
    struct apparmor_stats *stats;
    __u32 key = 0;
    
    stats = bpf_map_lookup_elem(&global_stats, &key);
    if (!stats) return;
    
    stats->total_events++;
    
    switch (event_type) {
        case EVENT_SYSCALL_ENTER:
        case EVENT_SYSCALL_EXIT:
            stats->syscall_events++;
            break;
        case EVENT_FILE_ACCESS:
            stats->file_events++;
            break;
        case EVENT_NETWORK_ACCESS:
            stats->network_events++;
            break;
        case EVENT_PROCESS_CREATE:
        case EVENT_PROCESS_EXIT:
            stats->process_events++;
            break;
        case EVENT_ANOMALY_DETECTED:
            stats->anomaly_events++;
            break;
        case EVENT_VIOLATION:
            stats->violation_events++;
            break;
    }
}

/* System call tracepoint */
SEC("tp/syscalls/sys_enter_openat")
int trace_sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    struct apparmor_event *event;
    struct syscall_info *syscall_info;
    __u32 pid = get_current_pid();
    __u64 timestamp = get_timestamp();
    
    // Check for anomalies
    if (detect_anomaly(pid, ctx->id, timestamp)) {
        // Log anomaly event
        event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
        if (!event) return 0;
        
        event->event_type = EVENT_ANOMALY_DETECTED;
        event->data.anomaly.timestamp = timestamp;
        event->data.anomaly.pid = pid;
        event->data.anomaly.uid = get_current_uid();
        event->data.anomaly.gid = get_current_gid();
        event->data.anomaly.anomaly_type = 1; // Rapid syscalls
        event->data.anomaly.severity = 2; // Medium
        event->data.anomaly.confidence = 80;
        bpf_probe_read_str(event->data.anomaly.description, 
                          sizeof(event->data.anomaly.description), 
                          "Rapid system calls detected");
        get_current_comm(event->data.anomaly.comm);
        
        bpf_ringbuf_submit(event, 0);
        update_stats(EVENT_ANOMALY_DETECTED);
    }
    
    // Log system call event
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) return 0;
    
    event->event_type = EVENT_SYSCALL_ENTER;
    syscall_info = &event->data.syscall;
    
    syscall_info->timestamp = timestamp;
    syscall_info->pid = pid;
    syscall_info->ppid = 0; // Would need to get from task_struct
    syscall_info->uid = get_current_uid();
    syscall_info->gid = get_current_gid();
    syscall_info->syscall_nr = ctx->id;
    syscall_info->result = 0; // Will be set on exit
    syscall_info->duration = 0; // Will be calculated on exit
    get_current_comm(syscall_info->comm);
    
    // Get file path from arguments
    if (ctx->args[1]) { // filename
        bpf_probe_read_user_str(syscall_info->args[0], 
                               sizeof(syscall_info->args[0]), 
                               (void *)ctx->args[1]);
    }
    
    bpf_ringbuf_submit(event, 0);
    update_stats(EVENT_SYSCALL_ENTER);
    
    return 0;
}

/* System call exit tracepoint */
SEC("tp/syscalls/sys_exit_openat")
int trace_sys_exit_openat(struct trace_event_raw_sys_exit *ctx) {
    struct apparmor_event *event;
    struct syscall_info *syscall_info;
    __u32 pid = get_current_pid();
    __u64 timestamp = get_timestamp();
    
    // Log system call exit event
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) return 0;
    
    event->event_type = EVENT_SYSCALL_EXIT;
    syscall_info = &event->data.syscall;
    
    syscall_info->timestamp = timestamp;
    syscall_info->pid = pid;
    syscall_info->ppid = 0;
    syscall_info->uid = get_current_uid();
    syscall_info->gid = get_current_gid();
    syscall_info->syscall_nr = ctx->id;
    syscall_info->result = ctx->ret;
    syscall_info->duration = 0; // Would need to calculate from enter time
    get_current_comm(syscall_info->comm);
    
    bpf_ringbuf_submit(event, 0);
    update_stats(EVENT_SYSCALL_EXIT);
    
    return 0;
}

/* Network socket creation */
SEC("kprobe/sys_socket")
int trace_socket_create(struct pt_regs *ctx) {
    struct apparmor_event *event;
    struct network_access_info *network_info;
    __u32 pid = get_current_pid();
    __u64 timestamp = get_timestamp();
    int domain = PT_REGS_PARM1(ctx);
    int type = PT_REGS_PARM2(ctx);
    int protocol = PT_REGS_PARM3(ctx);
    
    // Map socket parameters to our format
    __u32 protocol_type = 0;
    if (domain == AF_INET) {
        if (type == SOCK_STREAM) protocol_type = 1; // TCP
        else if (type == SOCK_DGRAM) protocol_type = 2; // UDP
        else if (type == SOCK_RAW) protocol_type = 4; // RAW
    }
    
    // Check network rules
    int action = match_network_rule(protocol_type, 0, 0);
    if (action == 2) { // Deny
        // Log violation
        event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
        if (!event) return 0;
        
        event->event_type = EVENT_VIOLATION;
        event->data.violation.timestamp = timestamp;
        event->data.violation.pid = pid;
        event->data.violation.uid = get_current_uid();
        event->data.violation.gid = get_current_gid();
        event->data.violation.violation_type = 1; // Network violation
        event->data.violation.severity = 3; // High
        bpf_probe_read_str(event->data.violation.resource, 
                          sizeof(event->data.violation.resource), 
                          "socket");
        bpf_probe_read_str(event->data.violation.action, 
                          sizeof(event->data.violation.action), 
                          "create");
        get_current_comm(event->data.violation.comm);
        
        bpf_ringbuf_submit(event, 0);
        update_stats(EVENT_VIOLATION);
        
        return -1; // Deny the operation
    }
    
    // Log network access event
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) return 0;
    
    event->event_type = EVENT_NETWORK_ACCESS;
    network_info = &event->data.network_access;
    
    network_info->timestamp = timestamp;
    network_info->pid = pid;
    network_info->uid = get_current_uid();
    network_info->gid = get_current_gid();
    network_info->protocol = protocol_type;
    network_info->port = 0; // Will be set on bind/connect
    network_info->address = 0;
    network_info->direction = 0; // Will be determined later
    get_current_comm(network_info->comm);
    
    bpf_ringbuf_submit(event, 0);
    update_stats(EVENT_NETWORK_ACCESS);
    
    return 0;
}

/* Process creation */
SEC("tp/sched/sched_process_fork")
int trace_process_fork(struct trace_event_raw_sched_process_fork *ctx) {
    struct apparmor_event *event;
    struct process_info *process_info;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 timestamp = get_timestamp();
    
    // Log process creation event
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) return 0;
    
    event->event_type = EVENT_PROCESS_CREATE;
    process_info = &event->data.process;
    
    process_info->timestamp = timestamp;
    process_info->pid = pid;
    process_info->ppid = ctx->parent_pid;
    process_info->uid = get_current_uid();
    process_info->gid = get_current_gid();
    process_info->event_type = 1; // Create
    get_current_comm(process_info->comm);
    
    bpf_ringbuf_submit(event, 0);
    update_stats(EVENT_PROCESS_CREATE);
    
    return 0;
}

/* Process exit */
SEC("tp/sched/sched_process_exit")
int trace_process_exit(struct trace_event_raw_sched_process_exit *ctx) {
    struct apparmor_event *event;
    struct process_info *process_info;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 timestamp = get_timestamp();
    
    // Log process exit event
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) return 0;
    
    event->event_type = EVENT_PROCESS_EXIT;
    process_info = &event->data.process;
    
    process_info->timestamp = timestamp;
    process_info->pid = pid;
    process_info->ppid = 0; // Would need to get from task_struct
    process_info->uid = get_current_uid();
    process_info->gid = get_current_gid();
    process_info->event_type = 2; // Exit
    get_current_comm(process_info->comm);
    
    bpf_ringbuf_submit(event, 0);
    update_stats(EVENT_PROCESS_EXIT);
    
    return 0;
}

/* File access monitoring */
SEC("kprobe/vfs_read")
int trace_file_read(struct pt_regs *ctx) {
    struct apparmor_event *event;
    struct file_access_info *file_info;
    __u32 pid = get_current_pid();
    __u64 timestamp = get_timestamp();
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    
    // Log file access event
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) return 0;
    
    event->event_type = EVENT_FILE_ACCESS;
    file_info = &event->data.file_access;
    
    file_info->timestamp = timestamp;
    file_info->pid = pid;
    file_info->uid = get_current_uid();
    file_info->gid = get_current_gid();
    file_info->operation = 1; // Read
    file_info->file_size = 0; // Would need to get from file
    file_info->permissions = 0; // Would need to get from file
    
    // Get file path (simplified)
    bpf_probe_read_str(file_info->file_path, 
                      sizeof(file_info->file_path), 
                      "unknown");
    
    bpf_ringbuf_submit(event, 0);
    update_stats(EVENT_FILE_ACCESS);
    
    return 0;
}

/* License and version */
char LICENSE[] SEC("license") = "GPL";
__u32 VERSION SEC("version") = 0xFFFFFFFE;
