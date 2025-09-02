/*
 * Network Microsegmentation for AppArmor Parser
 * 
 * Extends profile syntax to enforce fine-grained network rules
 * beyond the basic network capability.
 */

#ifndef NETWORK_MICROSEGMENTATION_H
#define NETWORK_MICROSEGMENTATION_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Network protocol types */
typedef enum {
    NET_PROTO_INET = 0,
    NET_PROTO_INET6,
    NET_PROTO_UNIX,
    NET_PROTO_NETLINK,
    NET_PROTO_PACKET
} network_protocol_t;

/* Transport protocol types */
typedef enum {
    NET_TRANSPORT_TCP = 0,
    NET_TRANSPORT_UDP,
    NET_TRANSPORT_ICMP,
    NET_TRANSPORT_RAW,
    NET_TRANSPORT_STREAM,
    NET_TRANSPORT_SEQPACKET,
    NET_TRANSPORT_DGRAM
} network_transport_t;

/* Network rule types */
typedef enum {
    NET_RULE_CREATE = 0,
    NET_RULE_BIND,
    NET_RULE_LISTEN,
    NET_RULE_ACCEPT,
    NET_RULE_CONNECT,
    NET_RULE_SEND,
    NET_RULE_RECEIVE
} network_rule_type_t;

/* Network address structure */
typedef struct {
    uint8_t family;        /* AF_INET, AF_INET6, etc. */
    uint8_t addr[16];      /* IPv4 or IPv6 address */
    uint16_t port;         /* Port number (0 for any) */
    uint8_t prefix_len;    /* CIDR prefix length */
} network_address_t;

/* Network rule structure */
typedef struct {
    network_rule_type_t type;
    network_protocol_t protocol;
    network_transport_t transport;
    network_address_t local_addr;
    network_address_t remote_addr;
    uint32_t permissions;  /* CREATE, BIND, LISTEN, etc. */
    bool audit;
    bool deny;
    char *condition;       /* Optional condition string */
} network_rule_t;

/* Network rule list */
typedef struct network_rule_node {
    network_rule_t rule;
    struct network_rule_node *next;
} network_rule_node_t;

typedef struct {
    network_rule_node_t *head;
    network_rule_node_t *tail;
    size_t count;
} network_rule_list_t;

/* Function prototypes */
network_rule_list_t *network_rules_create(void);
void network_rules_destroy(network_rule_list_t *rules);
int network_rules_add(network_rule_list_t *rules, const network_rule_t *rule);
int network_rules_remove(network_rule_list_t *rules, const network_rule_t *rule);
bool network_rules_match(network_rule_list_t *rules, 
                        network_rule_type_t type,
                        network_protocol_t protocol,
                        network_transport_t transport,
                        const network_address_t *local_addr,
                        const network_address_t *remote_addr);

/* Rule parsing functions */
int network_parse_rule(const char *rule_str, network_rule_t *rule);
int network_parse_address(const char *addr_str, network_address_t *addr);
int network_parse_protocol(const char *proto_str, network_protocol_t *protocol);
int network_parse_transport(const char *trans_str, network_transport_t *transport);

/* Rule compilation functions */
int network_compile_rules(network_rule_list_t *rules, void **binary_data, size_t *binary_size);
int network_decompile_rules(const void *binary_data, size_t binary_size, network_rule_list_t *rules);

/* Validation functions */
bool network_validate_rule(const network_rule_t *rule);
bool network_validate_address(const network_address_t *addr);
bool network_validate_protocol_combination(network_protocol_t protocol, network_transport_t transport);

/* Utility functions */
const char *network_protocol_to_string(network_protocol_t protocol);
const char *network_transport_to_string(network_transport_t transport);
const char *network_rule_type_to_string(network_rule_type_t type);
void network_address_to_string(const network_address_t *addr, char *str, size_t size);

/* Rule matching functions */
bool network_address_match(const network_address_t *rule_addr, const network_address_t *request_addr);
bool network_port_match(uint16_t rule_port, uint16_t request_port);
bool network_cidr_match(const network_address_t *rule_addr, const network_address_t *request_addr);

/* Enhanced network rule syntax support */
typedef struct {
    char *interface;       /* Network interface name */
    char *zone;           /* Network zone/namespace */
    char *service;        /* Service name */
    char *user;           /* User context */
    char *time_condition; /* Time-based condition */
    char *location;       /* Geographic location */
} network_context_t;

/* Context-aware rule matching */
bool network_rules_match_with_context(network_rule_list_t *rules,
                                     network_rule_type_t type,
                                     network_protocol_t protocol,
                                     network_transport_t transport,
                                     const network_address_t *local_addr,
                                     const network_address_t *remote_addr,
                                     const network_context_t *context);

/* Rule optimization */
int network_optimize_rules(network_rule_list_t *rules);
int network_merge_rules(network_rule_list_t *rules);
int network_validate_rule_set(network_rule_list_t *rules);

/* Statistics and monitoring */
typedef struct {
    uint64_t total_rules;
    uint64_t active_rules;
    uint64_t matched_rules;
    uint64_t denied_rules;
    uint64_t audit_rules;
    double match_rate;
    double deny_rate;
} network_rule_stats_t;

network_rule_stats_t *network_get_rule_stats(network_rule_list_t *rules);
void network_print_rule_stats(const network_rule_stats_t *stats);

#ifdef __cplusplus
}
#endif

#endif /* NETWORK_MICROSEGMENTATION_H */
