/*
 * Network Microsegmentation Implementation for AppArmor Parser
 * 
 * Extends profile syntax to enforce fine-grained network rules
 * beyond the basic network capability.
 */

#include "network_microsegmentation.h"
#include "enhanced_error.h"
#include "security_enhancements.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <pthread.h>

/* Global network rules state */
static struct {
    network_rule_list_t *global_rules;
    pthread_mutex_t mutex;
    int initialized;
} network_state = {0};

/* Initialize network microsegmentation */
static void network_init(void) {
    if (network_state.initialized) return;
    
    memset(&network_state, 0, sizeof(network_state));
    
    if (pthread_mutex_init(&network_state.mutex, NULL) != 0) {
        ENHANCED_ERROR(ERROR_LEVEL_ERROR, ERROR_CATEGORY_SYSTEM, 1, "Failed to initialize network mutex");
        return;
    }
    
    network_state.global_rules = network_rules_create();
    network_state.initialized = 1;
    
    ENHANCED_INFO(ERROR_CATEGORY_SYSTEM, 1, "Network microsegmentation initialized");
}

/* Create network rules list */
network_rule_list_t *network_rules_create(void) {
    network_rule_list_t *rules = security_malloc(sizeof(network_rule_list_t));
    if (!rules) {
        ENHANCED_ERROR_MEMORY(1, "Failed to allocate memory for network rules list");
        return NULL;
    }
    
    memset(rules, 0, sizeof(network_rule_list_t));
    return rules;
}

/* Destroy network rules list */
void network_rules_destroy(network_rule_list_t *rules) {
    if (!rules) return;
    
    network_rule_node_t *node = rules->head;
    while (node) {
        network_rule_node_t *next = node->next;
        if (node->rule.condition) {
            security_free(node->rule.condition);
        }
        security_free(node);
        node = next;
    }
    
    security_free(rules);
}

/* Add network rule */
int network_rules_add(network_rule_list_t *rules, const network_rule_t *rule) {
    if (!rules || !rule) return -1;
    
    network_init();
    
    if (!network_validate_rule(rule)) {
        ENHANCED_ERROR(ERROR_LEVEL_ERROR, ERROR_CATEGORY_VALIDATION, 1, "Invalid network rule");
        return -1;
    }
    
    network_rule_node_t *node = security_malloc(sizeof(network_rule_node_t));
    if (!node) {
        ENHANCED_ERROR_MEMORY(1, "Failed to allocate memory for network rule node");
        return -1;
    }
    
    node->rule = *rule;
    if (rule->condition) {
        node->rule.condition = security_strdup(rule->condition);
        if (!node->rule.condition) {
            security_free(node);
            return -1;
        }
    }
    
    node->next = NULL;
    
    if (rules->tail) {
        rules->tail->next = node;
    } else {
        rules->head = node;
    }
    rules->tail = node;
    rules->count++;
    
    ENHANCED_INFO(ERROR_CATEGORY_SYSTEM, 1, "Added network rule: %s", network_rule_type_to_string(rule->type));
    return 0;
}

/* Remove network rule */
int network_rules_remove(network_rule_list_t *rules, const network_rule_t *rule) {
    if (!rules || !rule) return -1;
    
    network_rule_node_t *node = rules->head;
    network_rule_node_t *prev = NULL;
    
    while (node) {
        if (memcmp(&node->rule, rule, sizeof(network_rule_t)) == 0) {
            if (prev) {
                prev->next = node->next;
            } else {
                rules->head = node->next;
            }
            
            if (node == rules->tail) {
                rules->tail = prev;
            }
            
            if (node->rule.condition) {
                security_free(node->rule.condition);
            }
            security_free(node);
            rules->count--;
            
            ENHANCED_INFO(ERROR_CATEGORY_SYSTEM, 1, "Removed network rule");
            return 0;
        }
        
        prev = node;
        node = node->next;
    }
    
    return -1;
}

/* Match network rules */
bool network_rules_match(network_rule_list_t *rules, 
                        network_rule_type_t type,
                        network_protocol_t protocol,
                        network_transport_t transport,
                        const network_address_t *local_addr,
                        const network_address_t *remote_addr) {
    if (!rules) return false;
    
    network_rule_node_t *node = rules->head;
    while (node) {
        network_rule_t *rule = &node->rule;
        
        /* Check rule type */
        if (rule->type != type) {
            node = node->next;
            continue;
        }
        
        /* Check protocol */
        if (rule->protocol != protocol) {
            node = node->next;
            continue;
        }
        
        /* Check transport */
        if (rule->transport != transport) {
            node = node->next;
            continue;
        }
        
        /* Check local address */
        if (local_addr && !network_address_match(&rule->local_addr, local_addr)) {
            node = node->next;
            continue;
        }
        
        /* Check remote address */
        if (remote_addr && !network_address_match(&rule->remote_addr, remote_addr)) {
            node = node->next;
            continue;
        }
        
        /* Rule matches */
        return true;
    }
    
    return false;
}

/* Parse network rule from string */
int network_parse_rule(const char *rule_str, network_rule_t *rule) {
    if (!rule_str || !rule) return -1;
    
    network_init();
    
    memset(rule, 0, sizeof(network_rule_t));
    
    /* Simple parsing - in real implementation, this would be more sophisticated */
    char *copy = security_strdup(rule_str);
    if (!copy) return -1;
    
    char *token = strtok(copy, " ");
    if (!token) {
        security_free(copy);
        return -1;
    }
    
    /* Parse rule type */
    if (strcmp(token, "create") == 0) {
        rule->type = NET_RULE_CREATE;
    } else if (strcmp(token, "bind") == 0) {
        rule->type = NET_RULE_BIND;
    } else if (strcmp(token, "listen") == 0) {
        rule->type = NET_RULE_LISTEN;
    } else if (strcmp(token, "accept") == 0) {
        rule->type = NET_RULE_ACCEPT;
    } else if (strcmp(token, "connect") == 0) {
        rule->type = NET_RULE_CONNECT;
    } else if (strcmp(token, "send") == 0) {
        rule->type = NET_RULE_SEND;
    } else if (strcmp(token, "receive") == 0) {
        rule->type = NET_RULE_RECEIVE;
    } else {
        security_free(copy);
        return -1;
    }
    
    /* Parse protocol */
    token = strtok(NULL, " ");
    if (!token) {
        security_free(copy);
        return -1;
    }
    
    if (strcmp(token, "inet") == 0) {
        rule->protocol = NET_PROTO_INET;
    } else if (strcmp(token, "inet6") == 0) {
        rule->protocol = NET_PROTO_INET6;
    } else if (strcmp(token, "unix") == 0) {
        rule->protocol = NET_PROTO_UNIX;
    } else if (strcmp(token, "netlink") == 0) {
        rule->protocol = NET_PROTO_NETLINK;
    } else if (strcmp(token, "packet") == 0) {
        rule->protocol = NET_PROTO_PACKET;
    } else {
        security_free(copy);
        return -1;
    }
    
    /* Parse transport */
    token = strtok(NULL, " ");
    if (!token) {
        security_free(copy);
        return -1;
    }
    
    if (strcmp(token, "tcp") == 0) {
        rule->transport = NET_TRANSPORT_TCP;
    } else if (strcmp(token, "udp") == 0) {
        rule->transport = NET_TRANSPORT_UDP;
    } else if (strcmp(token, "icmp") == 0) {
        rule->transport = NET_TRANSPORT_ICMP;
    } else if (strcmp(token, "raw") == 0) {
        rule->transport = NET_TRANSPORT_RAW;
    } else if (strcmp(token, "stream") == 0) {
        rule->transport = NET_TRANSPORT_STREAM;
    } else if (strcmp(token, "seqpacket") == 0) {
        rule->transport = NET_TRANSPORT_SEQPACKET;
    } else if (strcmp(token, "dgram") == 0) {
        rule->transport = NET_TRANSPORT_DGRAM;
    } else {
        security_free(copy);
        return -1;
    }
    
    /* Parse port (if specified) */
    token = strtok(NULL, " ");
    if (token && strcmp(token, "port") == 0) {
        token = strtok(NULL, " ");
        if (token) {
            rule->local_addr.port = atoi(token);
        }
    }
    
    security_free(copy);
    return 0;
}

/* Parse network address */
int network_parse_address(const char *addr_str, network_address_t *addr) {
    if (!addr_str || !addr) return -1;
    
    memset(addr, 0, sizeof(network_address_t));
    
    /* Check for IPv4 address */
    if (inet_pton(AF_INET, addr_str, addr->addr) == 1) {
        addr->family = AF_INET;
        return 0;
    }
    
    /* Check for IPv6 address */
    if (inet_pton(AF_INET6, addr_str, addr->addr) == 1) {
        addr->family = AF_INET6;
        return 0;
    }
    
    return -1;
}

/* Parse protocol */
int network_parse_protocol(const char *proto_str, network_protocol_t *protocol) {
    if (!proto_str || !protocol) return -1;
    
    if (strcmp(proto_str, "inet") == 0) {
        *protocol = NET_PROTO_INET;
    } else if (strcmp(proto_str, "inet6") == 0) {
        *protocol = NET_PROTO_INET6;
    } else if (strcmp(proto_str, "unix") == 0) {
        *protocol = NET_PROTO_UNIX;
    } else if (strcmp(proto_str, "netlink") == 0) {
        *protocol = NET_PROTO_NETLINK;
    } else if (strcmp(proto_str, "packet") == 0) {
        *protocol = NET_PROTO_PACKET;
    } else {
        return -1;
    }
    
    return 0;
}

/* Parse transport */
int network_parse_transport(const char *trans_str, network_transport_t *transport) {
    if (!trans_str || !transport) return -1;
    
    if (strcmp(trans_str, "tcp") == 0) {
        *transport = NET_TRANSPORT_TCP;
    } else if (strcmp(trans_str, "udp") == 0) {
        *transport = NET_TRANSPORT_UDP;
    } else if (strcmp(trans_str, "icmp") == 0) {
        *transport = NET_TRANSPORT_ICMP;
    } else if (strcmp(trans_str, "raw") == 0) {
        *transport = NET_TRANSPORT_RAW;
    } else if (strcmp(trans_str, "stream") == 0) {
        *transport = NET_TRANSPORT_STREAM;
    } else if (strcmp(trans_str, "seqpacket") == 0) {
        *transport = NET_TRANSPORT_SEQPACKET;
    } else if (strcmp(trans_str, "dgram") == 0) {
        *transport = NET_TRANSPORT_DGRAM;
    } else {
        return -1;
    }
    
    return 0;
}

/* Compile network rules to binary */
int network_compile_rules(network_rule_list_t *rules, void **binary_data, size_t *binary_size) {
    if (!rules || !binary_data || !binary_size) return -1;
    
    network_init();
    
    /* Calculate total size needed */
    size_t total_size = sizeof(uint32_t); /* Rule count */
    network_rule_node_t *node = rules->head;
    while (node) {
        total_size += sizeof(network_rule_t);
        if (node->rule.condition) {
            total_size += strlen(node->rule.condition) + 1;
        }
        node = node->next;
    }
    
    *binary_data = security_malloc(total_size);
    if (!*binary_data) {
        ENHANCED_ERROR_MEMORY(1, "Failed to allocate memory for binary rules");
        return -1;
    }
    
    uint8_t *ptr = (uint8_t*)*binary_data;
    
    /* Write rule count */
    *(uint32_t*)ptr = rules->count;
    ptr += sizeof(uint32_t);
    
    /* Write rules */
    node = rules->head;
    while (node) {
        memcpy(ptr, &node->rule, sizeof(network_rule_t));
        ptr += sizeof(network_rule_t);
        
        if (node->rule.condition) {
            size_t len = strlen(node->rule.condition) + 1;
            memcpy(ptr, node->rule.condition, len);
            ptr += len;
        }
        
        node = node->next;
    }
    
    *binary_size = total_size;
    return 0;
}

/* Decompile network rules from binary */
int network_decompile_rules(const void *binary_data, size_t binary_size, network_rule_list_t *rules) {
    if (!binary_data || !rules || binary_size < sizeof(uint32_t)) return -1;
    
    network_init();
    
    const uint8_t *ptr = (const uint8_t*)binary_data;
    
    /* Read rule count */
    uint32_t rule_count = *(uint32_t*)ptr;
    ptr += sizeof(uint32_t);
    
    /* Read rules */
    for (uint32_t i = 0; i < rule_count; i++) {
        if (ptr + sizeof(network_rule_t) > (const uint8_t*)binary_data + binary_size) {
            return -1;
        }
        
        network_rule_t rule;
        memcpy(&rule, ptr, sizeof(network_rule_t));
        ptr += sizeof(network_rule_t);
        
        if (rule.condition) {
            size_t len = strlen((const char*)ptr) + 1;
            if (ptr + len > (const uint8_t*)binary_data + binary_size) {
                return -1;
            }
            rule.condition = security_strdup((const char*)ptr);
            ptr += len;
        }
        
        if (network_rules_add(rules, &rule) != 0) {
            return -1;
        }
    }
    
    return 0;
}

/* Validate network rule */
bool network_validate_rule(const network_rule_t *rule) {
    if (!rule) return false;
    
    /* Validate rule type */
    if (rule->type >= 7) return false; /* Assuming 7 rule types */
    
    /* Validate protocol */
    if (rule->protocol >= 5) return false; /* Assuming 5 protocols */
    
    /* Validate transport */
    if (rule->transport >= 7) return false; /* Assuming 7 transports */
    
    /* Validate protocol/transport combination */
    if (!network_validate_protocol_combination(rule->protocol, rule->transport)) {
        return false;
    }
    
    /* Validate addresses */
    if (!network_validate_address(&rule->local_addr)) return false;
    if (!network_validate_address(&rule->remote_addr)) return false;
    
    return true;
}

/* Validate network address */
bool network_validate_address(const network_address_t *addr) {
    if (!addr) return false;
    
    /* Validate family */
    if (addr->family != AF_INET && addr->family != AF_INET6) {
        return false;
    }
    
    /* Validate port */
    if (addr->port > 65535) return false;
    
    /* Validate prefix length */
    if (addr->prefix_len > 128) return false;
    
    return true;
}

/* Validate protocol/transport combination */
bool network_validate_protocol_combination(network_protocol_t protocol, network_transport_t transport) {
    switch (protocol) {
        case NET_PROTO_INET:
        case NET_PROTO_INET6:
            return (transport == NET_TRANSPORT_TCP || transport == NET_TRANSPORT_UDP || 
                    transport == NET_TRANSPORT_ICMP || transport == NET_TRANSPORT_RAW);
        case NET_PROTO_UNIX:
            return (transport == NET_TRANSPORT_STREAM || transport == NET_TRANSPORT_DGRAM || 
                    transport == NET_TRANSPORT_SEQPACKET);
        case NET_PROTO_NETLINK:
        case NET_PROTO_PACKET:
            return (transport == NET_TRANSPORT_RAW);
        default:
            return false;
    }
}

/* Utility functions */
const char *network_protocol_to_string(network_protocol_t protocol) {
    switch (protocol) {
        case NET_PROTO_INET: return "inet";
        case NET_PROTO_INET6: return "inet6";
        case NET_PROTO_UNIX: return "unix";
        case NET_PROTO_NETLINK: return "netlink";
        case NET_PROTO_PACKET: return "packet";
        default: return "unknown";
    }
}

const char *network_transport_to_string(network_transport_t transport) {
    switch (transport) {
        case NET_TRANSPORT_TCP: return "tcp";
        case NET_TRANSPORT_UDP: return "udp";
        case NET_TRANSPORT_ICMP: return "icmp";
        case NET_TRANSPORT_RAW: return "raw";
        case NET_TRANSPORT_STREAM: return "stream";
        case NET_TRANSPORT_SEQPACKET: return "seqpacket";
        case NET_TRANSPORT_DGRAM: return "dgram";
        default: return "unknown";
    }
}

const char *network_rule_type_to_string(network_rule_type_t type) {
    switch (type) {
        case NET_RULE_CREATE: return "create";
        case NET_RULE_BIND: return "bind";
        case NET_RULE_LISTEN: return "listen";
        case NET_RULE_ACCEPT: return "accept";
        case NET_RULE_CONNECT: return "connect";
        case NET_RULE_SEND: return "send";
        case NET_RULE_RECEIVE: return "receive";
        default: return "unknown";
    }
}

void network_address_to_string(const network_address_t *addr, char *str, size_t size) {
    if (!addr || !str || size == 0) return;
    
    if (addr->family == AF_INET) {
        inet_ntop(AF_INET, addr->addr, str, size);
    } else if (addr->family == AF_INET6) {
        inet_ntop(AF_INET6, addr->addr, str, size);
    } else {
        strncpy(str, "unknown", size - 1);
        str[size - 1] = '\0';
    }
    
    if (addr->port > 0) {
        char port_str[16];
        snprintf(port_str, sizeof(port_str), ":%d", addr->port);
        strncat(str, port_str, size - strlen(str) - 1);
    }
}

/* Rule matching functions */
bool network_address_match(const network_address_t *rule_addr, const network_address_t *request_addr) {
    if (!rule_addr || !request_addr) return false;
    
    /* Check family */
    if (rule_addr->family != request_addr->family) return false;
    
    /* Check port */
    if (rule_addr->port != 0 && rule_addr->port != request_addr->port) return false;
    
    /* Check address */
    if (rule_addr->prefix_len > 0) {
        return network_cidr_match(rule_addr, request_addr);
    } else {
        return memcmp(rule_addr->addr, request_addr->addr, 
                     rule_addr->family == AF_INET ? 4 : 16) == 0;
    }
}

bool network_port_match(uint16_t rule_port, uint16_t request_port) {
    return (rule_port == 0 || rule_port == request_port);
}

bool network_cidr_match(const network_address_t *rule_addr, const network_address_t *request_addr) {
    if (!rule_addr || !request_addr) return false;
    
    if (rule_addr->family != request_addr->family) return false;
    
    int addr_len = (rule_addr->family == AF_INET) ? 4 : 16;
    int prefix_bytes = rule_addr->prefix_len / 8;
    int prefix_bits = rule_addr->prefix_len % 8;
    
    /* Compare full bytes */
    if (memcmp(rule_addr->addr, request_addr->addr, prefix_bytes) != 0) {
        return false;
    }
    
    /* Compare partial byte */
    if (prefix_bits > 0 && prefix_bytes < addr_len) {
        unsigned char mask = 0xFF << (8 - prefix_bits);
        if ((rule_addr->addr[prefix_bytes] & mask) != (request_addr->addr[prefix_bytes] & mask)) {
            return false;
        }
    }
    
    return true;
}

/* Context-aware rule matching */
bool network_rules_match_with_context(network_rule_list_t *rules,
                                     network_rule_type_t type,
                                     network_protocol_t protocol,
                                     network_transport_t transport,
                                     const network_address_t *local_addr,
                                     const network_address_t *remote_addr,
                                     const network_context_t *context) {
    if (!rules) return false;
    
    /* For now, just use basic matching */
    /* In a full implementation, this would evaluate context conditions */
    return network_rules_match(rules, type, protocol, transport, local_addr, remote_addr);
}

/* Rule optimization */
int network_optimize_rules(network_rule_list_t *rules) {
    if (!rules) return -1;
    
    ENHANCED_INFO(ERROR_CATEGORY_SYSTEM, 1, "Network rule optimization not implemented yet");
    return 0;
}

int network_merge_rules(network_rule_list_t *rules) {
    if (!rules) return -1;
    
    ENHANCED_INFO(ERROR_CATEGORY_SYSTEM, 1, "Network rule merging not implemented yet");
    return 0;
}

int network_validate_rule_set(network_rule_list_t *rules) {
    if (!rules) return -1;
    
    network_rule_node_t *node = rules->head;
    while (node) {
        if (!network_validate_rule(&node->rule)) {
            ENHANCED_ERROR(ERROR_LEVEL_ERROR, ERROR_CATEGORY_VALIDATION, 1, "Invalid rule in rule set");
            return -1;
        }
        node = node->next;
    }
    
    return 0;
}

/* Statistics and monitoring */
network_rule_stats_t *network_get_rule_stats(network_rule_list_t *rules) {
    if (!rules) return NULL;
    
    static network_rule_stats_t stats = {0};
    
    stats.total_rules = rules->count;
    stats.active_rules = rules->count;
    
    /* Calculate rates */
    if (stats.total_rules > 0) {
        stats.match_rate = (double)stats.matched_rules / stats.total_rules;
        stats.deny_rate = (double)stats.denied_rules / stats.total_rules;
    }
    
    return &stats;
}

void network_print_rule_stats(const network_rule_stats_t *stats) {
    if (!stats) return;
    
    printf("Network Rule Statistics:\n");
    printf("  Total Rules: %lu\n", stats->total_rules);
    printf("  Active Rules: %lu\n", stats->active_rules);
    printf("  Matched Rules: %lu\n", stats->matched_rules);
    printf("  Denied Rules: %lu\n", stats->denied_rules);
    printf("  Audit Rules: %lu\n", stats->audit_rules);
    printf("  Match Rate: %.2f%%\n", stats->match_rate * 100);
    printf("  Deny Rate: %.2f%%\n", stats->deny_rate * 100);
}
