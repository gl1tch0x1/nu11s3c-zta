/*
 * AppArmor Zero Trust Agent
 * 
 * This module implements the Zero Trust Agent daemon that provides dynamic
 * policy decisions based on external context and real-time security assessments.
 * 
 * Copyright (C) 2024 AppArmor Project
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include "zero_trust_agent.h"
#include "conditional_policy_engine.h"
#include "network_microsegmentation.h"
#include "security_enhancements.h"
#include "performance_monitor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <json-c/json.h>
#include <curl/curl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* Global state for the Zero Trust agent */
static struct zero_trust_agent_state {
    int running;
    int socket_fd;
    int epoll_fd;
    struct conditional_policy_engine_state *policy_engine;
    struct performance_metrics *perf_metrics;
    struct threat_intelligence *threat_intel;
    struct device_health_monitor *device_monitor;
    struct user_identity_service *identity_service;
    pthread_t main_thread;
    pthread_t threat_monitor_thread;
    pthread_t device_monitor_thread;
    pthread_mutex_t agent_mutex;
    int debug_mode;
    int log_level;
    char *config_file;
    char *socket_path;
    char *log_file;
} agent_state = {0};

/* Forward declarations */
static void *agent_main_loop(void *arg);
static void *threat_monitor_loop(void *arg);
static void *device_monitor_loop(void *arg);
static int handle_policy_request(int client_fd, struct zt_policy_request *request);
static int send_policy_response(int client_fd, struct zt_policy_response *response);
static int load_agent_configuration(const char *config_file);
static int initialize_netlink_communication(void);
static int initialize_threat_intelligence(void);
static int initialize_device_health_monitor(void);
static int initialize_user_identity_service(void);
static int evaluate_threat_level(struct zt_policy_request *request);
static int evaluate_device_health(struct zt_policy_request *request);
static int evaluate_user_identity(struct zt_policy_request *request);
static int get_external_context(struct zt_policy_request *request, 
                              struct external_context *context);
static void signal_handler(int sig);
static void cleanup_agent_resources(void);
static int validate_policy_request(struct zt_policy_request *request);
static int log_agent_event(const char *event, const char *details);

/**
 * Initialize the Zero Trust agent
 */
int zero_trust_agent_init(const char *config_file, int debug_mode) {
    if (agent_state.running) {
        return 0;
    }

    memset(&agent_state, 0, sizeof(agent_state));
    
    agent_state.debug_mode = debug_mode;
    agent_state.config_file = strdup(config_file ? config_file : "/etc/apparmor/zt-agent.conf");
    
    /* Initialize mutex */
    if (pthread_mutex_init(&agent_state.agent_mutex, NULL) != 0) {
        PERROR("Failed to initialize Zero Trust agent mutex\n");
        return -1;
    }
    
    /* Load configuration */
    if (load_agent_configuration(agent_state.config_file) != 0) {
        PERROR("Failed to load agent configuration\n");
        pthread_mutex_destroy(&agent_state.agent_mutex);
        return -1;
    }
    
    /* Initialize performance metrics */
    agent_state.perf_metrics = performance_monitor_create();
    if (!agent_state.perf_metrics) {
        PERROR("Failed to create performance metrics for Zero Trust agent\n");
        pthread_mutex_destroy(&agent_state.agent_mutex);
        return -1;
    }
    
    /* Initialize conditional policy engine */
    agent_state.policy_engine = calloc(1, sizeof(*agent_state.policy_engine));
    if (!agent_state.policy_engine) {
        PERROR("Failed to allocate memory for policy engine\n");
        performance_monitor_destroy(agent_state.perf_metrics);
        pthread_mutex_destroy(&agent_state.agent_mutex);
        return -1;
    }
    
    if (conditional_policy_engine_init(debug_mode) != 0) {
        PERROR("Failed to initialize conditional policy engine\n");
        free(agent_state.policy_engine);
        performance_monitor_destroy(agent_state.perf_metrics);
        pthread_mutex_destroy(&agent_state.agent_mutex);
        return -1;
    }
    
    /* Initialize threat intelligence */
    if (initialize_threat_intelligence() != 0) {
        PERROR("Failed to initialize threat intelligence\n");
        conditional_policy_engine_cleanup();
        free(agent_state.policy_engine);
        performance_monitor_destroy(agent_state.perf_metrics);
        pthread_mutex_destroy(&agent_state.agent_mutex);
        return -1;
    }
    
    /* Initialize device health monitor */
    if (initialize_device_health_monitor() != 0) {
        PERROR("Failed to initialize device health monitor\n");
        free(agent_state.threat_intel);
        conditional_policy_engine_cleanup();
        free(agent_state.policy_engine);
        performance_monitor_destroy(agent_state.perf_metrics);
        pthread_mutex_destroy(&agent_state.agent_mutex);
        return -1;
    }
    
    /* Initialize user identity service */
    if (initialize_user_identity_service() != 0) {
        PERROR("Failed to initialize user identity service\n");
        free(agent_state.device_monitor);
        free(agent_state.threat_intel);
        conditional_policy_engine_cleanup();
        free(agent_state.policy_engine);
        performance_monitor_destroy(agent_state.perf_metrics);
        pthread_mutex_destroy(&agent_state.agent_mutex);
        return -1;
    }
    
    /* Initialize Netlink communication */
    if (initialize_netlink_communication() != 0) {
        PERROR("Failed to initialize Netlink communication\n");
        free(agent_state.identity_service);
        free(agent_state.device_monitor);
        free(agent_state.threat_intel);
        conditional_policy_engine_cleanup();
        free(agent_state.policy_engine);
        performance_monitor_destroy(agent_state.perf_metrics);
        pthread_mutex_destroy(&agent_state.agent_mutex);
        return -1;
    }
    
    /* Set up signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGHUP, signal_handler);
    
    agent_state.running = 1;
    
    if (agent_state.debug_mode) {
        printf("Zero Trust Agent initialized successfully\n");
    }
    
    return 0;
}

/**
 * Start the Zero Trust agent
 */
int zero_trust_agent_start(void) {
    if (!agent_state.running) {
        return -1;
    }

    /* Start main agent thread */
    if (pthread_create(&agent_state.main_thread, NULL, agent_main_loop, NULL) != 0) {
        PERROR("Failed to create main agent thread\n");
        return -1;
    }
    
    /* Start threat monitor thread */
    if (pthread_create(&agent_state.threat_monitor_thread, NULL, 
                      threat_monitor_loop, NULL) != 0) {
        PERROR("Failed to create threat monitor thread\n");
        pthread_cancel(agent_state.main_thread);
        return -1;
    }
    
    /* Start device monitor thread */
    if (pthread_create(&agent_state.device_monitor_thread, NULL, 
                      device_monitor_loop, NULL) != 0) {
        PERROR("Failed to create device monitor thread\n");
        pthread_cancel(agent_state.threat_monitor_thread);
        pthread_cancel(agent_state.main_thread);
        return -1;
    }
    
    if (agent_state.debug_mode) {
        printf("Zero Trust Agent started successfully\n");
    }
    
    return 0;
}

/**
 * Stop the Zero Trust agent
 */
int zero_trust_agent_stop(void) {
    if (!agent_state.running) {
        return 0;
    }

    agent_state.running = 0;
    
    /* Wait for threads to finish */
    pthread_join(agent_state.main_thread, NULL);
    pthread_join(agent_state.threat_monitor_thread, NULL);
    pthread_join(agent_state.device_monitor_thread, NULL);
    
    cleanup_agent_resources();
    
    if (agent_state.debug_mode) {
        printf("Zero Trust Agent stopped\n");
    }
    
    return 0;
}

/**
 * Main agent loop
 */
static void *agent_main_loop(void *arg) {
    struct epoll_event events[MAX_EPOLL_EVENTS];
    int nfds;
    
    while (agent_state.running) {
        nfds = epoll_wait(agent_state.epoll_fd, events, MAX_EPOLL_EVENTS, 1000);
        
        if (nfds == -1) {
            if (errno == EINTR) {
                continue;
            }
            PERROR("epoll_wait failed\n");
            break;
        }
        
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == agent_state.socket_fd) {
                /* New connection */
                struct sockaddr_un client_addr;
                socklen_t client_len = sizeof(client_addr);
                int client_fd = accept(agent_state.socket_fd, 
                                     (struct sockaddr *)&client_addr, &client_len);
                
                if (client_fd >= 0) {
                    /* Add client to epoll */
                    struct epoll_event ev;
                    ev.events = EPOLLIN;
                    ev.data.fd = client_fd;
                    epoll_ctl(agent_state.epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);
                }
            } else {
                /* Handle client request */
                struct zt_policy_request request;
                ssize_t bytes_read = read(events[i].data.fd, &request, sizeof(request));
                
                if (bytes_read == sizeof(request)) {
                    handle_policy_request(events[i].data.fd, &request);
                } else if (bytes_read <= 0) {
                    /* Client disconnected */
                    epoll_ctl(agent_state.epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, NULL);
                    close(events[i].data.fd);
                }
            }
        }
    }
    
    return NULL;
}

/**
 * Threat monitor loop
 */
static void *threat_monitor_loop(void *arg) {
    while (agent_state.running) {
        /* Update threat intelligence */
        if (agent_state.threat_intel && agent_state.threat_intel->update_threats) {
            agent_state.threat_intel->update_threats(agent_state.threat_intel);
        }
        
        /* Sleep for 30 seconds */
        sleep(30);
    }
    
    return NULL;
}

/**
 * Device monitor loop
 */
static void *device_monitor_loop(void *arg) {
    while (agent_state.running) {
        /* Update device health */
        if (agent_state.device_monitor && agent_state.device_monitor->update_health) {
            agent_state.device_monitor->update_health(agent_state.device_monitor);
        }
        
        /* Sleep for 60 seconds */
        sleep(60);
    }
    
    return NULL;
}

/**
 * Handle a policy request
 */
static int handle_policy_request(int client_fd, struct zt_policy_request *request) {
    struct timespec start_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    
    struct zt_policy_response response;
    memset(&response, 0, sizeof(response));
    
    /* Validate request */
    if (validate_policy_request(request) != 0) {
        response.decision = ZT_DECISION_DENY;
        response.confidence = 0.0;
        response.reasoning = "Invalid request format";
        send_policy_response(client_fd, &response);
        return -1;
    }
    
    /* Evaluate threat level */
    int threat_level = evaluate_threat_level(request);
    if (threat_level > ZT_THREAT_LEVEL_HIGH) {
        response.decision = ZT_DECISION_DENY;
        response.confidence = 1.0;
        response.reasoning = "High threat level detected";
        send_policy_response(client_fd, &response);
        return 0;
    }
    
    /* Evaluate device health */
    int device_health = evaluate_device_health(request);
    if (device_health < ZT_DEVICE_HEALTH_GOOD) {
        response.decision = ZT_DECISION_DENY;
        response.confidence = 0.8;
        response.reasoning = "Device health compromised";
        send_policy_response(client_fd, &response);
        return 0;
    }
    
    /* Evaluate user identity */
    int identity_trust = evaluate_user_identity(request);
    if (identity_trust < ZT_IDENTITY_TRUST_HIGH) {
        response.decision = ZT_DECISION_DENY;
        response.confidence = 0.7;
        response.reasoning = "Low identity trust level";
        send_policy_response(client_fd, &response);
        return 0;
    }
    
    /* Get external context */
    struct external_context external_ctx;
    if (get_external_context(request, &external_ctx) != 0) {
        response.decision = ZT_DECISION_DENY;
        response.confidence = 0.5;
        response.reasoning = "Failed to get external context";
        send_policy_response(client_fd, &response);
        return 0;
    }
    
    /* Evaluate using conditional policy engine */
    if (conditional_policy_engine_evaluate(request, &response) != 0) {
        response.decision = ZT_DECISION_DENY;
        response.confidence = 0.0;
        response.reasoning = "Policy evaluation failed";
    }
    
    /* Adjust confidence based on external factors */
    response.confidence *= (1.0 - (threat_level * 0.2));
    response.confidence *= (device_health * 0.1);
    response.confidence *= (identity_trust * 0.1);
    
    /* Ensure confidence is within bounds */
    if (response.confidence > 1.0) response.confidence = 1.0;
    if (response.confidence < 0.0) response.confidence = 0.0;
    
    /* Send response */
    send_policy_response(client_fd, &response);
    
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    
    /* Update performance metrics */
    long elapsed_ns = (end_time.tv_sec - start_time.tv_sec) * 1000000000L + 
                      (end_time.tv_nsec - start_time.tv_nsec);
    performance_monitor_record_function_time(agent_state.perf_metrics, 
                                           "policy_request_handling", 
                                           elapsed_ns);
    
    /* Log the event */
    char details[512];
    snprintf(details, sizeof(details), 
             "Request: %s, Decision: %d, Confidence: %.2f, Threat: %d, Health: %d, Identity: %d",
             request->resource, response.decision, response.confidence,
             threat_level, device_health, identity_trust);
    log_agent_event("policy_decision", details);
    
    return 0;
}

/**
 * Send policy response
 */
static int send_policy_response(int client_fd, struct zt_policy_response *response) {
    if (!response) {
        return -1;
    }

    ssize_t bytes_sent = write(client_fd, response, sizeof(*response));
    if (bytes_sent != sizeof(*response)) {
        PERROR("Failed to send policy response\n");
        return -1;
    }
    
    return 0;
}

/**
 * Load agent configuration
 */
static int load_agent_configuration(const char *config_file) {
    if (!config_file) {
        return -1;
    }

    /* Default configuration */
    agent_state.socket_path = strdup("/var/run/apparmor/zt-agent.sock");
    agent_state.log_file = strdup("/var/log/apparmor/zt-agent.log");
    agent_state.log_level = ZT_LOG_LEVEL_INFO;
    
    /* Try to load from file */
    FILE *f = fopen(config_file, "r");
    if (!f) {
        /* Use defaults if file doesn't exist */
        return 0;
    }
    
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }
        
        /* Parse configuration */
        char key[64], value[192];
        if (sscanf(line, "%63s = %191s", key, value) == 2) {
            if (strcmp(key, "socket_path") == 0) {
                free(agent_state.socket_path);
                agent_state.socket_path = strdup(value);
            } else if (strcmp(key, "log_file") == 0) {
                free(agent_state.log_file);
                agent_state.log_file = strdup(value);
            } else if (strcmp(key, "log_level") == 0) {
                agent_state.log_level = atoi(value);
            }
        }
    }
    
    fclose(f);
    return 0;
}

/**
 * Initialize Netlink communication
 */
static int initialize_netlink_communication(void) {
    /* Create Unix domain socket */
    agent_state.socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (agent_state.socket_fd < 0) {
        PERROR("Failed to create socket\n");
        return -1;
    }
    
    /* Bind to socket path */
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, agent_state.socket_path, sizeof(addr.sun_path) - 1);
    
    /* Remove existing socket file */
    unlink(agent_state.socket_path);
    
    if (bind(agent_state.socket_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        PERROR("Failed to bind socket\n");
        close(agent_state.socket_fd);
        return -1;
    }
    
    /* Set socket permissions */
    chmod(agent_state.socket_path, 0660);
    
    /* Listen for connections */
    if (listen(agent_state.socket_fd, 10) < 0) {
        PERROR("Failed to listen on socket\n");
        close(agent_state.socket_fd);
        return -1;
    }
    
    /* Create epoll instance */
    agent_state.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (agent_state.epoll_fd < 0) {
        PERROR("Failed to create epoll instance\n");
        close(agent_state.socket_fd);
        return -1;
    }
    
    /* Add socket to epoll */
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = agent_state.socket_fd;
    if (epoll_ctl(agent_state.epoll_fd, EPOLL_CTL_ADD, agent_state.socket_fd, &ev) < 0) {
        PERROR("Failed to add socket to epoll\n");
        close(agent_state.epoll_fd);
        close(agent_state.socket_fd);
        return -1;
    }
    
    return 0;
}

/**
 * Initialize threat intelligence
 */
static int initialize_threat_intelligence(void) {
    agent_state.threat_intel = calloc(1, sizeof(*agent_state.threat_intel));
    if (!agent_state.threat_intel) {
        return -1;
    }
    
    /* Initialize threat intelligence sources */
    agent_state.threat_intel->update_threats = NULL; /* Placeholder */
    agent_state.threat_intel->check_ip_reputation = NULL; /* Placeholder */
    agent_state.threat_intel->check_domain_reputation = NULL; /* Placeholder */
    
    return 0;
}

/**
 * Initialize device health monitor
 */
static int initialize_device_health_monitor(void) {
    agent_state.device_monitor = calloc(1, sizeof(*agent_state.device_monitor));
    if (!agent_state.device_monitor) {
        return -1;
    }
    
    /* Initialize device health monitoring */
    agent_state.device_monitor->update_health = NULL; /* Placeholder */
    agent_state.device_monitor->check_security_status = NULL; /* Placeholder */
    agent_state.device_monitor->check_compliance = NULL; /* Placeholder */
    
    return 0;
}

/**
 * Initialize user identity service
 */
static int initialize_user_identity_service(void) {
    agent_state.identity_service = calloc(1, sizeof(*agent_state.identity_service));
    if (!agent_state.identity_service) {
        return -1;
    }
    
    /* Initialize user identity service */
    agent_state.identity_service->authenticate_user = NULL; /* Placeholder */
    agent_state.identity_service->get_user_attributes = NULL; /* Placeholder */
    agent_state.identity_service->check_permissions = NULL; /* Placeholder */
    
    return 0;
}

/**
 * Evaluate threat level
 */
static int evaluate_threat_level(struct zt_policy_request *request) {
    if (!agent_state.threat_intel) {
        return ZT_THREAT_LEVEL_UNKNOWN;
    }
    
    /* Check IP reputation */
    if (agent_state.threat_intel->check_ip_reputation) {
        int ip_reputation = agent_state.threat_intel->check_ip_reputation(
            agent_state.threat_intel, request->source_ip);
        if (ip_reputation < 0) {
            return ZT_THREAT_LEVEL_HIGH;
        }
    }
    
    /* Check domain reputation */
    if (agent_state.threat_intel->check_domain_reputation) {
        int domain_reputation = agent_state.threat_intel->check_domain_reputation(
            agent_state.threat_intel, request->domain);
        if (domain_reputation < 0) {
            return ZT_THREAT_LEVEL_MEDIUM;
        }
    }
    
    return ZT_THREAT_LEVEL_LOW;
}

/**
 * Evaluate device health
 */
static int evaluate_device_health(struct zt_policy_request *request) {
    if (!agent_state.device_monitor) {
        return ZT_DEVICE_HEALTH_UNKNOWN;
    }
    
    /* Check security status */
    if (agent_state.device_monitor->check_security_status) {
        int security_status = agent_state.device_monitor->check_security_status(
            agent_state.device_monitor, request->device_type);
        if (security_status < 0) {
            return ZT_DEVICE_HEALTH_POOR;
        }
    }
    
    /* Check compliance */
    if (agent_state.device_monitor->check_compliance) {
        int compliance = agent_state.device_monitor->check_compliance(
            agent_state.device_monitor, request->device_type);
        if (compliance < 0) {
            return ZT_DEVICE_HEALTH_FAIR;
        }
    }
    
    return ZT_DEVICE_HEALTH_GOOD;
}

/**
 * Evaluate user identity
 */
static int evaluate_user_identity(struct zt_policy_request *request) {
    if (!agent_state.identity_service) {
        return ZT_IDENTITY_TRUST_UNKNOWN;
    }
    
    /* Authenticate user */
    if (agent_state.identity_service->authenticate_user) {
        int auth_result = agent_state.identity_service->authenticate_user(
            agent_state.identity_service, request->uid, request->session_id);
        if (auth_result < 0) {
            return ZT_IDENTITY_TRUST_LOW;
        }
    }
    
    /* Get user attributes */
    if (agent_state.identity_service->get_user_attributes) {
        struct user_attributes attrs;
        int attr_result = agent_state.identity_service->get_user_attributes(
            agent_state.identity_service, request->uid, &attrs);
        if (attr_result < 0) {
            return ZT_IDENTITY_TRUST_MEDIUM;
        }
    }
    
    return ZT_IDENTITY_TRUST_HIGH;
}

/**
 * Get external context
 */
static int get_external_context(struct zt_policy_request *request, 
                              struct external_context *context) {
    if (!context) {
        return -1;
    }
    
    memset(context, 0, sizeof(*context));
    
    /* Get current time */
    context->timestamp = time(NULL);
    
    /* Get system load */
    FILE *f = fopen("/proc/loadavg", "r");
    if (f) {
        fscanf(f, "%f %f %f", &context->load_1min, &context->load_5min, &context->load_15min);
        fclose(f);
    }
    
    /* Get memory usage */
    f = fopen("/proc/meminfo", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "MemTotal:", 9) == 0) {
                sscanf(line, "MemTotal: %lu kB", &context->total_memory);
            } else if (strncmp(line, "MemAvailable:", 13) == 0) {
                sscanf(line, "MemAvailable: %lu kB", &context->available_memory);
            }
        }
        fclose(f);
    }
    
    /* Get network statistics */
    f = fopen("/proc/net/dev", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, request->interface)) {
                sscanf(line, "%*s %lu %*lu %*lu %*lu %*lu %*lu %*lu %*lu %lu", 
                       &context->bytes_received, &context->bytes_sent);
                break;
            }
        }
        fclose(f);
    }
    
    return 0;
}

/**
 * Signal handler
 */
static void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        agent_state.running = 0;
    } else if (sig == SIGHUP) {
        /* Reload configuration */
        if (agent_state.config_file) {
            load_agent_configuration(agent_state.config_file);
        }
    }
}

/**
 * Cleanup agent resources
 */
static void cleanup_agent_resources(void) {
    pthread_mutex_lock(&agent_state.agent_mutex);
    
    /* Close socket */
    if (agent_state.socket_fd >= 0) {
        close(agent_state.socket_fd);
        unlink(agent_state.socket_path);
    }
    
    /* Close epoll */
    if (agent_state.epoll_fd >= 0) {
        close(agent_state.epoll_fd);
    }
    
    /* Cleanup policy engine */
    if (agent_state.policy_engine) {
        conditional_policy_engine_cleanup();
        free(agent_state.policy_engine);
    }
    
    /* Cleanup other components */
    if (agent_state.threat_intel) {
        free(agent_state.threat_intel);
    }
    
    if (agent_state.device_monitor) {
        free(agent_state.device_monitor);
    }
    
    if (agent_state.identity_service) {
        free(agent_state.identity_service);
    }
    
    if (agent_state.perf_metrics) {
        performance_monitor_destroy(agent_state.perf_metrics);
    }
    
    /* Free strings */
    if (agent_state.config_file) {
        free(agent_state.config_file);
    }
    
    if (agent_state.socket_path) {
        free(agent_state.socket_path);
    }
    
    if (agent_state.log_file) {
        free(agent_state.log_file);
    }
    
    pthread_mutex_unlock(&agent_state.agent_mutex);
    pthread_mutex_destroy(&agent_state.agent_mutex);
}

/**
 * Validate policy request
 */
static int validate_policy_request(struct zt_policy_request *request) {
    if (!request) {
        return -1;
    }
    
    /* Check required fields */
    if (!request->profile_name || strlen(request->profile_name) == 0) {
        return -1;
    }
    
    if (!request->resource || strlen(request->resource) == 0) {
        return -1;
    }
    
    if (request->uid < 0 || request->gid < 0) {
        return -1;
    }
    
    if (request->pid < 0 || request->ppid < 0) {
        return -1;
    }
    
    return 0;
}

/**
 * Log agent event
 */
static int log_agent_event(const char *event, const char *details) {
    if (!event || !details) {
        return -1;
    }
    
    if (agent_state.debug_mode) {
        printf("[%s] %s: %s\n", 
               agent_state.log_level >= ZT_LOG_LEVEL_DEBUG ? "DEBUG" : "INFO",
               event, details);
    }
    
    return 0;
}
