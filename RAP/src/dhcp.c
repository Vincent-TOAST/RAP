
#include "../include/dhcp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <time.h>

#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68
#define DHCP_MAGIC_COOKIE 0x63825363

#define DHCP_DISCOVER 1
#define DHCP_OFFER 2
#define DHCP_REQUEST 3
#define DHCP_ACK 5
#define DHCP_NAK 6

#define DHCP_OPT_SUBNET_MASK 1
#define DHCP_OPT_ROUTER 3
#define DHCP_OPT_DNS 6
#define DHCP_OPT_REQUESTED_IP 50
#define DHCP_OPT_LEASE_TIME 51
#define DHCP_OPT_MSG_TYPE 53
#define DHCP_OPT_SERVER_ID 54
#define DHCP_OPT_END 255

typedef struct {
    uint8_t op;            
    uint8_t htype;         
    uint8_t hlen;          
    uint8_t hops;          
    uint32_t xid;         
    uint16_t secs;         
    uint16_t flags;     
    uint32_t ciaddr;      
    uint32_t yiaddr;     
    uint32_t siaddr;      
    uint32_t giaddr;      
    uint8_t chaddr[16];    
    uint8_t sname[64];   
    uint8_t file[128];     
    uint32_t magic_cookie; 
    uint8_t options[308];  
} dhcp_packet_t;

typedef struct {
    uint32_t ip;
    uint8_t mac[6];
    time_t lease_expiry;
    bool allocated;
} dhcp_lease_t;

static pthread_t dhcp_thread;
static int dhcp_socket = -1;
static bool dhcp_running = false;
static uint32_t server_ip = 0;
static uint32_t subnet_mask = 0;
static uint32_t gateway_ip = 0;
static uint32_t dns_server_ip = 0;
static uint32_t start_ip = 0;
static uint32_t end_ip = 0;
static dhcp_lease_t *leases = NULL;
static int lease_count = 0;
static pthread_mutex_t lease_mutex = PTHREAD_MUTEX_INITIALIZER;

static int set_option(uint8_t *options, int offset, uint8_t code, uint8_t len, void *data) {
    options[offset++] = code;
    options[offset++] = len;
    memcpy(&options[offset], data, len);
    return offset + len;
}

static uint8_t *get_option(uint8_t *options, int options_len, uint8_t code) {
    int i = 0;
    while (i < options_len) {
        if (options[i] == DHCP_OPT_END) {
            break;
        }
        
        if (options[i] == code) {
            return &options[i + 2];
        }
        
        i += options[i + 1] + 2;
    }
    
    return NULL;
}

static uint32_t find_available_ip() {
    uint32_t start = ntohl(start_ip);
    uint32_t end = ntohl(end_ip);
    
    for (uint32_t ip = start; ip <= end; ip++) {
        bool found = false;
        
        pthread_mutex_lock(&lease_mutex);
        for (int i = 0; i < lease_count; i++) {
            if (leases[i].allocated && ntohl(leases[i].ip) == ip) {
                found = true;
                break;
            }
        }
        pthread_mutex_unlock(&lease_mutex);
        
        if (!found) {
            return htonl(ip);
        }
    }
    
    return 0;
}

static dhcp_lease_t *find_lease_by_mac(uint8_t *mac) {
    pthread_mutex_lock(&lease_mutex);
    
    for (int i = 0; i < lease_count; i++) {
        if (leases[i].allocated && memcmp(leases[i].mac, mac, 6) == 0) {
            pthread_mutex_unlock(&lease_mutex);
            return &leases[i];
        }
    }
    
    pthread_mutex_unlock(&lease_mutex);
    return NULL;
}

static dhcp_lease_t *find_lease_by_ip(uint32_t ip) {
    pthread_mutex_lock(&lease_mutex);
    
    for (int i = 0; i < lease_count; i++) {
        if (leases[i].allocated && leases[i].ip == ip) {
            pthread_mutex_unlock(&lease_mutex);
            return &leases[i];
        }
    }
    
    pthread_mutex_unlock(&lease_mutex);
    return NULL;
}

static dhcp_lease_t *create_lease(uint8_t *mac, uint32_t ip) {
    pthread_mutex_lock(&lease_mutex);
    
    for (int i = 0; i < lease_count; i++) {
        if (!leases[i].allocated) {
            memcpy(leases[i].mac, mac, 6);
            leases[i].ip = ip;
            leases[i].lease_expiry = time(NULL) + 3600; 
            leases[i].allocated = true;
            
            pthread_mutex_unlock(&lease_mutex);
            return &leases[i];
        }
    }
    
    dhcp_lease_t *new_leases = realloc(leases, (lease_count + 10) * sizeof(dhcp_lease_t));
    if (new_leases == NULL) {
        pthread_mutex_unlock(&lease_mutex);
        return NULL;
    }
    
    leases = new_leases;
    memset(&leases[lease_count], 0, 10 * sizeof(dhcp_lease_t));
    
    memcpy(leases[lease_count].mac, mac, 6);
    leases[lease_count].ip = ip;
    leases[lease_count].lease_expiry = time(NULL) + 3600; 
    leases[lease_count].allocated = true;
    
    dhcp_lease_t *result = &leases[lease_count];
    lease_count += 10;
    
    pthread_mutex_unlock(&lease_mutex);
    return result;
}

static void process_dhcp_discover(dhcp_packet_t *packet, struct sockaddr_in *client_addr) {
    dhcp_packet_t response;
    memset(&response, 0, sizeof(response));
    
    response.op = 2;
    response.htype = packet->htype;
    response.hlen = packet->hlen;
    response.hops = 0;
    response.xid = packet->xid;
    response.secs = 0;
    response.flags = packet->flags;
    response.ciaddr = 0;
    
    uint32_t offer_ip = 0;
    dhcp_lease_t *existing_lease = find_lease_by_mac(packet->chaddr);
    
    if (existing_lease != NULL) {
        offer_ip = existing_lease->ip;
    } else {
        offer_ip = find_available_ip();
        if (offer_ip == 0) {
            printf("[-] No available IP addresses to offer\n");
            return;
        }
    }
    
    response.yiaddr = offer_ip;
    response.siaddr = server_ip;
    response.giaddr = packet->giaddr;
    memcpy(response.chaddr, packet->chaddr, 16);
    
    response.magic_cookie = htonl(DHCP_MAGIC_COOKIE);
    
    int offset = 0;
    uint8_t msg_type = DHCP_OFFER;
    uint32_t lease_time = htonl(3600); 
    
    offset = set_option(response.options, offset, DHCP_OPT_MSG_TYPE, 1, &msg_type);
    offset = set_option(response.options, offset, DHCP_OPT_SUBNET_MASK, 4, &subnet_mask);
    offset = set_option(response.options, offset, DHCP_OPT_ROUTER, 4, &gateway_ip);
    offset = set_option(response.options, offset, DHCP_OPT_DNS, 4, &dns_server_ip);
    offset = set_option(response.options, offset, DHCP_OPT_LEASE_TIME, 4, &lease_time);
    offset = set_option(response.options, offset, DHCP_OPT_SERVER_ID, 4, &server_ip);
    response.options[offset++] = DHCP_OPT_END;
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(DHCP_CLIENT_PORT);
    addr.sin_addr.s_addr = INADDR_BROADCAST;
    
    if (sendto(dhcp_socket, &response, sizeof(response), 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[-] Failed to send DHCP OFFER");
        return;
    }
    
    printf("[+] Sent DHCP OFFER to %02x:%02x:%02x:%02x:%02x:%02x - IP: %s\n",
           packet->chaddr[0], packet->chaddr[1], packet->chaddr[2],
           packet->chaddr[3], packet->chaddr[4], packet->chaddr[5],
           inet_ntoa(*(struct in_addr *)&offer_ip));
}

static void process_dhcp_request(dhcp_packet_t *packet, struct sockaddr_in *client_addr) {
    dhcp_packet_t response;
    memset(&response, 0, sizeof(response));
    
    response.op = 2; 
    response.htype = packet->htype;
    response.hlen = packet->hlen;
    response.hops = 0;
    response.xid = packet->xid;
    response.secs = 0;
    response.flags = packet->flags;
    response.ciaddr = packet->ciaddr;
    
    uint32_t requested_ip = 0;
    uint8_t *requested_ip_opt = get_option(packet->options, sizeof(packet->options), DHCP_OPT_REQUESTED_IP);
    
    if (requested_ip_opt != NULL) {
        memcpy(&requested_ip, requested_ip_opt, 4);
    } else if (packet->ciaddr != 0) {
        requested_ip = packet->ciaddr;
    }
    
    dhcp_lease_t *lease = find_lease_by_mac(packet->chaddr);
    
    if (lease == NULL && requested_ip != 0) {
        lease = find_lease_by_ip(requested_ip);
        
        if (lease != NULL && memcmp(lease->mac, packet->chaddr, 6) != 0) {
            lease = NULL;
        }
    }
    
    uint8_t msg_type;
    
    if (lease == NULL && requested_ip != 0) {
        lease = create_lease(packet->chaddr, requested_ip);
        if (lease == NULL) {
            msg_type = DHCP_NAK;
            response.yiaddr = 0;
        } else {
            msg_type = DHCP_ACK;
            response.yiaddr = lease->ip;
        }
    } else if (lease != NULL) {
        lease->lease_expiry = time(NULL) + 3600;
        msg_type = DHCP_ACK;
        response.yiaddr = lease->ip;
    } else {
        msg_type = DHCP_NAK;
        response.yiaddr = 0;
    }
    
    response.siaddr = server_ip;
    response.giaddr = packet->giaddr;
    memcpy(response.chaddr, packet->chaddr, 16);
    
    response.magic_cookie = htonl(DHCP_MAGIC_COOKIE);
    
    int offset = 0;
    uint32_t lease_time = htonl(3600); 
    
    offset = set_option(response.options, offset, DHCP_OPT_MSG_TYPE, 1, &msg_type);
    
    if (msg_type == DHCP_ACK) {
        offset = set_option(response.options, offset, DHCP_OPT_SUBNET_MASK, 4, &subnet_mask);
        offset = set_option(response.options, offset, DHCP_OPT_ROUTER, 4, &gateway_ip);
        offset = set_option(response.options, offset, DHCP_OPT_DNS, 4, &dns_server_ip);
        offset = set_option(response.options, offset, DHCP_OPT_LEASE_TIME, 4, &lease_time);
    }
    
    offset = set_option(response.options, offset, DHCP_OPT_SERVER_ID, 4, &server_ip);
    response.options[offset++] = DHCP_OPT_END;
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(DHCP_CLIENT_PORT);
    
    if (packet->giaddr != 0) {
        addr.sin_addr.s_addr = packet->giaddr;
    } else if (packet->ciaddr != 0) {
        addr.sin_addr.s_addr = packet->ciaddr;
    } else {
        addr.sin_addr.s_addr = INADDR_BROADCAST;
    }
    
    if (sendto(dhcp_socket, &response, sizeof(response), 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[-] Failed to send DHCP ACK/NAK");
        return;
    }
    
    printf("[+] Sent DHCP %s to %02x:%02x:%02x:%02x:%02x:%02x - IP: %s\n",
           (msg_type == DHCP_ACK) ? "ACK" : "NAK",
           packet->chaddr[0], packet->chaddr[1], packet->chaddr[2],
           packet->chaddr[3], packet->chaddr[4], packet->chaddr[5],
           (msg_type == DHCP_ACK) ? inet_ntoa(*(struct in_addr *)&response.yiaddr) : "N/A");
}

static void process_dhcp_packet(dhcp_packet_t *packet, int len, struct sockaddr_in *client_addr) {
    if (len < sizeof(dhcp_packet_t) - sizeof(packet->options)) {
        return;
    }
    
    if (ntohl(packet->magic_cookie) != DHCP_MAGIC_COOKIE) {
        return;
    }
    
    uint8_t *msg_type_opt = get_option(packet->options, sizeof(packet->options), DHCP_OPT_MSG_TYPE);
    if (msg_type_opt == NULL) {
        return;
    }
    
    uint8_t msg_type = *msg_type_opt;
    
    switch (msg_type) {
        case DHCP_DISCOVER:
            printf("[*] Received DHCP DISCOVER from %02x:%02x:%02x:%02x:%02x:%02x\n",
                   packet->chaddr[0], packet->chaddr[1], packet->chaddr[2],
                   packet->chaddr[3], packet->chaddr[4], packet->chaddr[5]);
            process_dhcp_discover(packet, client_addr);
            break;
            
        case DHCP_REQUEST:
            printf("[*] Received DHCP REQUEST from %02x:%02x:%02x:%02x:%02x:%02x\n",
                   packet->chaddr[0], packet->chaddr[1], packet->chaddr[2],
                   packet->chaddr[3], packet->chaddr[4], packet->chaddr[5]);
            process_dhcp_request(packet, client_addr);
            break;
            
        default:
            break;
    }
}

static void *dhcp_server_thread(void *arg) {
    printf("[+] DHCP server started\n");
    
    while (dhcp_running) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(dhcp_socket, &read_fds);
        
        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        int ret = select(dhcp_socket + 1, &read_fds, NULL, NULL, &timeout);
        
        if (ret < 0) {
            if (dhcp_running) {
                perror("[-] select() failed");
            }
            continue;
        }
        
        if (ret == 0) {
            continue;
        }
        
        if (FD_ISSET(dhcp_socket, &read_fds)) {
            dhcp_packet_t packet;
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            
            ssize_t recv_len = recvfrom(dhcp_socket, &packet, sizeof(packet), 0,
                                        (struct sockaddr *)&client_addr, &addr_len);
            
            if (recv_len < 0) {
                perror("[-] recvfrom() failed");
                continue;
            }
            
            process_dhcp_packet(&packet, recv_len, &client_addr);
        }
    }
    
    printf("[+] DHCP server stopped\n");
    return NULL;
}

bool start_dhcp_server(void) {
    dhcp_config_t config;
    config.server_ip = inet_addr("192.168.1.1");
    config.subnet_mask = inet_addr("255.255.255.0");
    config.gateway = inet_addr("192.168.1.1");
    config.dns_server = inet_addr("192.168.1.1");
    config.start_ip = inet_addr("192.168.1.100");
    config.end_ip = inet_addr("192.168.1.200");
    
    return start_dhcp_server_with_config(&config);
}

bool start_dhcp_server_with_config(dhcp_config_t *config) {
    if (dhcp_running) {
        return true;
    }
    
    leases = calloc(10, sizeof(dhcp_lease_t));
    if (leases == NULL) {
        perror("[-] Failed to allocate memory for DHCP leases");
        return false;
    }
    lease_count = 10;
    
    server_ip = config->server_ip;
    subnet_mask = config->subnet_mask;
    gateway_ip = config->gateway;
    dns_server_ip = config->dns_server;
    start_ip = config->start_ip;
    end_ip = config->end_ip;
    
    dhcp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (dhcp_socket < 0) {
        perror("[-] Failed to create DHCP socket");
        free(leases);
        leases = NULL;
        return false;
    }
    
    int opt = 1;
    if (setsockopt(dhcp_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("[-] Failed to set SO_REUSEADDR");
        close(dhcp_socket);
        free(leases);
        leases = NULL;
        return false;
    }
    
    if (setsockopt(dhcp_socket, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt)) < 0) {
        perror("[-] Failed to set SO_BROADCAST");
        close(dhcp_socket);
        free(leases);
        leases = NULL;
        return false;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(DHCP_SERVER_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(dhcp_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[-] Failed to bind DHCP socket");
        close(dhcp_socket);
        free(leases);
        leases = NULL;
        return false;
    }
    
    dhcp_running = true;
    
    if (pthread_create(&dhcp_thread, NULL, dhcp_server_thread, NULL) != 0) {
        perror("[-] Failed to create DHCP server thread");
        close(dhcp_socket);
        free(leases);
        leases = NULL;
        dhcp_running = false;
        return false;
    }
    
    return true;
}

void stop_dhcp_server(void) {
    if (dhcp_running) {
        dhcp_running = false;
        pthread_join(dhcp_thread, NULL);
        close(dhcp_socket);
        dhcp_socket = -1;
        free(leases);
        leases = NULL;
        lease_count = 0;
    }
}