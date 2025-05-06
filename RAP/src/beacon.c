
#include "../include/beacon.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <net/if.h>
#include <sys/ioctl.h>

#define MAC_LEN 6 

struct ieee80211_beacon_frame {
    uint8_t radiotap_header[8];
    uint8_t frame_control[2];
    uint8_t duration[2];
    uint8_t dest[6];
    uint8_t src[6];
    uint8_t bssid[6];
    uint8_t seq_ctrl[2];
    uint8_t fixed_params[12];
};

static pthread_t beacon_thread;
static bool beacon_running = false;
static char *ssid_name = NULL;

static char* get_interface_mac(const char *iface_name) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return NULL;
    }

    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ-1);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(sock);
        return NULL;
    }
    close(sock);

    char *mac = malloc(18);
    if (!mac) return NULL;

    sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
        (unsigned char)ifr.ifr_hwaddr.sa_data[0],
        (unsigned char)ifr.ifr_hwaddr.sa_data[1],
        (unsigned char)ifr.ifr_hwaddr.sa_data[2],
        (unsigned char)ifr.ifr_hwaddr.sa_data[3],
        (unsigned char)ifr.ifr_hwaddr.sa_data[4],
        (unsigned char)ifr.ifr_hwaddr.sa_data[5]);

    return mac;
}

void send_beacon_loop(pcap_t *handle, const char *ssid, const char *iface_mac_str) {
    uint8_t packet[256];
    int ssid_len = strlen(ssid);
    if(ssid_len > 32) ssid_len = 32;

    uint8_t iface_mac[MAC_LEN];
    sscanf(iface_mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &iface_mac[0], &iface_mac[1], &iface_mac[2],
           &iface_mac[3], &iface_mac[4], &iface_mac[5]);

    memset(packet, 0, sizeof(packet));

    packet[0] = 0x00;
    packet[1] = 0x00;
    packet[2] = 0x08;
    packet[3] = 0x00;
    packet[8] = 0x80;
    packet[9] = 0x00;
    packet[10] = 0x00;
    packet[11] = 0x00;

    memset(packet + 12, 0xff, MAC_LEN);
    memcpy(packet + 18, iface_mac, MAC_LEN);
    memcpy(packet + 24, iface_mac, MAC_LEN);

    packet[30] = 0x00;
    packet[31] = 0x00;

    memset(packet +32, 0x00,8);
    packet[40] = 0x64; packet[41] = 0x00;
    packet[42] = 0x01; packet[43] = 0x04;

    packet[44] = 0x00;
    packet[45] = ssid_len;
    memcpy(packet +46, ssid, ssid_len);

    int packet_len = 46 + ssid_len;

    printf("[*] Shooting Out SSID: \"%s\" ...\n", ssid);
    while (beacon_running) {
        if (pcap_sendpacket(handle, packet, packet_len) != 0) {
            fprintf(stderr, "Error sending beacon: %s\n", pcap_geterr(handle));
        }
        usleep(100000);
    }
}

static void *beacon_thread_func(void *arg) {
    const char *ssid = (const char *)arg;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    handle = pcap_open_live("wlan0mon", BUFSIZ, 1, 0, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "[-] Failed to open interface: %s\n", errbuf);
        return NULL;
    }
    
    char *mac_addr = get_interface_mac("wlan0mon");
    if (mac_addr == NULL) {
        fprintf(stderr, "[-] Failed to get interface MAC address\n");
        pcap_close(handle);
        return NULL;
    }
    
    send_beacon_loop(handle, ssid, mac_addr);
    
    free(mac_addr);
    pcap_close(handle);
    
    return NULL;
}

bool start_beacon_broadcast(const char *ssid) {
    if (beacon_running) {
        return true;
    }
    
    ssid_name = strdup(ssid);
    if (ssid_name == NULL) {
        perror("[-] Failed to allocate memory for SSID");
        return false;
    }
    
    beacon_running = true;
    
    if (pthread_create(&beacon_thread, NULL, beacon_thread_func, ssid_name) != 0) {
        perror("[-] Failed to create beacon thread");
        free(ssid_name);
        ssid_name = NULL;
        beacon_running = false;
        return false;
    }
    
    return true;
}

void stop_beacon_broadcast(void) {
    if (beacon_running) {
        beacon_running = false;
        pthread_join(beacon_thread, NULL);
        
        if (ssid_name != NULL) {
            free(ssid_name);
            ssid_name = NULL;
        }
    }
}