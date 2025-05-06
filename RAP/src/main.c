
#include <stdio.h>
#include "../include/beacon.h"
#include "../include/dhcp.h"
#include "../include/dns_spoof.h"
#include "../include/http_intercept.h"

int main() {
    printf("[*] RAP Starting...\n");

    if (!start_beacon_broadcast("free_wifi")) {
        fprintf(stderr, "[-] Failed to breadcast beacon frames.\n");
        return 1;
    }

    if (!start_dhcp_server()) {
        fprintf(stderr, "[-] Failed to start DNS spoofing.\n");
        return 1;
    }

    if(!start_http_intercept()) {
        fprintf(stderr, "[-] Failed to start HTTP interceptor.\n");
        return 1;
    }

    printf("[+] RAP running successfully.\n");

    while(1) {
        sleep(1);
    }

    return 0;
}