
#ifndef DHCP_H
#define DHCP_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    uint8_t server_ip;
    uint8_t subnet_mask;
    uint8_t gateway;
    uint8_t dns_server;
    uint8_t start_ip;
    uint8_t end_ip;
} dhcp_config_t;

bool start_dhcp_server(void);

bool start_dhcp_server_with_config(dhcp_config_t *config);

void stop_dhcp_server(void);

#endif