
#ifndef DNS_SPOOF_H
#define DNS_SPOOF_H

#include <stdbool.h>
#include <stdint.h>

bool start_dns_spoofing(void);

bool add_dns_redirect(const char *domain, uint32_t redirect_ip);

bool remove_dns_redirect(const char *domain);

void stop_dns_spoofing(void);

#endif