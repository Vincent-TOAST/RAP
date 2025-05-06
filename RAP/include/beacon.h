
#ifndef BEACON_H
#define BEACON_H

#include <pcap.h>
#include <stdbool.h>

void send_beacon_loop(pcap_t *handle, const char *ssid, const char *iface_mac);

bool start_beacon_broadcast(const char *ssid);

void stop_beacon_broadcast(void);

#endif 