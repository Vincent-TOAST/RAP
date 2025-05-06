
#ifndef HTTP_INTERCEPT_H
#define HTTP_INTERCEPT_H

#include <stdbool.h>

bool start_http_intercept(void);

bool set_phishing_page(const char *path);

bool set_ssl_certificate(const char *cert_path, const char *key_path);

void stop_http_intercept(void);

#endif