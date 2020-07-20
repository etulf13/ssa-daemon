#ifndef REVOCATION_CRL_H
#define REVOCATION_CRL_H

#include <openssl/ocsp.h>
#include <openssl/ssl.h>
#include <event2/bufferevent.h>
#include "log.h"
#include "hashmap_crl.h"

#define LEEWAY_90_SECS 90
#define MAX_HEADER_SIZE 8192
#define MAX_OCSP_AGE 604800L


char** retrieve_crl_urls(X509* cert, int* num_urls);
int crl_parse_url(const char *url, char **host, char **port, char **path);
int send_crl_request(struct bufferevent* bev, char* url, char* http_req);
int do_crl_response_checks(X509_CRL* crl, X509* subject, X509* issuer, int* response);

int check_crl_cache(hcmap_t* cache_map, X509* cert);
int crl_cache_update(hcmap_t* cache_map, X509_CRL* crl);

int read_crl_cache(hcmap_t* cache_map, FILE* cache_ptr);

#endif
