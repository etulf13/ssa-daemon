#ifndef CRL_UPDATE_H
#define CRL_UPDATE_H

#include <fcntl.h>
#include <sys/stat.h>

#define UBUNTU_DEFAULT_CA "/etc/ssl/certs/ca-certificates.crt"
#define FEDORA_DEFAULT_CA "/etc/pki/tls/certs/ca-bundle.crt"

#define DEFAULT_CIPHER_LIST "ECDHE-ECDSA-AES256-GCM-SHA384:"  \
							"ECDHE-RSA-AES256-GCM-SHA384:"    \
							"ECDHE-ECDSA-CHACHA20-POLY1305:"  \
							"ECDHE-RSA-CHACHA20-POLY1305:"    \
							"ECDHE-ECDSA-AES128-GCM-SHA256:"  \
							"ECDHE-RSA-AES128-GCM-SHA256"

#define DEFAULT_CIPHERSUITES "TLS_AES_256_GCM_SHA384:"       \
                             "TLS_AES_128_GCM_SHA256:"       \
							 "TLS_CHACHA20_POLY1305_SHA256:" \
							 "TLS_AES_128_CCM_SHA256:"       \
							 "TLS_AES_128_CCM_8_SHA256"

#define CRL_READ_TIMEOUT 50

typedef struct revocation_ctx_st revocation_ctx;
typedef struct responder_ctx_st responder_ctx;

struct revocation_ctx_st {
	struct event_base* ev_base;
	struct evdns_base* dns_base;
	struct bufferevent* bev;
	hcmap_t* crl_cache;

	int fd;
	int crl_clients_left;

	responder_ctx* crl_clients;
	unsigned int crl_client_cnt;
	SSL* ssl;
};

struct responder_ctx_st {
	struct bufferevent* bev;
	char* url;


	unsigned char* buffer; /**< A temporary buffer to store read data */
	int buf_size;
	int tot_read;
	int reading_body;

	revocation_ctx* rev_ctx; /**< The parent sock_ctx of ther responder. */
};

//each revocation context instance has its own 

#endif
