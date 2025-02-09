#ifndef SSA_IN_TLS
#define SSA_IN_TLS

#ifndef _BITS_SOCKADDR_H
        typedef unsigned short int sa_family_t;
#endif

/* Protocol */
#define IPPROTO_TLS     (715 % 255)

/* Options */
#define TLS_REMOTE_HOSTNAME               85
#define TLS_HOSTNAME                      86
#define TLS_TRUSTED_PEER_CERTIFICATES     87
#define TLS_CERTIFICATE_CHAIN             88
#define TLS_PRIVATE_KEY                   89
#define TLS_ALPN                          90
#define TLS_SESSION_TTL                   91
#define TLS_DISABLE_CIPHER                92
#define TLS_PEER_IDENTITY                 93
#define TLS_REQUEST_PEER_AUTH             94

/* Internal use only */
#define TLS_PEER_CERTIFICATE_CHAIN        95
#define TLS_ID                            96

/* added recently--not in kernel */
#define TLS_TRUSTED_CIPHERS               97
#define TLS_ERROR                        100

/* TLS versions */
#define TLS_VERSION_MIN			 102
#define TLS_VERSION_MAX			 103
#define TLS_VERSION_CONN		 104
const int TLS_1_2 = 0x0303;
const int TLS_1_3 = 0x0304;
char* tls_version_str(int version) {

	if (version == TLS_1_2) 
		return "TLS 1.2";
	if (version == TLS_1_3)
		return "TLS 1.3";
	return "Unknown version";
}

/* TCP options */
#define TCP_UPGRADE_TLS         33

/* Address types */
#define AF_HOSTNAME     43

struct host_addr {
        unsigned char name[255]; /* max hostname size in lunux */
};

struct sockaddr_host {
        sa_family_t sin_family;
        unsigned short sin_port;
        struct host_addr sin_addr;
};


#endif

