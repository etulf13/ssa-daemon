/**
 * A simple example of a client that implements OpenSSL to connect to a server via internet address
 * and prints Success if it was able to connect securely, or error if the connection was not secure.
 * 
 * This version implements all procedures and functions needed to generally secure and verify the 
 * connection. This code does not account for Certificate Revocation Checking, nor does it correct
 * a few advanced security vulnerabilities (such as the BREACH Attack).
 * 
 * Written by Nathaniel Bennett
 * Updated 24 February 2020
 * 
 * To Compile: gcc -o <prgm-name> ssl_minimal.c $(pkg-config --libs --cflags openssl)
 * To Run: ./<prgm-name> <domain-name> 
 * 
 *  |-------------------|-------------------|
 *  |     FEATURES      |   IMPLEMENTED?    |
 *  |-------------------|-------------------|
 *  | Secure Encryption | Yes               |
 *  | Cert Verification | Yes               |
 *  | Error Testing     | None              |
 *  | Concurrency       | None--Blocking    |
 *  | Memory Leak Free? | Yes--Valgrind Good|
 *  | Revocation Checks	| None              |
 *  |   -OCSP Stapling  | "                 |
 *  |   -CRL Checking   | "                 |
 *  |   -OCSP Request   | "                 |
 * 
 * 
 *  |-----------------------|-------------------|
 *  | SECURITY VULNERBILITY | SECURED AGAINST?  |
 *  |-----------------------|-------------------|
 *  | No Certificate        | Yes               |
 *  | Expired Certificate   | Yes               |
 *  | Malformed Certificate | Yes               |
 *  | Untrusted Root Cert   | Yes               |
 *  | Broken Cert Chain     | Yes               |
 *  | Revoked Certificate   | NO                |
 *  |   -Bad OCSP Response  | N/A               |
 *  |   -No OCSP/CRL URL    | N/A               |
 *  | Secure Renegotiation  | Yes (Default)     |
 *  | Protocol Downgrading  | Yes               |
 *  | Weak MD4/RC5          | Yes               |
 *  | SHA1 Certificate      | NO?--FIX          |
 *  | SHA1 Intermediate Cert| NO--FIX           |    
 *  | CRIME Attack          | Yes               |
 *  | BREACH Attack         | NO                |
 * 
 */

#include <unistd.h>
#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/tcp.h> /* for TCP_NODELAY flag in setsockopt() */
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"


/* Port 443 is standard for HTTPS */
#define HTTPS_PORT "443"

/*
 * Fedora and Ubuntu store CA certificates at different locations.
 * Fedora stores them all in a single file, which needs to be passed
 * in as the second argument of SSL_CTX_load_verify_locations().
 * Ubuntu stores them in a file, which should be passed in as the third
 * argument of the same function. 
 */
#define CA_FOLDER_UBUNTU "/etc/ssl/certs"
#define CA_FILE_FEDORA "/etc/pki/tls/certs/ca-bundle.crt"
/* 
 * Most secure ciphers only. More generally secure ones could be added
 * to this list, but I decided to keep it short. Colons separate ciphers.
 * Note: AES-CBC ciphers are vulnerable to the Lucky Thirteen attack.
 */
#define SECURE_CIPHER_LIST "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
#define SECURE_CIPERSUITES "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256"

/* Helper functions */
int get_fd(char *hostname, char *port);
void throw_input_err();

/* Part 1: Setting up the CTX object */
SSL_CTX *create_ready_CTX() {
	SSL_CTX *ctx;

	/* Create a Context to generate SSL objects from; set to client mode */
	ctx = SSL_CTX_new(TLS_client_method());
    
    /* Enable verification of cert; load Cert Authority certs. */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_load_verify_locations(ctx, NULL, CA_FOLDER_UBUNTU);
    
    /* Set allowed TLS versions, ciphersuites, disabled features */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
	SSL_CTX_set_cipher_list(ctx, SECURE_CIPHER_LIST);
	SSL_CTX_set_ciphersuites(ctx, SECURE_CIPERSUITES);
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION | SSL_OP_NO_TICKET);

	return ctx;
}

/* Part 2: Setting up the SSL object */
SSL *create_ready_SSL(SSL_CTX *ctx, char *hostname) {
	int socket_fd;
	SSL *ssl;
	
	ssl = SSL_new(ctx);
	
	/* Ensure proper hostname recognition */
	SSL_set_tlsext_host_name(ssl, hostname);
	SSL_set1_host(ssl, hostname);
	
	/* Create a TCP connection and assign it to the SSL object */
	socket_fd = get_fd(hostname, HTTPS_PORT);
	SSL_set_fd(ssl, socket_fd);

	return ssl;
}

/* Part 3: Connection and authentication */
void do_handshake(SSL *ssl) {
	X509 *server_cert;

    /* Connect and see if it throws any errors */
	if (SSL_connect(ssl) != 1) {
		int cert_err = SSL_get_verify_result(ssl);

		if (cert_err != X509_V_OK) {
			const char *err_string = X509_verify_cert_error_string(cert_err);
			fprintf(stderr, "Error validating cert. Code %i:%s\n", cert_err, err_string);
		}
		else {
			fprintf(stderr, "Fatal error occured during handshake:\n");
			ERR_print_errors_fp(stderr);
		}
		exit(1);
	}
	
	/* Finally, check to make sure that a cert was actually received.
     * OpenSSL DOES NOT fail a connection if a cert was not sent, even
     * though this is perhaps the biggest security oversight in the history
     * of TLS security oversights. It's been that way for 10 years. :/
     */
	server_cert = SSL_get_peer_certificate(ssl);
	if (server_cert == NULL) {
		/* No cert was sent */
		fprintf(stderr, "Error: No certificate presented by server in handshake.\n");
		exit(1);
	}
	X509_free(server_cert);

	/* Passed all verification; handshake succeeded. */
	fprintf(stderr, "Handshake succeeded! Connection secured.\n");
}


int main (int argc, char *argv[]) {
	char *hostname;
	SSL_CTX *ctx;
	SSL *ssl;

	if (argc < 2)
		throw_input_err();
	hostname = argv[1]; 

	ctx = create_ready_CTX();
	ssl = create_ready_SSL(ctx, hostname);
	do_handshake(ssl);

    /* This is the part where we have a secure connection and could just send 
     * http requests using SSL_read() and SSL_write()
     */

	/* Part 4: cleanup */
	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ctx);

	return 0;
}

/*
 **************************************************************************
 * 		HELPER FUNCTIONS NOT SPECIFIC TO OPENSSL
 **************************************************************************
 */

void throw_input_err() {
	printf("\nERROR: insufficient arguments in command.\n");
	printf("Proper usage: ./ssl_simple_client <domain_name>\n");
	exit(1);
}

/* get_fd uses getaddrinfo to create and connect to the proper socket. it returns a file descriptor to a socket. */
int get_fd(char *hostname, char *port) {
	int clientfd;
	struct addrinfo hints, *listp = NULL, *p;
	/* Get a list of potential server addresses*/
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICSERV;
	hints.ai_flags |= AI_ADDRCONFIG;

	getaddrinfo(hostname, port, &hints, &listp);

	if (listp == NULL) {
		printf("\nNo addrinfo pointers available to traverse through...\n");
		exit(1);
	}
	
	/* Walk the list until one is successfully connected to */
	for (p = listp; p != NULL; p = p->ai_next) {
		if ((clientfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0) {
			printf("\nSocket failed to create...\n");
			continue; /* Try next socket; this one failed */
		}
		
		if (connect(clientfd, p->ai_addr, p->ai_addrlen) >= 0) {
			break; 
		}
		else {
			printf("\nConnect call failed...\n");
		} 
		
		close(clientfd);
	} 
	
	if (listp != NULL) {
		/* Clean up */
		freeaddrinfo(listp); 
	}

	if (p == NULL) { /* All connections failed */
		printf("\nAll connections failed...\n");
		exit(1);
	}
	return clientfd;
}
