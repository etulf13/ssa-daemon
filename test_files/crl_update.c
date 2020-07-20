#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/dns.h>
#include <event2/util.h>
#include <openssl/ssl.h>
#include <openssl/ocsp.h>

#include "../hashmap_crl.h"
#include "../revocation_crl.h"
#include "crl_update.h"
int loop(struct bufferevent *bev) {
	while (1) {
		if (bufferevent_socket_get_dns_error(bev))
			break;
	}
}
int launch_client(revocation_ctx* rev, char* url);
int revocation_cb(SSL* ssl, void* arg);
revocation_ctx* rev_ctx_new(struct event_base* event_base, struct evdns_base* evdns_base);
SSL_CTX* set_ssl_ctx();
int launch_crl_checks(revocation_ctx* rev, char** urls, int num_urls);
int launch_crl_client(revocation_ctx* rev, char* url);
void client_read_cb(struct bufferevent *bev, void* arg);
void client_write_cb(struct bufferevent *bev, void* arg);
void client_event_cb(struct bufferevent *bev, short events, void* arg);
void crl_read_cb(struct bufferevent *bev, void* arg);
void crl_event_cb(struct bufferevent *bev, short events, void* arg);
int parse_url(char* url, char** host_out, int* port_out, char** path_out);
int is_bad_http_response(char* response);
int get_http_body_len(char* response);
int start_reading_body(responder_ctx* client);
int done_reading_body(responder_ctx* resp_ctx);

int main()
{
//1. Load CRL cache from text document into cache map
	hcmap_t* crl_cache;
	FILE* cache = fopen("../crl_cache.txt", "r");
	if (cache == NULL) printf("Not yet\n");
	else {
		fprintf(stderr, "Reading cache\n");
		crl_cache = crl_hashmap_create(10000);
		read_crl_cache(crl_cache, cache);
	}
//2. Set up SSL context
	SSL_CTX* ssl_ctx = set_ssl_ctx();
	SSL_CTX_set_tlsext_status_cb(ssl_ctx, revocation_cb);
//3. Open metadoc and load reference URL's
	FILE* metadoc = fopen("../crl_metadoc.txt", "r");
	char* url;

	struct event_base* ev_base = event_base_new();
	event_base_priority_init(ev_base, 3);
	//event_base_dispatch(ev_base);
	struct evdns_base* dns_base = evdns_base_new(ev_base, 1);
	if (dns_base == NULL)
		goto err;


//4. Attempt to establish connections to metadoc URL's

	while(fgets(url, 50, metadoc) != NULL) {
		if (strstr(url, "URL:")) {
			fprintf(stderr, "Found URL\n");
			revocation_ctx *rev = rev_ctx_new(ev_base, dns_base);
			SSL_CTX_set_tlsext_status_arg(ssl_ctx, rev);
			rev->ssl = SSL_new(ssl_ctx);
			rev->crl_cache = crl_cache;
			launch_client(rev, url+5);
		}
	}
	fclose(metadoc);
	fprintf(stderr, "about to dispatch\n");
	event_base_dispatch(ev_base);
	return 0;

err:
	fprintf(stderr, "ERROR?\n");
}

int launch_client(revocation_ctx* rev, char* url)
{
	url[strlen(url) - 1] = '\0';
//set remote hostname 
	SSL_set_tlsext_host_name(rev->ssl, url);
	SSL_set1_host(rev->ssl, url);
	fprintf(stderr, "Set hostname: %s\n", url);
	fprintf(stderr, "%d\n", strlen(url));

//open bufferevent openssl socket
	rev->bev = bufferevent_openssl_socket_new(rev->ev_base, -1, rev->ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE);
	if (rev->bev == NULL) {
		fprintf(stderr, "Creating OpenSSL bufferevent failed: %i %s\n", 
				EVUTIL_SOCKET_ERROR(), strerror(EVUTIL_SOCKET_ERROR()));
		fprintf(stderr, "What just printed?\n");
		return 0;
	}
//enable bufferevent
	int ret = bufferevent_enable(rev->bev, EV_READ | EV_WRITE);
	if (ret < 0)
		fprintf(stderr, "Couldn't enable bev\n");

//set bufferevent callbacks
	bufferevent_setcb(rev->bev, client_read_cb, client_write_cb, client_event_cb, rev);//client_event_cb, rev);


//connect bufferevent
	if (bufferevent_socket_connect_hostname(rev->bev, NULL, AF_INET, url, 443)) {
		fprintf(stderr, "failure\n");
	}
	else {
		fprintf(stderr, "Connected?\n");
		int cert_err = SSL_get_verify_result(rev->ssl);
		int num_urls = 0;
		//char* url;
		int response;
		X509_CRL* crl;

		if (cert_err != X509_V_OK) {
			fprintf(stderr, "cert not ok\n");
			goto err;
		}
		X509 *server_cert = SSL_get_peer_certificate(rev->ssl);
		if (server_cert == NULL) {
			fprintf(stderr, "cert is null\n");
			goto err;
		}
		STACK_OF(X509) *cert_chain = SSL_get_peer_cert_chain(rev->ssl);
		X509 *issuer = sk_X509_value(cert_chain, 1);
		char** urls = retrieve_crl_urls(server_cert, &num_urls);
		if (urls == NULL) {
			fprintf(stderr, "returned no URLs\n");
			goto err;
		}

		if (num_urls > 0)
			launch_crl_checks(rev, urls, num_urls);

		//for (int i = 0; i < num_urls; i++) {
		//	url = urls[i];
		//	if (query_crl_responder(url, &crl))
		//		goto err;
		//	if (check_crl_status(crl, rev->ssl, cert, issuer, &response))
		//		goto err;
		//	if (response == X509_V_OK)
		//		crl_cache_update(rev->crl_cache, crl);
	}

	return 0;

err:
	fprintf(stderr, "Failure in connect bufferevent\n");
		bufferevent_write(rev->bev, url, strlen(url));
	return -1;
}

int revocation_cb(SSL* ssl, void* arg)
{
	revocation_ctx* rev = (revocation_ctx*) arg;
	X509* cert;
	char** crl_urls = NULL;
	int crl_url_cnt;
	cert = SSL_get_peer_certificate(rev->ssl);

	if (cert == NULL)
		goto err;

	crl_urls = retrieve_crl_urls(cert, &crl_url_cnt);
	if (crl_url_cnt > 0)
		launch_crl_checks(rev, crl_urls, crl_url_cnt);

	if (crl_urls != NULL)
		free(crl_urls);

	X509_free(cert);

err:
	fprintf(stderr, "ERROR?\n");
}



revocation_ctx* rev_ctx_new(struct event_base* event_base, struct evdns_base* evdns_base)
{
	revocation_ctx* rev = NULL;

	rev = calloc(1, sizeof(revocation_ctx));
	if (rev == NULL)
		goto err;

	rev->ev_base = event_base;
	rev->dns_base = evdns_base;

	return rev;
err:
	fprintf(stderr, "Error in rev_ctx_new\n");
}

SSL_CTX* set_ssl_ctx()
{
	SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_method());

	SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);

	SSL_CTX_set_options(ssl_ctx, SSL_CTX_get_options(ssl_ctx) | 
			SSL_OP_NO_COMPRESSION | SSL_OP_NO_TICKET);

	if (SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION) != 1)
		goto err;

	if (SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION) != 1)
		goto err;

	if (SSL_CTX_set_cipher_list(ssl_ctx, DEFAULT_CIPHER_LIST) != 1)
		goto err;

	if (SSL_CTX_set_ciphersuites(ssl_ctx, DEFAULT_CIPHERSUITES) != 1)
		goto err;

	struct stat file_stats;
	char* CA_path;

	if (access(UBUNTU_DEFAULT_CA, F_OK) != -1)
		CA_path = UBUNTU_DEFAULT_CA;
	else if (access(FEDORA_DEFAULT_CA, F_OK) != -1)
		CA_path = FEDORA_DEFAULT_CA;
	else
		goto err;

	if (stat(CA_path, &file_stats) != 0) {
		fprintf(stderr, "Failed to access CA file %s: %s\n", CA_path, strerror(errno));
		goto err;
	}

	if (S_ISREG(file_stats.st_mode))
		if (!SSL_CTX_load_verify_locations(ssl_ctx, CA_path, NULL)) {
			fprintf(stderr, "couldn't load CA file location\n");
			goto err;
		}
	else if (S_ISDIR(file_stats.st_mode))
		if (!SSL_CTX_load_verify_locations(ssl_ctx, NULL, CA_path)) {
			fprintf(stderr, "couldn't load CA directory location\n");
			goto err;
		}
	else {
		fprintf(stderr, "couldn't load CA location\n");
		goto err;	
	}

	return ssl_ctx;

err:
	fprintf(stderr, "Error in set_SSL_CTX\n");
	return NULL;
}

int launch_crl_checks(revocation_ctx* rev, char** urls, int num_urls)
{
	rev->crl_clients = calloc(num_urls, sizeof(responder_ctx));
	if (rev->crl_clients == NULL)
		return 0;

	for (int i = 0; i < num_urls; i++)
		launch_crl_client(rev, urls[i]);

	if (rev->crl_client_cnt == 0)
		return -1;

	return 0;
}

int launch_crl_client(revocation_ctx* rev, char* url)
{

	responder_ctx* crl_client = &rev->crl_clients[rev->crl_client_cnt];
	struct bufferevent* bev = NULL;
	char* hostname = NULL;
	int port;
	int ret;

    struct timeval read_timeout = {
		.tv_sec = CRL_READ_TIMEOUT,
		.tv_usec = 0,
	};

	ret = parse_url(url, &hostname, &port, NULL);
	if (ret != 0)
		goto err;


    bev = bufferevent_socket_new(rev->ev_base, 
            -1, BEV_OPT_CLOSE_ON_FREE);
    if (bev == NULL)
        goto err;

    ret = bufferevent_set_timeouts(bev, &read_timeout, NULL);
    if (ret != 0)
        goto err;

    bufferevent_setcb(bev, crl_read_cb, NULL, 
            crl_event_cb, (void*) crl_client);

    ret = bufferevent_socket_connect_hostname(bev, 
            rev->dns_base, AF_UNSPEC, hostname, port);
    if (ret != 0)
        goto err;

    crl_client->buffer = (unsigned char*) calloc(1, MAX_HEADER_SIZE + 1);
	if (crl_client->buffer == NULL) 
		goto err;

    crl_client->bev = bev;
	crl_client->rev_ctx = rev;
	crl_client->buf_size = MAX_HEADER_SIZE;
	crl_client->url = url;

	rev->crl_client_cnt++;

	free(hostname);
	return 0;
 err:
    if (bev != NULL)
        bufferevent_free(bev);
    if (hostname != NULL)
		free(hostname);
	if (crl_client->buffer != NULL)
		free(crl_client->buffer);

	return -1;
}

void client_read_cb(struct bufferevent* bev, void* arg)
{
	fprintf(stderr, "read cb\n");
}

void client_write_cb(struct bufferevent *bev, void* arg)
{
	fprintf(stderr, "write cb\n");
}

void client_event_cb(struct bufferevent* bev, short events, void* arg)
{
	if (events == BEV_EVENT_CONNECTED) {
	fprintf(stderr, "event cb\n");
	revocation_ctx *rev = (revocation_ctx*) arg;
X509 *server_cert = SSL_get_peer_certificate(rev->ssl);
int cert_err = SSL_get_verify_result(rev->ssl);
		int num_urls = 0;
		//char* url;
		int response;
		X509_CRL* crl;

		if (cert_err != X509_V_OK) {
			fprintf(stderr, "cert not ok\n");
			goto err;
		}

		if (server_cert == NULL) {
			fprintf(stderr, "cert is null\n");
			goto err;
		}
		STACK_OF(X509) *cert_chain = SSL_get_peer_cert_chain(rev->ssl);
		X509 *issuer = sk_X509_value(cert_chain, 1);
		char** urls = retrieve_crl_urls(server_cert, &num_urls);
		if (urls == NULL) {
			fprintf(stderr, "returned no URLs\n");
			goto err;
		}

		if (num_urls > 0)
			launch_crl_checks(rev, urls, num_urls);
	}


	return;

err:
	fprintf(stderr, "error in client_event_cb\n");	
}
void crl_read_cb(struct bufferevent* bev, void* arg)
{
	fprintf(stderr, "crl_read_cb\n");
	responder_ctx* resp_ctx = (responder_ctx*) arg;
	revocation_ctx* rev_ctx = resp_ctx->rev_ctx;
	STACK_OF(X509) *cert_chain;
	X509 *cert, *issuer;
	X509_CRL *crl;
	SSL* ssl = rev_ctx->ssl;

	int ret, status;
	int num_read;

	num_read = bufferevent_read(bev, &resp_ctx->buffer[resp_ctx->tot_read], resp_ctx->buf_size - resp_ctx->tot_read);

	resp_ctx->tot_read += num_read;

	if(!resp_ctx->reading_body) {
		if (strstr((char*)resp_ctx->buffer, "\r\n\r\n") != NULL) {
			ret = start_reading_body(resp_ctx);
			if (ret != 0)
				goto err;
		} else if (resp_ctx->tot_read == resp_ctx->buf_size)
			goto err;
	}
	/* A connection could be all done reading both header and body in one go */
	if (done_reading_body(resp_ctx)) {
		const unsigned char* request = resp_ctx->buffer;
		crl = d2i_X509_CRL(NULL, &request, resp_ctx->tot_read);\
		if (crl == NULL) 
			fprintf(stderr, "Why is it null?\n");
	cert = SSL_get_peer_certificate(ssl);
	
	if (cert == NULL) {
		fprintf(stderr, "The cert is null\n");
		goto err;
}
	cert_chain = SSL_get_peer_cert_chain(ssl);
	issuer = sk_X509_value(cert_chain, 1);

	do_crl_response_checks(crl, cert, issuer, &status);

	if (status == X509_V_OK || status == X509_V_ERR_CERT_REVOKED)
		crl_cache_update(rev_ctx->crl_cache, crl);
	else 
		fprintf(stderr, "What's the status\n");
	}

	return;

err:
	fprintf(stderr, "ERROR?\n");
	//WHAT TO DO ON ERROR? WHAT TO CLEAN?
}

void crl_event_cb(struct bufferevent* bev, short events, void* arg)
{
	fprintf(stderr, "crl_event_cb\n");
	responder_ctx* resp_ctx = (responder_ctx*) arg;
	revocation_ctx* rev_ctx = resp_ctx->rev_ctx;
	char* request = NULL;
	int ret;

	if (events & BEV_EVENT_CONNECTED) {
		ret = send_crl_request(bev, resp_ctx->url, request);
		if (ret != 0)
			goto err;

		ret = bufferevent_enable(bev, EV_READ | EV_WRITE);
		if (ret != 0)
			goto err;
	}

	if (events & BEV_EVENT_TIMEOUT || events & BEV_EVENT_ERROR) {
		fprintf(stderr, "Bufferevent timed out/encountered error\n");
		goto err;
	}

	return;
err:
	if (request != NULL)
		free(request);

	//responder_cleanup(resp_ctx);
	if (rev_ctx->crl_client_cnt-- == 0) {
		//set_err_string(sock_ctx, "TLS handshake failure: "
				//"the certificate's revocation status could not be determined");

		//fail_revocation_checks(sock_ctx);
	}
}

int parse_url(char* url, char** host_out, int* port_out, char** path_out) {

	fprintf(stderr, "parse_url\n");
	char* host;
	char* port_ptr;
	char* path;
	int ret, use_ssl;
    long port;

	ret = OCSP_parse_url(url, &host, &port_ptr, &path, &use_ssl);
	if (ret != 1)
		return -1;

    port = strtol(port_ptr, NULL, 10);
    if (port == INT_MAX || port < 0) {
        free(host);
        free(port_ptr);
        free(path);
        return -1;
    }

    free(port_ptr);

	if (host_out != NULL)
		*host_out = host;
	else
		free(host);
	
	if (port_out != NULL)
		*port_out = (int) port;


	if (path_out != NULL)
		*path_out = path;
	else
		free(path);

	return 0;
}

int is_bad_http_response(char* response) {

	char* firstline_end = strstr(response, "\r\n");
	char* response_code_ptr = strchr(response, ' ') + 1;
	
	if (response_code_ptr >= firstline_end) 
		return 1;

	long response_code = strtol(response_code_ptr, NULL, 10);
	if (response_code != 200)
		return 1;

	return 0;
}

int get_http_body_len(char* response) {

	long body_length;

	char* length_ptr = strstr(response, "Content-Length");
	if (length_ptr == NULL)
		return -1;

	if (length_ptr > strstr(response, "\r\n\r\n"))
		return -1;

	length_ptr += strlen("Content-Length");
	
	while(*length_ptr == ' ' || *length_ptr == ':')
		++length_ptr;

	body_length = strtol(length_ptr, NULL, 10);
	if (body_length >= INT_MAX || body_length < 0)
		return -1;

	return (int) body_length;
}

int start_reading_body(responder_ctx* client) {

	unsigned char* body_start;
	int header_len;
	int body_len;

	if (is_bad_http_response((char*) client->buffer))
		return -1;

	body_start = (unsigned char*) strstr((char*) client->buffer, "\r\n\r\n") 
			+ strlen("\r\n\r\n");
	header_len = body_start - client->buffer;

	body_len = get_http_body_len((char*) client->buffer);
	if (body_len < 0)
		return -1;

	unsigned char* tmp_buffer = (unsigned char*) malloc(body_len);
	if (tmp_buffer == NULL)
		return -1;

	client->tot_read -= header_len;
	client->buf_size = body_len;

	memcpy(tmp_buffer, body_start, client->tot_read);
	free(client->buffer);
	client->buffer = tmp_buffer;

	client->reading_body = 1;

	return 0;
}

int done_reading_body(responder_ctx* resp_ctx) {

	return resp_ctx->reading_body && (resp_ctx->tot_read == resp_ctx->buf_size);
}

