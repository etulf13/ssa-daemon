#include <string.h>

#include <event2/bufferevent.h>

#include "log.h"
#include "netlink.h"
#include "config.h"
#include "revocation.h"



void set_revocation_state(socket_ctx* sock_ctx, enum revocation_state state) {

    daemon_ctx* daemon = sock_ctx->daemon;
    int id = sock_ctx->id;
    int response;

    sock_ctx->rev_ctx.state = state;

    if (sock_ctx->state == SOCKET_FINISHING_CONN) {
        switch (state) {
        case REV_S_PASS:
            response = NOTIFY_SUCCESS;
            break;
        default:
            response = -EPROTO;
            break;
        }

        netlink_handshake_notify_kernel(daemon, id, response);
    }
}



/**
 * Creates an OCSP Request for the given subject certificate and
 * populates it with all the necessary information needed to query
 * an OCSP Responder. Note that this allocates an OCSP_REQUEST struct
 * that should be freed after use.
 * @param subject The certificate to be checked.
 * @param issuer The parent CA certificate of subject.
 * @returns A pointer to a fully-formed OCSP_REQUEST struct.
 * @see OCSP_REQUEST_free 
 */
OCSP_REQUEST* create_ocsp_request(SSL* ssl)
{
    OCSP_REQUEST* request = NULL;
	OCSP_CERTID* id = NULL;

    request = OCSP_REQUEST_new();
    if (request == NULL)
        goto err;

    id = get_ocsp_certid(ssl);
	if (id == NULL)
		goto err;

    if (OCSP_request_add0_id(request, id) == NULL)
		goto err;

    return request;
 err:
	OCSP_REQUEST_free(request);
	return NULL;
}


/**
 * Forms an OCSP certificate ID from the peer's certificate chain found in ssl.
 * @param ssl The already-connected SSL object to form an OCSP_CERTID from.
 * @returns A newly-allocated OCSP_CERTID, or NULL on failure.
 */
OCSP_CERTID* get_ocsp_certid(SSL* ssl) {

	STACK_OF(X509)* certs;
	X509* subject;
	X509* issuer;

	certs = SSL_get_peer_cert_chain(ssl);
	if (certs == NULL || sk_X509_num(certs) < 2)
		return NULL;

	subject = sk_X509_value(certs, 0);
	issuer = sk_X509_value(certs, 1);

	return OCSP_cert_to_id(NULL, subject, issuer);
}


/**
 * Converts a given array of bytes into an OCSP_RESPONSE, checks its validity,
 * and extracts the basic response found within the response.
 * @param bytes The given bytes to convert.
 * @param len The length of bytes.
 * @param resp The OCSP basic response structure extracted from bytes.
 * @returns 0 on success, or -1 if an error occurred.
 */
int get_ocsp_basicresp(unsigned char* bytes, int len, OCSP_BASICRESP** resp) {

	OCSP_RESPONSE* full_response = NULL;
	const unsigned char* const_bytes = bytes;
	int ret;

	full_response = d2i_OCSP_RESPONSE(NULL, &const_bytes, (long)len);
	if (full_response == NULL)
		goto err;

	ret = OCSP_response_status(full_response);
	if (ret != OCSP_RESPONSE_STATUS_SUCCESSFUL)
		goto err;

	*resp = OCSP_response_get1_basic(full_response);
	if (*resp == NULL)
		goto err;

	OCSP_RESPONSE_free(full_response);
	return 0;
 err:
	if (full_response != NULL)
		OCSP_RESPONSE_free(full_response);

	return -1;
}



/*******************************************************************************
 *                 FUNCTIONS FOR GETTING/MANIPULATING URLS
 ******************************************************************************/


/**
 * Parses the AUTHORITY_INFORMATION_ACCESS field out of a given X.509 
 * certificate and returns a list of URLS designating the location of the 
 * OCSP responders.
 * @param cert The X.509 certificate to parse OCSP responder information from.
 * @param num_urls The number of OCSP responder URLs parsed from cert.
 * @returns An allocated array of NULL-terminated strings containing the 
 * URLs of OCSP responders.
 */
char** retrieve_ocsp_urls(X509* cert, int* num_urls) {

	STACK_OF(OPENSSL_STRING) *url_sk = NULL;
	char** urls = NULL;
	url_sk = X509_get1_ocsp(cert);
	if (url_sk == NULL)
		return NULL;

	*num_urls = sk_OPENSSL_STRING_num(url_sk);
	if (*num_urls == 0)
		return NULL;

	urls = calloc(*num_urls, sizeof(char*));
	if (urls == NULL)
		return NULL;

	for (int i = 0; i < *num_urls; i++) 
		urls[i] = sk_OPENSSL_STRING_value(url_sk, i);

	sk_OPENSSL_STRING_free(url_sk);

	return urls;
}


/**
 * Parses the CRL_DISTRIBUTION_POINTS field out of a given X.509 certificate
 * and returns a list of URLs designating the location of the distribution 
 * points.
 * @param cert The X.509 certificate to parse distribution points out of.
 * @param num_urls The number of URLs returned.
 * @returns An allocated array of NULL-terminated strings containing the CRL
 * responder URLs.
 */
/*
char** retrieve_crl_urls(X509* cert, int* num_urls) {

	CRL_DIST_POINTS *points;
	char *urls[10]; /* MAX_URLS */
/*
	int idx = -1;

	*num_urls = 0;

	points = X509_get_ext_d2i(cert, NID_crl_distribution_points, NULL, &idx);

	if (points == NULL) {
		log_printf(LOG_DEBUG, "No crl_distribution_points found\n");
		return NULL;
	}

	while (points != NULL) {
		for (int i = 0; i < sk_DIST_POINT_num(points); i++) {
			log_printf(LOG_DEBUG, "Found a point!\n");

			DIST_POINT *point = sk_DIST_POINT_value(points, i);
			DIST_POINT_NAME *name = point->distpoint;

			GENERAL_NAMES *names = name->name.fullname;
			if (names == NULL) {
				log_printf(LOG_DEBUG, "No general names\n");
			}

			for (int j = 0; j < sk_GENERAL_NAME_num(names); j++) {
				GENERAL_NAME *name = sk_GENERAL_NAME_value(names, j);

				log_printf(LOG_DEBUG, "Found a GENERAL_NAME!\n");
				if (name->type != GEN_URI) {
					log_printf(LOG_DEBUG, "GENERAL_NAME not URI\n");
					continue;
				}

				ASN1_IA5STRING *url_asn1 = name->d.uniformResourceIdentifier;

				unsigned char *url_utf8;
				int len = ASN1_STRING_to_UTF8(&url_utf8, url_asn1);
				if (len < 0) {
					continue;
				}

				urls[*num_urls] = utf8_to_ascii(url_utf8, len);
				if (urls[*num_urls] != NULL)
					(*num_urls)++;

				if (*num_urls >= 10) {
					log_printf(LOG_DEBUG, "Too many CRL Dist Points\n");
					return NULL;
				}

				OPENSSL_free(url_utf8);

			}
		}
		points = X509_get_ext_d2i(cert, NID_crl_distribution_points, NULL, &idx);
	}
	if (*num_urls == 0) {
		log_printf(LOG_DEBUG, "No CRL URLs found\n");
		return NULL;
	}

	log_printf(LOG_DEBUG, "CRL distribution points: \n");
	for (int i = 0; i < *num_urls; i++) {
		printf("%s\n", urls[i]);
	}

	char **response = malloc((*num_urls) * sizeof(char*));
	if (response == NULL)
		return NULL;

	for (int i = 0; i < *num_urls; i++) {
		response[i] = urls[i];
	}

	return response;
}
*/


/**
 * Takes in a given URL and parses it into its hostname, port and path.
 * If no port is specified and the protocol is `http`, then the port specified 
 * will default to 80. Each output may be set to NULL safely (if only some
 * of the outputs are desired).
 * @param url The given url to parse.
 * @param host_out An address to populate with the hostname of the url.
 * @param port_out An address to populate with the port of the url.
 * @param path_out An address to populate with the path of the url.
 * @returns 0 if the url could be successfully parsed, or -1 otherwise.
 */
int parse_url(char* url, char** host_out, int* port_out, char** path_out) {

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


/*******************************************************************************
 *          FUNCTIONS FOR VERIFYING THE CORRECTNESS OF RESPONSES
 ******************************************************************************/

/**
 * Retrieves the OCSP response stapled to the handshake in ssl, and checks to 
 * see if the returned response is valid.
 * @param ssl The TLS connection to retrieve the stapled response from (a 
 * handshake must be performed before calling this function).
 * @returns V_OCSP_CERTSTATUS_GOOD (0) if the stapled response was verified 
 * and it contained a GOOD status for the certificate;
 * V_OCSP_CERTSTATUS_REVOKED (1) if the response was verified and it contained 
 * the REVOKED status for the certificate; and
 * V_OCSP_CERTSTATUS_UNKNOWN (2) if the response could not be verified OR if 
 * the responder could not return a definitive answer on the certificate's
 * revocation status OR if no response was stapled.
 */
int check_stapled_response(socket_ctx* sock_ctx) {

    SSL* ssl = sock_ctx->ssl;
	unsigned char* stapled_resp;
	int resp_len, ret;

	resp_len = SSL_get_tlsext_status_ocsp_resp(ssl, &stapled_resp);
	if (resp_len < 0)
		return V_OCSP_CERTSTATUS_UNKNOWN;

    ret = do_ocsp_response_checks(stapled_resp, resp_len, sock_ctx);

	return ret;
}


/**
 * Checks the given OCSP response to ensure it is not malformed or invalid, 
 * and then caches the response and returns its status.
 * @param resp_bytes An OCSP response in binary format.
 * @param resp_len The length of resp_bytes.
 * @param sock_ctx The connection to check the response for.
 * @returns V_OCSP_CERTSTATUS_GOOD (0) if the response was properly verified 
 * and it contained a GOOD status for the certificate;
 * V_OCSP_CERTSTATUS_REVOKED (1) if the response was properly verified and it
 * contained the REVOKED status for the certificate; and
 * V_OCSP_CERTSTATUS_UNKNOWN (2) if the response could not be verified OR if 
 * the responder could not return a definitive answer on the certificate's
 * revocation status.
 */
int do_ocsp_response_checks(unsigned char* resp_bytes,
		 int resp_len, socket_ctx* sock_ctx) {

	OCSP_BASICRESP* basicresp = NULL;
	SSL* ssl = sock_ctx->ssl;
	STACK_OF(X509)* chain = NULL;
	X509_STORE* store = NULL;
	OCSP_CERTID* id = NULL;
	int status, ret;

	chain = SSL_get_peer_cert_chain(ssl);
	store = SSL_CTX_get_cert_store(SSL_get_SSL_CTX(ssl));
	if (chain == NULL || store == NULL)
		goto err;

	ret = get_ocsp_basicresp(resp_bytes, resp_len, &basicresp);
	if (ret != 0)
		goto err;

	id = get_ocsp_certid(ssl);
	if (id == NULL)
		goto err;

	status = verify_ocsp_basicresp(basicresp, id, chain, store);
	if (status == V_OCSP_CERTSTATUS_UNKNOWN)
		goto err;

    /* even if a user doesn't check cached responses, we should add them */
	add_to_ocsp_cache(id, basicresp, sock_ctx->daemon);

	OCSP_CERTID_free(id);

	return status;
 err:
	// Something went wrong with parsing/verification
	if (basicresp != NULL)
		OCSP_BASICRESP_free(basicresp);
	if (id != NULL)
		OCSP_CERTID_free(id);
	
	return V_OCSP_CERTSTATUS_UNKNOWN;
}


/**
 * Verifies the correctness of the signature and timestamps present in the 
 * given CRL list and checks to see if it contains an entry for the certificate 
 * found in ssl. If so, the CRL revoked status is returned.
 * If the response failes to validate, then the UNKNOWN status is returned.
 * @param response The response to verify the correctness of.
 * @param ssl The TLS connection to verify the response on.
 * @returns 1 if a revoked status was found for the certificate in the CRL, or
 * 0 if no such status was found; or -1 if the response's correctness could not 
 * be verified.
 */
/*
int do_crl_response_checks(X509_CRL* crl, SSL* tls, X509* subject, X509* issuer, int* response) {

	const ASN1_TIME * thisupd, * nextupd;
	X509_REVOKED *revoked;
	EVP_PKEY *CA_public_key;
	int ret;

	CA_public_key = X509_get0_pubkey(issuer);

	ret = X509_CRL_verify(crl, CA_public_key);
	if (ret != 1) {
		/* signature check failed */
/*		log_printf(LOG_ERROR, "CRL signature doesn't match CA\n");
		*response = X509_V_ERR_CRL_SIGNATURE_FAILURE;
		return -1;
	}

	thisupd = X509_CRL_get0_lastUpdate(crl);
	if (thisupd == NULL) {
		*response = X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD;
		return -1;
	}
	nextupd = X509_CRL_get0_nextUpdate(crl); /* doesn't matter if NULL */
/*
	ret = crl_check_times(thisupd, nextupd, LEEWAY_90_SECS, MAX_OCSP_AGE);
	if (ret != 1) {
		log_printf(LOG_ERROR, "CRL dates expired or else malformed\n");
		*response = X509_V_ERR_CRL_HAS_EXPIRED;
		/* or X509_V_ERR_CRL_NOT_YET_VALID... */
/*		return -1;
	}

	ret = X509_CRL_get0_by_cert(crl, &revoked, subject);
	if (ret == 1) {
		/* ASN1_TIME *time = X509_revoked_get0_revocationDate(revoked); */
/*		*response = X509_V_ERR_CERT_REVOKED;
		return -1;
	}

	*response = X509_V_OK;
	return 0;
}
*/



/**
 * Verifies the correctness of the signature and timestamps present in 
 * response and checks to make sure it matches the certificate found 
 * in ssl. The OCSP response status found in response is then returned.
 * If the response failes to validate, then the UNKNOWN status is returned.
 * @param response The response to verify the correctness of.
 * @param ssl The TLS connection to verify the response on.
 * @returns V_OCSP_CERTSTATUS_GOOD (0) if the response was properly verified 
 * and it contained a GOOD status for the certificate;
 * V_OCSP_CERTSTATUS_REVOKED (1) if the response was properly verified and it
 * contained the REVOKED status for the certificate; and
 * V_OCSP_CERTSTATUS_UNKNOWN (2) if the response could not be verified OR if 
 * the responder could not return a definitive answer on the certificate's
 * revocation status.
 */
int verify_ocsp_basicresp(OCSP_BASICRESP* resp, 
		OCSP_CERTID* id, STACK_OF(X509)* certs, X509_STORE* store) {
	
	ASN1_GENERALIZEDTIME* revtime = NULL;
	ASN1_GENERALIZEDTIME* thisupd = NULL;
	ASN1_GENERALIZEDTIME* nextupd = NULL;
	int ret, status, reason;

    ret = OCSP_basic_verify(resp, certs, store, 0);
    if (ret != 1)
		return V_OCSP_CERTSTATUS_UNKNOWN;


    ret = OCSP_resp_find_status(resp, id, 
			&status, &reason, &revtime, &thisupd, &nextupd);
    if (ret != 1)
		return V_OCSP_CERTSTATUS_UNKNOWN;


    ret = OCSP_check_validity(thisupd, nextupd, LEEWAY_90_SECS, MAX_OCSP_AGE);
    if (ret != 1) {
        /* response too old */
        log_printf(LOG_ERROR, "cert is too old or has invalid timestamps\n");
        status = V_OCSP_CERTSTATUS_UNKNOWN;
    }

	return status;
}

/*******************************************************************************
 *                   FUNCTIONS TO DO WITH OCSP CACHING
 ******************************************************************************/



/**
 * Parses the hexadecimal ID of a given OCSP_CERTID.
 * @param certid The OCSP_CERTID to parse an ID from.
 * @returns An ASCII representation of the hexadecimal ID of certid.
 */
char* get_ocsp_id_string(OCSP_CERTID* certid) {

	ASN1_INTEGER* id_int = NULL;
	BIGNUM* id_bignum = NULL;
	char* id_string = NULL;
	char* tmp = NULL;

	OCSP_id_get0_info(NULL, NULL, NULL, &id_int, certid);
	if (id_int == NULL)
		goto err;

	id_bignum = ASN1_INTEGER_to_BN(id_int, NULL);
	if (id_bignum == NULL)
		goto err;

	tmp = BN_bn2hex(id_bignum);
	if (tmp == NULL)
		goto err;

	id_string = strdup(tmp);

	OPENSSL_free(tmp); //so that we don't have to free this way later
	BN_free(id_bignum);

	return id_string;
 err:
	if (id_bignum != NULL)
		BN_free(id_bignum);

	return NULL;
}


/**
 * Adds the given OCSP response to the revocation cache of the daemon.
 * @param response The response to add to the cache
 */
int add_to_ocsp_cache(OCSP_CERTID* id, 
		OCSP_BASICRESP* response, daemon_ctx* daemon) {
	hsmap_t* rev_cache = daemon->revocation_cache;
	char* id_string = NULL;
	int ret;

	id_string = get_ocsp_id_string(id);
	if (id_string == NULL)
		return -1;
	
	ret = str_hashmap_add(rev_cache, id_string, (void*)response);
	if (ret != 0) {
		log_printf(LOG_INFO, "Cache entry already exists\n");
        OCSP_BASICRESP_free(response);
		free(id_string);
		return -1;
	}

	return 0;
}


int check_cached_response(socket_ctx* sock_ctx) {

	hsmap_t* rev_cache = sock_ctx->daemon->revocation_cache;
	OCSP_BASICRESP* cached_resp = NULL;
	STACK_OF(X509)* chain = NULL;
	X509_STORE* store = NULL;
	OCSP_CERTID* id = NULL;
	char* id_string = NULL;
	int ret;

	store = SSL_CTX_get_cert_store(SSL_get_SSL_CTX(sock_ctx->ssl));
	chain = SSL_get_peer_cert_chain(sock_ctx->ssl);
	if (store == NULL || chain == NULL)
		goto err;

	id = get_ocsp_certid(sock_ctx->ssl);
	if (id == NULL)
		goto err;

	id_string = get_ocsp_id_string(id);
	if (id_string == NULL)
		goto err;

	cached_resp = (OCSP_BASICRESP*) str_hashmap_get(rev_cache, id_string);
	if (cached_resp == NULL)
		goto err;

	ret = verify_ocsp_basicresp(cached_resp, id, chain, store);
	if (ret == V_OCSP_CERTSTATUS_UNKNOWN) {
		str_hashmap_del(rev_cache, id_string);
		goto err;
	}

	OCSP_CERTID_free(id);
	free(id_string);
	return ret;
 err:
	if (id != NULL)
		OCSP_CERTID_free(id);
	if (id_string != NULL)
		free(id_string);

	return V_OCSP_CERTSTATUS_UNKNOWN;
}
/*
int check_crl_cache (socket_ctx* sock_ctx) {

	hcmap_t* crl_cache = sock_ctx->daemon->crl_cache;
	X509* cert;
	ASN1_INTEGER* serial;
	BIGNUM *big_serial;
	char *hex_serial;
	char *hash;


	cert = SSL_get_peer_certificate(sock_ctx->ssl);
	serial = X509_get_serialNumber(cert);
	big_serial = ASN1_INTEGER_to_BN(serial, NULL);
	hex_serial = BN_bn2hex(big_serial);

	hash = crl_convert(hex_serial);

	fprintf(stderr, "%s\n", hex_serial);
	if (crl_hashmap_get(crl_cache, hash, 17)) {
		log_printf(LOG_DEBUG, "Revoked in CRL cache\n");
		return -1;
	}
	BN_free(big_serial);
	OPENSSL_free(hex_serial);
	free(hash);
	return 0;
}
*/	

/*
int crl_check_times(const ASN1_TIME* thisupd,
		const ASN1_TIME* nextupd, long nsec, long maxsec) {

	int ret = 1;
	time_t t_now, t_tmp;
	time(&t_now);
	/* Check thisUpdate is valid and not more than nsec in the future */
/*	if (!ASN1_TIME_check(thisupd)) {
		log_printf(LOG_ERROR, "CRL thisupd invalid\n");
		/* TODO: print "ERROR in thisupd field--invalid format\n" */
/*		ret = 0;
	} else {
		t_tmp = t_now + nsec;
		if (X509_cmp_time(thisupd, &t_tmp) > 0) {
			log_printf(LOG_ERROR, "CRL not yet valid\n");
			/* Print error CRL not yet valid */
			/*ret = 0;
		}

		/*
		 * If maxsec specified check thisUpdate is not more than maxsec
		 * in the past
		 */
/*		if (maxsec >= 0) {
			t_tmp = t_now - maxsec;
			if (X509_cmp_time(thisupd, &t_tmp) < 0) {
				log_printf(LOG_ERROR, "CRL status too old (our checks\n");
				/* Print error CRL status too old */
/*				ret = 0;
			}
		}
	}

	if (!nextupd)
		return ret;

	/* Check nextUpdate is valid and not more than nsec in the past */
/*	if (!ASN1_TIME_check(nextupd)) {
		/* TODO: Print error in nextUpdate Field */
/*		log_printf(LOG_ERROR, "CRL nextupd malformed\n");
		ret = 0;
	} else {
		t_tmp = t_now - nsec;
		if (X509_cmp_time(nextupd, &t_tmp) < 0) {
			/* TODO: Print error CRL expired */
		/*	log_printf(LOG_ERROR, "CRL expired\n");
			ret = 0;
		}
	}

	/* Also don't allow nextUpdate to precede thisUpdate */
/*	if (ASN1_STRING_cmp(nextupd, thisupd) < 0) {
		/* TODO: Print error nextupd was before thisupd */
/*		ret = 0;
	}

	return ret;
}
*/
/*
int crl_cache_update(daemon_ctx *daemon, X509_CRL *crl) {

	log_printf(LOG_DEBUG, "Updating the CRL cache\n");
	STACK_OF(X509_REVOKED) *rev = NULL;
	X509_REVOKED *rev_entry;
	char *hash;
	int revnum;
	const ASN1_INTEGER *serial_num;
	BIGNUM *big_serial;
	char *hex_serial;
	rev = X509_CRL_get_REVOKED(crl);
	FILE* crl_cache = fopen("crl_cache.txt", "a");
	//FILE* cache_metadoc = fopen("crl_cache_info.txt", "a");



	if (rev == NULL)
		goto err;

	revnum = sk_X509_REVOKED_num(rev);
	fprintf(stderr, "Size: %d\n", sizeof(ASN1_INTEGER));
	for (int i = 0; i < revnum; i++) { //change revnum to revnum - 1 for metadoc info
		rev_entry = sk_X509_REVOKED_value(rev, i);
		serial_num = X509_REVOKED_get0_serialNumber(rev_entry);
		big_serial = ASN1_INTEGER_to_BN(serial_num, NULL);
		hex_serial = BN_bn2hex(big_serial);
		hash = crl_convert(hex_serial);
		if (crl_hashmap_add(daemon->crl_cache, hash, 17)) {
			fprintf(stderr, "add\n");
			for (int j = 0; j < 16; j++) {
				fputc(hash[j], crl_cache);
			}
			//fputc('\n', crl_cache);
		}
		else
			fprintf(stderr, "%s was already in the cache\n", hex_serial);
		BN_free(big_serial);
		OPENSSL_free(hex_serial);
	}
	//str_hashmap_print(daemon->crl_cache);
	//if (i == revnum - 1)
		//get date, return date?
	crl_hashmap_print(daemon->crl_cache);

	fclose(crl_cache);
	//fclose(cache_metadoc);
	return 0;

err:
	fclose(crl_cache);
	//fclose(cache_metadoc);
	return -1;
}
*/
/*
char char_convert(char char1, char char2)
{
	if (char1 & 0x40)
		char1 |= 0x08;
	char1 &= 0x0F;
	if (char2 & 0x40)
		char2 |= 0x08;
	char2 &= 0x0F;
	char1 = char1 << 4;
	char1 |= char2;
	return char1;
}

char* crl_convert(char* serial) {
	int len = strlen(serial);
	char* conversion = malloc((len/2) + 1);

	for (int i = 0; i < len; i+=2) {
		conversion[i/2] = char_convert(serial[i], serial[i+1]);
	}
	conversion[16] = '\0';
	return conversion;
}
*/




