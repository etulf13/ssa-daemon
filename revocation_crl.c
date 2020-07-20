#include <string.h>
#include <unistd.h>
#include "revocation_crl.h"
#include "config.h"



int form_crl_http_request(char *host, char *path, char **request);
int crl_check_times(const ASN1_TIME* thisupd,
		const ASN1_TIME* nextupd, long nsec, long maxsec);

char char_convert(char char1, char char2);
char* crl_convert(char* serial);

char* serial_dup(char* serial);
int get_serial(char* serial, FILE* cache_ptr);


char** retrieve_crl_urls(X509* cert, int* num_urls) {

	CRL_DIST_POINTS *points;
	char *urls[10]; /* MAX_URLS */
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

int crl_parse_url(const char *url, char **host, char **port, char **path) {

	char *p, *buf;
	char *tmp_host;
	char *tmp_port = "80";

	if (url ==NULL) {
		/* TODO: Throw an error here analagous to the one below */
		/* HTTPerr(0, ERR_R_PASSED_NULL_PARAMETER); */
		return -1;
	}

	if (host != NULL)
		*host = NULL;
	if (port != NULL)
		*port = NULL;
	if (path != NULL)
		*path = NULL;

	/* dup the buffer since we are going to mess with it */
	if ((buf = OPENSSL_strdup(url)) == NULL)
		goto err;

	/* Check for initial colon */
	p = strchr(buf, ':');
	if (p == NULL || p - buf > 5 /* strlen("https") */) {
		p = buf;
	} else {
		*(p++) = '\0';

		if (strcmp(buf, "http") != 0) {
			goto parse_err;
		}

		/* Check for double slash */
		if ((p[0] != '/') || (p[1] != '/'))
			goto parse_err;
		p += 2;
	}
	tmp_host = p;

	/* Check for trailing part of path */
	p = strchr(p, '/');
	if (path != NULL && (*path = OPENSSL_strdup(p == NULL ? "/" : p)) == NULL)
		goto err;
	if (p != NULL)
		*p = '\0'; /* Set start of path to = so hostname[:port] is valid */

	p = tmp_host;
	if (tmp_host[0] == '[') {
		/* ipv6 listeral */
		tmp_host++;
		p = strchr(tmp_host, ']');
		if (p == NULL)
			goto parse_err;
		*p = '\0';
		p++;
	}

	/* Look for optional ':' for port number */
	if ((p = strchr(p, ':'))) {
		*p = '\0';
		tmp_port = p + 1;
	}
	if (host != NULL && (*host = OPENSSL_strdup(tmp_host)) == NULL)
		goto err;
	if (port != NULL && (*port = OPENSSL_strdup(tmp_port)) == NULL)
		goto err;

	OPENSSL_free(buf);
	return 0;

parse_err:
	/* TODO: Throw an error here analogous to the one below */
	/* HTTPerr(0, HTTP_R_ERROR_PARSING_URL); */

err:
	if (path != NULL) {
		OPENSSL_free(*path);
		*path = NULL;
	}
	if (port != NULL) {
		OPENSSL_free(*port);
		*port = NULL;
	}
	if (host != NULL) {
		OPENSSL_free(*host);
		*host = NULL;
	}
	OPENSSL_free(buf);
	return -1;
}

int form_crl_http_request(char *host, char *path, char **request) {

	char header[MAX_HEADER_SIZE] = {0};
	int len;

	len = snprintf(header, MAX_HEADER_SIZE,
		"GET %s HTTP/1.1\r\n"
		"Host: %s\r\n"
		"Accept: */*\r\n"
		"Accept-Encoding: identity\r\n"
		"Connection: close\r\n"
		"\r\n", path, host);

	if (len < 0 || len >= MAX_HEADER_SIZE) {
		fprintf(stderr, "SNPRINTF\n");
		return -1; /* snprintf failed; or too much header */
	}

	*request = malloc(len);
	if (*request == NULL) {
		fprintf(stderr, "form_http_request failed");
		return -1;
	}

	memcpy(*request, header, len);

	return len;
}

int send_crl_request(struct bufferevent* bev, char* url, char* http_req) {
	fprintf(stderr, "send_crl_request\n");
	http_req = NULL;
	char* host = NULL;
	char* path = NULL;
	int ret, req_len;

	ret = crl_parse_url(url, &host, NULL, &path);
	if (ret != 0) {
		fprintf(stderr, "crl_parse_url\n");
		goto err;
	}

	req_len = form_crl_http_request(host, path, &http_req);
	if (req_len < 0) {
		log_printf(LOG_ERROR, "form_http_request failed\n");
		goto err;
	}

	ret = bufferevent_write(bev, http_req, req_len);
	if (ret != 0) {
		log_printf(LOG_ERROR, "Bufferevent_write failed\n");
		goto err;
	}

	free(http_req);
	OPENSSL_free(host);
	OPENSSL_free(path);
	return 0;
 err:
	fprintf(stderr, "error in send_crl_request\n");
	if (http_req != NULL)
		free(http_req);
	if (host != NULL)
		OPENSSL_free(host);
	if (path != NULL)
		OPENSSL_free(path);

	return -1;
}

int do_crl_response_checks(X509_CRL* crl, X509* subject, X509* issuer, int* response) {

	const ASN1_TIME * thisupd, * nextupd;
	X509_REVOKED *revoked;
	EVP_PKEY *CA_public_key;
	int ret;

	CA_public_key = X509_get0_pubkey(issuer);

	ret = X509_CRL_verify(crl, CA_public_key);
	if (ret != 1) {
		/* signature check failed */
		log_printf(LOG_ERROR, "CRL signature doesn't match CA\n");
		*response = X509_V_ERR_CRL_SIGNATURE_FAILURE;
		return -1;
	}

	thisupd = X509_CRL_get0_lastUpdate(crl);
	if (thisupd == NULL) {
		*response = X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD;
		return -1;
	}
	nextupd = X509_CRL_get0_nextUpdate(crl); /* doesn't matter if NULL */

	ret = crl_check_times(thisupd, nextupd, LEEWAY_90_SECS, MAX_OCSP_AGE);
	if (ret != 1) {
		log_printf(LOG_ERROR, "CRL dates expired or else malformed\n");
		*response = X509_V_ERR_CRL_HAS_EXPIRED;
		/* or X509_V_ERR_CRL_NOT_YET_VALID... */
		return -1;
	}

	ret = X509_CRL_get0_by_cert(crl, &revoked, subject);
	if (ret == 1) {
		/* ASN1_TIME *time = X509_revoked_get0_revocationDate(revoked); */
		*response = X509_V_ERR_CERT_REVOKED;
		return -1;
	}

	*response = X509_V_OK;
	return 0;
}

int crl_check_times(const ASN1_TIME* thisupd,
		const ASN1_TIME* nextupd, long nsec, long maxsec) {

	int ret = 1;
	time_t t_now, t_tmp;
	time(&t_now);
	/* Check thisUpdate is valid and not more than nsec in the future */
	if (!ASN1_TIME_check(thisupd)) {
		log_printf(LOG_ERROR, "CRL thisupd invalid\n");
		/* TODO: print "ERROR in thisupd field--invalid format\n" */
		ret = 0;
	} else {
		t_tmp = t_now + nsec;
		if (X509_cmp_time(thisupd, &t_tmp) > 0) {
			log_printf(LOG_ERROR, "CRL not yet valid\n");
			/* Print error CRL not yet valid */
			ret = 0;
		}

		/*
		 * If maxsec specified check thisUpdate is not more than maxsec
		 * in the past
		 */
		if (maxsec >= 0) {
			t_tmp = t_now - maxsec;
			if (X509_cmp_time(thisupd, &t_tmp) < 0) {
				log_printf(LOG_ERROR, "CRL status too old (our checks\n");
				/* Print error CRL status too old */
				ret = 0;
			}
		}
	}

	if (!nextupd)
		return ret;

	/* Check nextUpdate is valid and not more than nsec in the past */
	if (!ASN1_TIME_check(nextupd)) {
		/* TODO: Print error in nextUpdate Field */
		log_printf(LOG_ERROR, "CRL nextupd malformed\n");
		ret = 0;
	} else {
		t_tmp = t_now - nsec;
		if (X509_cmp_time(nextupd, &t_tmp) < 0) {
			/* TODO: Print error CRL expired */
			log_printf(LOG_ERROR, "CRL expired\n");
			ret = 0;
		}
	}

	/* Also don't allow nextUpdate to precede thisUpdate */
	if (ASN1_STRING_cmp(nextupd, thisupd) < 0) {
		/* TODO: Print error nextupd was before thisupd */
		ret = 0;
	}

	return ret;
}

int check_crl_cache(hcmap_t* cache_map, X509* cert) {

	ASN1_INTEGER* serial;
	BIGNUM *big_serial;
	char *hex_serial;
	char *hash;


	serial = X509_get_serialNumber(cert);
	big_serial = ASN1_INTEGER_to_BN(serial, NULL);
	hex_serial = BN_bn2hex(big_serial);

	hash = crl_convert(hex_serial);

	fprintf(stderr, "%s\n", hex_serial);
	if (crl_hashmap_get(cache_map, hash, 17)) {
		log_printf(LOG_DEBUG, "Revoked in CRL cache\n");
		return -1;
	}
	BN_free(big_serial);
	OPENSSL_free(hex_serial);
	free(hash);
	return 0;
}

int crl_cache_update(hcmap_t* cache_map, X509_CRL* crl) {

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
	fprintf(stderr, "Size: %ld\n", sizeof(ASN1_INTEGER));
	for (int i = 0; i < revnum; i++) { //change revnum to revnum - 1 for metadoc info
		rev_entry = sk_X509_REVOKED_value(rev, i);
		serial_num = X509_REVOKED_get0_serialNumber(rev_entry);
		big_serial = ASN1_INTEGER_to_BN(serial_num, NULL);
		hex_serial = BN_bn2hex(big_serial);
		hash = crl_convert(hex_serial);
		if (crl_hashmap_add(cache_map, hash, 17)) {
			fprintf(stderr, "add\n");
			for (int j = 0; j < 16; j++) {
				fputc(hash[j], crl_cache);
			}
			//fputc('\n', crl_cache);
		}
		else
			//fprintf(stderr, "%s was already in the cache\n", hex_serial);
		BN_free(big_serial);
		OPENSSL_free(hex_serial);
	}
	//str_hashmap_print(cache_map);
	//if (i == revnum - 1)
		//get date, return date?
	//crl_hashmap_print(cache_map);

	fclose(crl_cache);
	//fclose(cache_metadoc);
	return 0;

err:
	fclose(crl_cache);
	//fclose(cache_metadoc);
	return -1;
}

char char_convert(char char1, char char2) {

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

int read_crl_cache(hcmap_t* cache_map, FILE* cache_ptr) {

	char* serial_no = malloc(17 * sizeof(char));
	char* dup;

	while (get_serial(serial_no, cache_ptr)) {
		dup = serial_dup(serial_no); //allocates memory for the string
		crl_hashmap_add(cache_map, dup, 17);
	}
	fclose(cache_ptr);
	free(serial_no);
	return 1;
}

char* serial_dup(char* serial) {

	char* dup = malloc(17 * sizeof(char));
	for (int i = 0; i < 17; i++) {
		dup[i] = serial[i];
	}
	return dup;
}

int get_serial(char* serial, FILE* cache_ptr) {

	for (int i = 0; i < 16; i++) {
		serial[i] = fgetc(cache_ptr);
		if (serial[i] == EOF)
			return 0;
	}
	serial[16] = '\0';
	return 1;
}
