/*
 * TLS Wrapping Daemon - transparent TLS wrapping of plaintext connections
 * Copyright (C) 2017, Mark O'Neill <mark@markoneill.name>
 * All rights reserved.
 * https://owntrust.org
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <unistd.h>

#include <event2/bufferevent.h>
#include <event2/listener.h>
#include <event2/util.h>

#include "daemon.h"
#include "daemon_structs.h"
#include "error.h"
#include "in_tls.h"
#include "log.h"
#include "netlink.h"
#include "socket_setup.h"
#include "sockopt_functions.h"


#define MAX_UPGRADE_SOCKET  18


/* SSA direct functions */
static void accept_error_cb(struct evconnlistener *listener, void *ctx);
static void accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
	struct sockaddr *address, int socklen, void *ctx);
static void signal_cb(evutil_socket_t fd, short event, void* arg);
static evutil_socket_t create_server_socket(ev_uint16_t port,
		int family, int protocol);

/* SSA listener functions */
static void listener_accept_error_cb(struct evconnlistener *listener, void *ctx);
static void listener_accept_cb(struct evconnlistener *listener,
		evutil_socket_t fd, struct sockaddr *address, int socklen, void *arg);

int begin_handling_listener_connections(socket_ctx* sock_ctx);


/**
 * Performs all of the steps needed to run the SSA daemon, estabilshes
 * a netlink connection with the kernel module, begins listening on the given 
 * port for connections, and runs the libevent event base indefinitely.
 * This function only returns if an unrecoverable error occurred in the
 * Daemon, or if a SIGINT signal was sent to the process.
 * @param port The port to listen on for new connections.
 * @param config_path A NULL-terminated string identifying the file path
 * of a .yml configuration for the daemon.
 * @returns EXIT_SUCCESS (0) if the event base ran for some indeterminate
 * amount of time successfully, or EXIT_FAILURE (1) if an error occurred
 * before the event base could run.
 */
int run_daemon(int port, char* config_path) {

	struct evconnlistener* listener = NULL;
	daemon_ctx* daemon = NULL;

	evutil_socket_t server_sock;
	
	struct event* sev_pipe = NULL;
	struct event* sev_int = NULL;
	struct event* nl_ev = NULL;

	daemon = daemon_context_new(config_path, port);
	if (daemon == NULL)
		goto err;

	log_printf(LOG_INFO, 
			"Using libevent version %s with %s behind the scenes\n", 
			event_get_version(), event_base_get_method(daemon->ev_base));


	/* Signal handler registration */
	sev_pipe = evsignal_new(daemon->ev_base, SIGPIPE, signal_cb, NULL);
	if (sev_pipe == NULL)
		goto err;
	evsignal_add(sev_pipe, NULL);

	sev_int = evsignal_new(daemon->ev_base, SIGINT, signal_cb, daemon->ev_base);
	if (sev_int == NULL)
		goto err;
	evsignal_add(sev_int, NULL);


	/* Set up server socket with event base */
	server_sock = create_server_socket(port, PF_INET, SOCK_STREAM);
	listener = evconnlistener_new(daemon->ev_base, accept_cb, (void*) daemon,
			LEV_OPT_CLOSE_ON_FREE | LEV_OPT_THREADSAFE, SOMAXCONN, server_sock);
	if (listener == NULL) 
		goto err;

	evconnlistener_set_error_cb(listener, accept_error_cb);

	nl_ev = event_new(daemon->ev_base, nl_socket_get_fd(daemon->netlink_sock),
			EV_READ | EV_PERSIST, netlink_recv, daemon->netlink_sock);
	if (nl_ev == NULL)
		goto err;

	/* lower priority than read/write ops--they're 1 */
	if (event_priority_set(nl_ev, 2) != 0)
		goto err;
	if (event_add(nl_ev, NULL) != 0)
		goto err;


	/* Main event loop */
	if (event_base_dispatch(daemon->ev_base) != 0)
		goto err;



	log_printf(LOG_INFO, "Main event loop terminated\n");

	/* Cleanup */
#if LIBEVENT_VERSION_NUMBER >= 0x02010000
	libevent_global_shutdown();
#endif
	evconnlistener_free(listener); /* This also closes the socket */
	event_free(nl_ev);
	event_free(sev_pipe);
	event_free(sev_int);

	daemon_context_free(daemon); //Free last
	OPENSSL_cleanup();

    return EXIT_SUCCESS;
 err:

	printf("An error occurred setting up the daemon: %s\n", strerror(errno));


	if (listener != NULL)
		evconnlistener_free(listener); /* This also closes the socket */
	if (nl_ev != NULL)
		event_free(nl_ev);
	if (sev_pipe != NULL)
		event_free(sev_pipe);
	if (sev_int != NULL)
		event_free(sev_int);

	if (daemon != NULL)
		daemon_context_free(daemon);
	return EXIT_FAILURE;
}


/**
 * Creates a listening socket that binds to local IPv4 and IPv6 interfaces.
 * It also makes the socket nonblocking (since this software uses libevent).
 * @param port The local port to listen on.
 * @param type SOCK_STREAM or SOCK_DGRAM.
 */
evutil_socket_t create_server_socket(ev_uint16_t port, int family, int type) {
	evutil_socket_t sock;
	char port_buf[6];
	int ret;

	struct evutil_addrinfo hints;
	struct evutil_addrinfo* addr_ptr;
	struct evutil_addrinfo* addr_list;
	struct sockaddr_un bind_addr = {
		.sun_family = AF_UNIX,
	};

	/* Convert port to string for getaddrinfo */
	evutil_snprintf(port_buf, sizeof(port_buf), "%d", (int)port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_socktype = type;

	if (family == PF_UNIX) {
		sock = socket(AF_UNIX, type, 0);
		if (sock == -1) {
			log_printf(LOG_ERROR, "socket: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}

		ret = evutil_make_listen_socket_reuseable(sock);
		if (ret == -1) {
			log_printf(LOG_ERROR, "Failed in evutil_make_listen_socket_reuseable: %s\n",
				 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
			EVUTIL_CLOSESOCKET(sock);
			exit(EXIT_FAILURE);
		}

		ret = evutil_make_socket_nonblocking(sock);
		if (ret == -1) {
			log_printf(LOG_ERROR, "Failed in evutil_make_socket_nonblocking: %s\n",
				 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
			EVUTIL_CLOSESOCKET(sock);
			exit(EXIT_FAILURE);
		}

		strcpy(bind_addr.sun_path+1, port_buf);
		ret = bind(sock, (struct sockaddr*)&bind_addr, sizeof(sa_family_t) + 1 + strlen(port_buf));
		if (ret == -1) {
			log_printf(LOG_ERROR, "bind: %s\n", strerror(errno));
			EVUTIL_CLOSESOCKET(sock);
			exit(EXIT_FAILURE);
		}
		return sock;
	}

	/* AI_PASSIVE for filtering out addresses on which we
	 * can't use for servers
	 *
	 * AI_ADDRCONFIG to filter out address types the system
	 * does not support
	 *
	 * AI_NUMERICSERV to indicate port parameter is a number
	 * and not a string
	 *
	 */
	hints.ai_flags = EVUTIL_AI_PASSIVE | EVUTIL_AI_ADDRCONFIG | EVUTIL_AI_NUMERICSERV;
	/*
	 *  On Linux binding to :: also binds to 0.0.0.0
	 *  Null is fine for TCP, but UDP needs both
	 *  See https://blog.powerdns.com/2012/10/08/on-binding-datagram-udp-sockets-to-the-any-addresses/
	 */
	ret = evutil_getaddrinfo(type == SOCK_DGRAM ? "::" : NULL, port_buf, &hints, &addr_list);
	if (ret != 0) {
		log_printf(LOG_ERROR, "Failed in evutil_getaddrinfo: %s\n", evutil_gai_strerror(ret));
		exit(EXIT_FAILURE);
	}

	for (addr_ptr = addr_list; addr_ptr != NULL; addr_ptr = addr_ptr->ai_next) {
		sock = socket(addr_ptr->ai_family, addr_ptr->ai_socktype, addr_ptr->ai_protocol);
		if (sock == -1) {
			log_printf(LOG_ERROR, "socket: %s\n", strerror(errno));
			continue;
		}

		ret = evutil_make_listen_socket_reuseable(sock);
		if (ret == -1) {
			log_printf(LOG_ERROR, "Failed in evutil_make_listen_socket_reuseable: %s\n",
				 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
			EVUTIL_CLOSESOCKET(sock);
			continue;
		}

		ret = evutil_make_socket_nonblocking(sock);
		if (ret == -1) {
			log_printf(LOG_ERROR, "Failed in evutil_make_socket_nonblocking: %s\n",
				 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
			EVUTIL_CLOSESOCKET(sock);
			continue;
		}

		ret = bind(sock, addr_ptr->ai_addr, addr_ptr->ai_addrlen);
		if (ret == -1) {
			log_printf(LOG_ERROR, "bind: %s\n", strerror(errno));
			EVUTIL_CLOSESOCKET(sock);
			continue;
		}
		break;
	}
	evutil_freeaddrinfo(addr_list);
	if (addr_ptr == NULL) {
		log_printf(LOG_ERROR, "Failed to find a suitable address for binding\n");
		exit(EXIT_FAILURE);
	}

	return sock;
}

/**
 * This function is called after an internal program calls connect() and after
 * that given TLS connection successfully finishes its handshake, but before
 * connect() returns for the internal program. That may seem confusing--here's
 * another way to think of it. Once the daemon has connected on the secure 
 * channel, it notifies the kernel module. The kernel module then takes the
 * `connect()` request from the internal program and reroutes it to this 
 * daemon's listening port and address (rather than the external one). This is 
 * the function that is called once that connection is successfully established.
 * @param listener The listener that the SSA Daemon uses to accept connections 
 * from internal programs.
 * @param fd The socket that is now connected with the internal program.
 * @param address The internal program's address/port combo, encapsulated 
 * within a sockaddr struct.
 * @param addrlen The length of address.
 * @param arg A void pointer referencing the daemon_ctx of the daemon.
 * 
 * WARNING: This is NOT the callback for a listening socket to receive
 * a new connection. The function for that is listener_accept_cb.
 */
void accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
		struct sockaddr *address, int addrlen, void *arg) {
	daemon_ctx* daemon = (daemon_ctx*)arg;
	socket_ctx* sock_ctx;
	int port, ret;
	
	port = get_port(address);
	sock_ctx = (socket_ctx*)hashmap_get(daemon->sock_map_port, port);
	if (sock_ctx == NULL) {
		log_printf(LOG_ERROR, "Unauthorized connection on port %d\n", port);
		return;
	}

    /* Don't clear the socket's error string here */

	if (sock_ctx->state != SOCKET_FINISHING_CONN) {
		log_printf(LOG_ERROR, "accept_cb() called on bad connection\n");
		goto err;
	}

	/* the odds of this are *pretty much nil* */
	if (evutil_make_socket_nonblocking(fd) == -1) {
		log_printf(LOG_ERROR, "Failed in evutil_make_socket_nonblocking: %s\n",
			 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
		goto err;
	}

	log_printf_addr(&sock_ctx->rem_addr);

	ret = associate_fd(sock_ctx, fd);
	if (ret < 0)
		goto err;

	hashmap_del(daemon->sock_map_port, port);
	sock_ctx->state = SOCKET_CONNECTED;

	return;
 err:
	if (sock_ctx != NULL) {
		hashmap_del(daemon->sock_map_port, port);
		socket_shutdown(sock_ctx);
		sock_ctx->state = SOCKET_ERROR;
	}

	EVUTIL_CLOSESOCKET(fd);
	return;
}

/**
 * Callback function that is called whenever an accept() call fails on the
 * main connection listener. This function ignores several errno values; the
 * reason for this can be found in man accept(2), under RETURN VALUE.
 * Additionally, this function ignores ECONNABORTED. The reason can be found
 * here: https://bit.ly/3eHZzFZ
 * Lastly, it ignores EINTR as that error simply means that a signal
 * interrupted the system call before a connection came in.
 * @param listener The SSA daemon's main listener for client connections.
 * @param ctx A void pointer to the daemon_ctx.
 * @returns No return, but exits the event base loop if the error is fatal.
 */
void accept_error_cb(struct evconnlistener *listener, void *ctx) {

	struct event_base* base = NULL;
	int err = EVUTIL_SOCKET_ERROR();

	switch (err) {
	case ENETDOWN:
	case EPROTO:
	case ENOPROTOOPT:
	case EHOSTDOWN:
	case ENONET:
	case EHOSTUNREACH:
	case EOPNOTSUPP:
	case ENETUNREACH:
	case ECONNABORTED:
	case EINTR:
		/* all these errors can be ignored */
		log_printf(LOG_INFO, "Got a nonfatal error %d (%s) on the listener\n",
				err, evutil_socket_error_to_string(err));
		break;
	default:
		log_printf(LOG_ERROR, "Fatal error %d (%s) on the main listener\n",
				err, evutil_socket_error_to_string(err));
		base = evconnlistener_get_base(listener);
		event_base_loopexit(base, NULL);
	}
	return;
}

/**
 * When an external client connects to the server, this callback is called.
 * It is analagous to accept() in normal HTTP connections, but is intended
 * to do everything needed to begin a TLS connection with theexternal client.
 * If this function completes successfully, then tls_bev_events_cb will be
 * called once the TLS handshake has completed. If not, the connection to the
 * client will be dropped.
 * @param efd The file descriptor of the peer that has sent the connect()
 * request to our server. 'Peer' should not be confused with the programmer
 * interacting via c POSIX sockets calls to the daemon; it is simply someone
 * creating a connection with the socket to which this listener_accept_cb
 * was assigned with.
 * @param address The address information sent by the connecting client.
 * @param addrlen The length of the address info sent by the connecting client.
 */
void listener_accept_cb(struct evconnlistener *listener, evutil_socket_t efd,
	struct sockaddr *address, int addrlen, void *arg) {

    /* TODO: could assign address and addrlen to rem_addr and rem_addrlen? */

    struct sockaddr_in int_addr = {
		.sin_family = AF_INET,
		.sin_port = 0, /* allow kernel to give us a random port */
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK)
	};
	socket_ctx* listening_ctx = (socket_ctx*)arg;
	daemon_ctx* daemon = listening_ctx->daemon;
	socket_ctx* new_ctx = NULL;
	socklen_t intaddr_len = sizeof(int_addr);
	evutil_socket_t ifd = -1;
	int ret = 0;

	ret = evutil_make_socket_nonblocking(efd);
	if (ret != 0)
		goto err;

	new_ctx = accepting_socket_ctx_new(listening_ctx, efd);
	if (ret != 0)
		goto err;

	new_ctx->int_addr = listening_ctx->int_addr;
	new_ctx->int_addrlen = listening_ctx->int_addrlen;

    ifd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (ifd == -1)
		goto err;

	ret = evutil_make_socket_nonblocking(ifd);
	if (ret != 0)
		goto err;

	if (bind(ifd, (struct sockaddr*)&int_addr, sizeof(int_addr)) == -1)
		goto err;

	/* refresh the sockaddr info to get the port the kernel assigned us */
	if (getsockname(ifd, (struct sockaddr*)&int_addr, &intaddr_len) == -1)
		goto err;

    ret = prepare_SSL_connection(new_ctx, FALSE);
    if (ret != 0)
        goto err;

    ret = prepare_bufferevents(new_ctx, ifd);
    if (ret != 0)
        goto err;

    new_ctx->accept_port = get_port((struct sockaddr*) &int_addr);
    ret = hashmap_add(daemon->sock_map_port, 
                new_ctx->accept_port, (void*) new_ctx);
    if (ret != 0)
        goto err;

    return;
 err:

	if (new_ctx != NULL)
		socket_context_free(new_ctx);

	if (ifd != -1)
		EVUTIL_CLOSESOCKET(ifd);

	return;
}

void listener_accept_error_cb(struct evconnlistener *listener, void *arg) {

	socket_ctx* sock_ctx = (socket_ctx*) arg;
	int err = EVUTIL_SOCKET_ERROR();

	switch (err) {
	case ENETDOWN:
	case EPROTO:
	case ENOPROTOOPT:
	case EHOSTDOWN:
	case ENONET:
	case EHOSTUNREACH:
	case EOPNOTSUPP:
	case ENETUNREACH:
	case ECONNABORTED:
	case EINTR:
		log_printf(LOG_INFO, "Recoverable error %d (%s) on a server listener\n",
				err, evutil_socket_error_to_string(err));
		/* all these errors can be ignored */
		break;
	default:
		log_printf(LOG_ERROR, "Fatal error %d (%s) on a server listener\n",
				err, evutil_socket_error_to_string(err));

		SSL_free(sock_ctx->ssl);
		evconnlistener_free(listener);
		sock_ctx->sockfd = -1;
		sock_ctx->state = SOCKET_ERROR;

		set_err_string(sock_ctx, "External listener failed with error %i: %s",
				err, strerror(err));
		netlink_error_notify_kernel(sock_ctx->daemon, sock_ctx->id);
		break;
	}
}

void signal_cb(evutil_socket_t fd, short event, void* arg) {
	int signum = fd; /* why is this fd? */
	switch (signum) {
		case SIGPIPE:
            /* TODO: printf is generally dangerous in signal handlers (maybe not for libevent?) */
			log_printf(LOG_DEBUG, "Caught SIGPIPE and ignored it\n");
			break;
		case SIGINT:
			log_printf(LOG_DEBUG, "Caught SIGINT\n");
			event_base_loopbreak(arg);
			break;
		default:
			break;
	}
	return;
}

/**
 * The callback invoked when an internal program calls socket() with the
 * IPPROTO_TLS option. This function creates a socket within the daemon
 * that mirrors any settings or functionality set by the internal program.
 * That socket is added to a hashmap (sock_map), and is used to establish
 * encrypted connections with the external peer via TLS protocols.
 * @param daemon A pointer to the program's daemon_ctx.
 * @param id A uniquely generated ID for the given socket; corresponds with
 * (though is not equal to) the internal program's file descriptor of that
 * socket.
 * @param comm The address path of the calling program.
 * @returns (via netlink) a notification of 0 on success, or -errno on failure.
 */
void socket_cb(daemon_ctx* daemon, unsigned long id, char* comm) {

	socket_ctx* sock_ctx;
	evutil_socket_t fd = -1;
	int response;

    clear_global_errors();

	sock_ctx = (socket_ctx*)hashmap_get(daemon->sock_map, id);
	if (sock_ctx != NULL) {
		log_printf(LOG_ERROR,
				"We have created a socket with this ID already: %lu\n", id);
		response = -ECANCELED;
		sock_ctx = NULL; /* err would try to free sock_ctx otherwise */
		goto err;
	}

    /* TODO: what if AF_INET6 is what the user intents to connect to? */
	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd == -1) {
		response = -errno;
		goto err;
	}

	if (evutil_make_socket_nonblocking(fd) != 0) {
        log_printf(LOG_ERROR, "Failed to make socket nonblocking (errno %i): %s",
                    EVUTIL_SOCKET_ERROR(), strerror(EVUTIL_SOCKET_ERROR()));
		response = -ECANCELED;
		goto err;
	}
	
	response = socket_context_new(&sock_ctx, fd, daemon, id);
	if (response != 0)
		goto err;

	log_printf(LOG_INFO, "Socket created on behalf of application %s\n", comm);
	netlink_notify_kernel(daemon, id, NOTIFY_SUCCESS);
	return;

 err:
	if (fd != -1)
		close(fd);
	if (sock_ctx != NULL)
		socket_context_free(sock_ctx);

	log_printf(LOG_ERROR, "Socket failed to be created: %i\n", response);

	netlink_notify_kernel(daemon, id, response);
	return;
}

void setsockopt_cb(daemon_ctx* ctx, unsigned long id, int level,
		int option, void* value, socklen_t len) {

	socket_ctx* sock_ctx;
	int response = 0; /* Default is success */
	int *version_num;
	sock_ctx = (socket_ctx*)hashmap_get(ctx->sock_map, id);
	if (sock_ctx == NULL) {
		netlink_notify_kernel(ctx, id, -EBADF);
		return;
	}

	clear_global_and_socket_errors(sock_ctx);

	switch (option) {
	case TLS_REMOTE_HOSTNAME:
		if ((response = check_socket_state(sock_ctx, 1, SOCKET_NEW)) != 0)
			break;
		response = set_remote_hostname(sock_ctx, (char*) value, len);
		break;

	case TLS_DISABLE_CIPHER:
		if ((response = check_socket_state(sock_ctx, 1, SOCKET_NEW)) != 0)
			break;
		response = disable_cipher(sock_ctx, (char*) value);
		break;

	case TLS_TRUSTED_PEER_CERTIFICATES:
		if ((response = check_socket_state(sock_ctx, 1, SOCKET_NEW)) != 0)
			break;
		response = set_trusted_CA_certificates(sock_ctx, (char*) value);
		break;

	case TLS_CERTIFICATE_CHAIN:
		if ((response = check_socket_state(sock_ctx, 1, SOCKET_NEW)) != 0)
			break;
		response = set_certificate_chain(sock_ctx, (char*) value);
		break;

	case TLS_PRIVATE_KEY:
		if ((response = check_socket_state(sock_ctx, 1, SOCKET_NEW)) != 0)
			break;
		response = set_private_key(sock_ctx, value);
		break;

	case TLS_VERSION_MIN:
		version_num = (int *) value;
		if (*version_num != TLS_1_2 && *version_num != TLS_1_3) {
			response = -EINVAL;
			log_printf(LOG_DEBUG, "Set TLS_VERSION_MIN not TLS 1.2 or 1.3\n");
			break;
		}
		if (*version_num < get_tls_version(ctx->settings->min_tls_version)) {
			response = -EINVAL;
			log_printf(LOG_DEBUG, "Set TLS_VERSION_MIN less than min in config\n");
			break;
		}
		if (*version_num > SSL_CTX_get_max_proto_version(sock_ctx->ssl_ctx)) {
			response = -EINVAL;
			log_printf(LOG_DEBUG, "Set TLS_VERSION_MIN greater than current max\n");
			break;
		}
		response = (SSL_CTX_set_min_proto_version(sock_ctx->ssl_ctx, *version_num) - 1);
		//returns 1 on success and 0 on failure, but we return 0 on success and -1 on failure
		break;

	case TLS_VERSION_MAX:
		version_num = (int *) value;
		if (*version_num != TLS_1_2 && *version_num != TLS_1_3) {
			response = -EINVAL;
			log_printf(LOG_DEBUG, "Set TLS_VERSION_MAX not 1.2 or 1.3\n");
			break;
		}
		if (*version_num < get_tls_version(ctx->settings->max_tls_version)) {
			response = -EINVAL;
			log_printf(LOG_DEBUG, "Set TLS_VERSION_MAX less than max in config\n");
			break;
		}
		if (*version_num < SSL_CTX_get_min_proto_version(sock_ctx->ssl_ctx)) {
			response = -EINVAL;
			log_printf(LOG_DEBUG, "Set TLS_VERSION_MAX less than current min\n");
			break;
		}
		response = (SSL_CTX_set_max_proto_version(sock_ctx->ssl_ctx, *version_num) - 1);
		//returns 1 on success and 0 on failure, but we return 0 on success and -1 on failure
		break;

	case TLS_ERROR:
	case TLS_HOSTNAME:
	case TLS_TRUSTED_CIPHERS:
	case TLS_ID:
		response = -ENOPROTOOPT; /* all get only */
		break;
	default:
		if (setsockopt(sock_ctx->sockfd, level, option, value, len) == -1) {
			response = -errno;
			set_err_string(sock_ctx, "Daemon error: internal fd setsockopt failed");
		}
		break;
	}

	netlink_notify_kernel(ctx, id, response);
	return;
}

void getsockopt_cb(daemon_ctx* daemon, 
		unsigned long id, int level, int option) {

	socket_ctx* sock_ctx;
	int response = 0;
	void* data = NULL;
	unsigned int len = 0;
	int need_free = 0;
	int version;

	sock_ctx = (socket_ctx*)hashmap_get(daemon->sock_map, id);
	if (sock_ctx == NULL) {
		netlink_notify_kernel(daemon, id, -EBADF);
		return;
	}

    if (option != TLS_ERROR)
        clear_global_and_socket_errors(sock_ctx);

    switch (option) {
	case TLS_ERROR:
		if (!has_error_string(sock_ctx)) {
			response = -EINVAL;
			break;
		}

		data = sock_ctx->err_string;
		len = strlen(sock_ctx->err_string) + 1;
		break;

	case TLS_REMOTE_HOSTNAME:
		if ((response = check_socket_state(sock_ctx,
				2, SOCKET_NEW, SOCKET_CONNECTED)) != 0)
			break;

		if (strlen(sock_ctx->rem_hostname) > 0) {
			data = sock_ctx->rem_hostname;
			len = strlen(sock_ctx->rem_hostname) + 1;
		}
		break;

	case TLS_HOSTNAME:
		if ((response = check_socket_state(sock_ctx, 
				1, SOCKET_ACCEPTED)) != 0)
			break;

		response = get_hostname(sock_ctx, &data, &len);
		break;

	case TLS_PEER_IDENTITY:
		if ((response = check_socket_state(sock_ctx, 2, 
				SOCKET_CONNECTED, SOCKET_ACCEPTED)) != 0)
			break;

		response = get_peer_identity(sock_ctx, &data, &len);
		if (response == 0)
			need_free = 1;
		break;

	case TLS_PEER_CERTIFICATE_CHAIN:
		if ((response = check_socket_state(sock_ctx, 1, SOCKET_CONNECTED)) != 0)
			break;
		response = get_peer_certificate(sock_ctx, &data, &len);
		if (response == 0)
			need_free = 1;
		break;

	case TLS_TRUSTED_CIPHERS:
		response = get_enabled_ciphers(sock_ctx, &data, &len);
		if (response == 0)
			need_free = 1;
		break;

	case TLS_VERSION_MIN:
		version = SSL_CTX_get_min_proto_version(sock_ctx->ssl_ctx);
		data = &version;
		len = sizeof(int);
		break;

	case TLS_VERSION_MAX:
		version = SSL_CTX_get_max_proto_version(sock_ctx->ssl_ctx);
		data = &version;
		len = sizeof(int);
		break;

	case TLS_VERSION_CONN:
		version = SSL_version(sock_ctx->ssl);
		data = &version;
		len = sizeof(int);
		break;

	case TLS_TRUSTED_PEER_CERTIFICATES:
	case TLS_PRIVATE_KEY:
	case TLS_DISABLE_CIPHER:
	case TLS_REQUEST_PEER_AUTH:
		response = -ENOPROTOOPT; /* all set only */
		break;

	case TLS_ID:
		/* This case is handled directly by the kernel.
		 * If we want to change that, uncomment the lines below */
		/* data = &id;
		len = sizeof(id);
		break; */
	default:
		log_printf(LOG_ERROR,
				"Default case for getsockopt hit: should never happen\n");
		response = -EBADF;
		break;
	}

	if (response != 0) {
		netlink_notify_kernel(daemon, id, response);
		return;
	}

	netlink_send_and_notify_kernel(daemon, id, data, len);
	if (need_free == 1)
		free(data);
	
	return;
}

void bind_cb(daemon_ctx* daemon, unsigned long id,
			 struct sockaddr* int_addr, int int_addrlen,
			 struct sockaddr* ext_addr, int ext_addrlen) {

	socket_ctx* sock_ctx = NULL;
	int response = 0;

	sock_ctx = (socket_ctx*) hashmap_get(daemon->sock_map, id);
	if (sock_ctx == NULL) {
		response = -EBADF;
		goto err;
	}

    clear_global_and_socket_errors(sock_ctx);

	response = check_socket_state(sock_ctx, 1, SOCKET_NEW);
	if (response != 0) {
		netlink_notify_kernel(daemon, id, response);
		return;
	}

	if (evutil_make_listen_socket_reuseable(sock_ctx->sockfd) != 0) {
        log_printf(LOG_ERROR, "Failed to make socket nonblocking (errno %i): %s",
                    EVUTIL_SOCKET_ERROR(), strerror(EVUTIL_SOCKET_ERROR()));
		response = -ECANCELED;
		goto err;
	}

	if (bind(sock_ctx->sockfd, ext_addr, ext_addrlen) != 0) {
		response = -errno;
		set_err_string(sock_ctx, "Bind error: SSA daemon socket failed to bind");
		goto err;
	}

	sock_ctx->int_addr = *int_addr;
	sock_ctx->int_addrlen = int_addrlen;
	sock_ctx->ext_addr = *ext_addr;
	sock_ctx->ext_addrlen = ext_addrlen;

	netlink_notify_kernel(daemon, id, NOTIFY_SUCCESS);
	clear_socket_error(sock_ctx);
	return;
 err:

	if (sock_ctx != NULL) {
		EVUTIL_CLOSESOCKET(sock_ctx->sockfd);
		sock_ctx->sockfd = -1;

		sock_ctx->state = SOCKET_ERROR;
	}

	netlink_notify_kernel(daemon, id, response);
	return;
}

/**
 * Begins an attempt to connect via TLS to the remote host. Upon completion,
 * the function client_bev_event_cb() will be called with the appropriate events
 * (BEV_EVENT_CONNECTED on success, BEV_EVENT_ERROR on failure). Since the
 * daemon's internal sockets are always set to non-blocking, this function
 * does not notify the kernel (unless a failure happened from within the
 * function); that is left up to the callback function.
 * @param daemon_ctx The daemon context associated with this daemon.
 * @param id The ID of the socket to attempt to connect. This is used along
 * with a hashmap (sock_map) found in the daemon context in order to retrieve
 * the context specific to the socket being called by the user.
 * @param int_addr The address of the internal peer calling these functions.
 * @param int_addrlen The length of int_addr.
 * @param ext_addr The address of the server we're attempting to connect to.
 * @param ext_addrlen The length of ext_addr.
 * @param blocking Set as 1 if the user's socket is blocking, or 0
 * if it is set as non-blocking. If it is non-blocking, then this function
 * will notify the kernel with the EINPROGRESS errno code before returning.
 * @return No return value--meant to send a netlink message if something is
 * to be returned.
 */
void connect_cb(daemon_ctx* daemon, unsigned long id,
		struct sockaddr* int_addr, int int_addrlen,
		struct sockaddr* rem_addr, int rem_addrlen, int blocking) {

	socket_ctx* sock_ctx;
	int response = 0, ret;

	sock_ctx = (socket_ctx*)hashmap_get(daemon->sock_map, id);
	if (sock_ctx == NULL) {
		netlink_notify_kernel(daemon, id, -EBADF);
        return;
	}

	response = check_socket_state(sock_ctx, 4, 
            SOCKET_NEW, SOCKET_CONNECTING, 
            SOCKET_FINISHING_CONN, SOCKET_CONNECTED);
	if (response != 0) {
		netlink_notify_kernel(daemon, id, response);
		return;
	}

    clear_global_and_socket_errors(sock_ctx);

	if (sock_ctx->state == SOCKET_CONNECTING 
            || sock_ctx->state == SOCKET_FINISHING_CONN) {
		netlink_notify_kernel(daemon, id, -EALREADY);
		return;

	} else if (sock_ctx->state == SOCKET_CONNECTED) {
		netlink_notify_kernel(daemon, id, -EISCONN);
		return;
    }

	sock_ctx->int_addr = *int_addr;
	sock_ctx->int_addrlen = int_addrlen;
	sock_ctx->rem_addr = *rem_addr;
	sock_ctx->rem_addrlen = rem_addrlen;

    response = prepare_SSL_connection(sock_ctx, TRUE);
    if (response != 0)
        goto err;

    response = prepare_bufferevents(sock_ctx, NO_FD);
    if (response != 0)
        goto err;

    ret = bufferevent_socket_connect(sock_ctx->secure.bev, rem_addr, rem_addrlen);
	if (ret != 0) {
		response = -EVUTIL_SOCKET_ERROR();
		set_err_string(sock_ctx, "Internal daemon error: "
				"Failed to initiate TLS handshake");
		goto err;
	}

    ret = hashmap_add(daemon->sock_map_port, get_port(int_addr), sock_ctx);
    if (ret != 0) {
        response = -errno;
        goto err;
    }

    sock_ctx->state = SOCKET_CONNECTING;

	if (!blocking) {
		log_printf(LOG_INFO, "Nonblocking connect requested\n");
		netlink_notify_kernel(daemon, id, -EINPROGRESS);
	}

	return;
 err:

    socket_shutdown(sock_ctx);
    sock_ctx->state = SOCKET_ERROR;

	netlink_notify_kernel(daemon, id, response);
	return;
}

void listen_cb(daemon_ctx* daemon, unsigned long id,
			struct sockaddr* int_addr, int int_addrlen,
			struct sockaddr* ext_addr, int ext_addrlen) {

	socket_ctx* sock_ctx = NULL;
	int response = 0;

	sock_ctx = (socket_ctx*)hashmap_get(daemon->sock_map, id);
	if (sock_ctx == NULL) {
        netlink_notify_kernel(daemon, id, -EBADF);
        return;
	}

    clear_global_and_socket_errors(sock_ctx);

	response = check_socket_state(sock_ctx, 1, SOCKET_NEW);
	if (response != 0) {
		netlink_notify_kernel(daemon, id, response);
		return;
	}

	if (listen(sock_ctx->sockfd, SOMAXCONN) == -1) {
		response = -errno;
		set_err_string(sock_ctx, "Listener setup error: "
				"SSA daemon's external socket returned error on `listen()`");
		goto err;
	}

    response = begin_handling_listener_connections(sock_ctx);
    if (response != 0)
        goto err;

    netlink_notify_kernel(daemon, id, NOTIFY_SUCCESS);
	return;
 err:
	log_printf(LOG_ERROR, "listen_cb failed: %s\n", strerror(-response));
	netlink_notify_kernel(daemon, id, response);

    EVUTIL_CLOSESOCKET(sock_ctx->sockfd);
    sock_ctx->sockfd = -1;

	sock_ctx->state = SOCKET_ERROR;
	return;
}

/**
 * Finishes the process of accepting an incoming client connection.
 * This function is only called after the internal user calls accept()
 * and a TLS connection has been successfully made between the incoming
 * client and the daemon's internal socket. The purpose of this function
 * is to associate an id with the sock_ctx of the already accepted connection
 * so that the internal user can begin to communicate via the daemon to the
 * client.
 */
void associate_cb(daemon_ctx* daemon, unsigned long id,
		struct sockaddr* int_addr, int int_addrlen) {

	socket_ctx* sock_ctx;
	int port = get_port(int_addr);

    clear_global_errors();

	sock_ctx = hashmap_get(daemon->sock_map_port, port);
	if (sock_ctx == NULL) {
		log_printf(LOG_ERROR, "Port provided in associate_cb not found\n");
        /* socket_ctx encountered fatal error and was erased before accepted */
		netlink_notify_kernel(daemon, id, -ECONNABORTED);
		return;
	}

	hashmap_del(daemon->sock_map_port, port);

	if (sock_ctx->state != SOCKET_CONNECTING)
		goto err;

	sock_ctx->id = id;
	sock_ctx->state = SOCKET_ACCEPTED;

	int ret = hashmap_add(daemon->sock_map, id, (void*)sock_ctx);
    if (ret != 0)
        goto err;

    netlink_notify_kernel(daemon, id, 0);
	return;
 err:
    /* Tear down this connection--nobody has access to it anyways */
    socket_shutdown(sock_ctx);
    socket_context_free(sock_ctx);

    netlink_notify_kernel(daemon, id, -ECONNABORTED);
}

/**
 * Closes and frees all internal file descriptors and buffers associated
 * with a socket.
 * @param id The id of the socket to be closed.
 */
void close_cb(daemon_ctx* daemon_ctx, unsigned long id) {
	socket_ctx* sock_ctx;

	sock_ctx = (socket_ctx*)hashmap_get(daemon_ctx->sock_map, id);
	if (sock_ctx == NULL) {
		log_printf(LOG_ERROR, "Close called on non-existent socket\n");
		return;
	}

	switch (sock_ctx->state) {
	case SOCKET_FINISHING_CONN:
	case SOCKET_CONNECTED:
	case SOCKET_ACCEPTED:
		socket_shutdown(sock_ctx);
		break;
	default:
		break;
	}

	socket_context_free(sock_ctx);
	hashmap_del(daemon_ctx->sock_map, id);
	return;
}




int begin_handling_listener_connections(socket_ctx* sock_ctx) {

	sock_ctx->listener = evconnlistener_new(sock_ctx->daemon->ev_base,
			listener_accept_cb, (void*) sock_ctx,
			LEV_OPT_CLOSE_ON_FREE | LEV_OPT_THREADSAFE, 0, sock_ctx->sockfd);

	if (sock_ctx->listener == NULL) {
		set_err_string(sock_ctx, "Listener setup error: "
				"failed to allocate buffers within the SSA daemon");
		return errno;
	}

	evconnlistener_set_error_cb(sock_ctx->listener, listener_accept_error_cb);
    
    sock_ctx->state = SOCKET_LISTENING;
    return 0;
}

