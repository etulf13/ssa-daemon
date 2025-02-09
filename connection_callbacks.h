#ifndef SSA_CONNECTION_CALLBACKS_H
#define SSA_CONNECTION_CALLBACKS_H

#include <event2/bufferevent.h>
#include "daemon_structs.h"

#define MAX_BUFFER	1024*1024*10 /* 10 Megabits */



void common_bev_write_cb(struct bufferevent *bev, void *arg);
void common_bev_read_cb(struct bufferevent *bev, void *arg);

void client_bev_event_cb(struct bufferevent *bev, short events, void *arg);
void server_bev_event_cb(struct bufferevent *bev, short events, void *arg);

int revocation_cb(SSL* ssl, void* arg);

int set_inotify(daemon_ctx *daemon);



#endif
