#ifndef EV_IO_CLIENT_CONNECT_WATCHER_H
#define EV_IO_CLIENT_CONNECT_WATCHER_H

struct ev_io_client_connect_watcher {
	struct ev_io io;
	struct addrinfo *backend_addrinfo;
};

#endif
