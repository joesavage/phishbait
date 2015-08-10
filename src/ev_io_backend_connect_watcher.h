#ifndef EV_IO_BACKEND_CONNECT_WATCHER_H
#define EV_IO_BACKEND_CONNECT_WATCHER_H

struct ev_io_backend_connect_watcher {
	struct ev_io io;
	int client_socket;
	struct addrinfo *backend_addrinfo;
};

#endif
