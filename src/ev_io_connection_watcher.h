#ifndef EV_IO_CONNECTION_WATCHER_H
#define EV_IO_CONNECTION_WATCHER_H

struct ev_io_connection_watcher {
	struct ev_io io;
	struct addrinfo *backend_addrinfo;
};

#endif
