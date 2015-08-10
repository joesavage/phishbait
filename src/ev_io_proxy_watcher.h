#ifndef EV_IO_PROXY_WATCHER_H
#define EV_IO_PROXY_WATCHER_H

#include <errno.h>
#include <ev.h>

struct ev_io_proxy_watcher {
	ev_io io;
	struct ev_io_proxy_watcher *paired_watcher, *alternate_watcher;
	char is_first_time;
	char *data_buffer;
	char *pairs_finished;

	const char *request_uri, *referer;
	size_t request_uri_length, referer_length;
};

struct ev_io *init_ev_io_proxy_watcher(struct ev_io_proxy_watcher *watcher, struct ev_io_proxy_watcher *paired_watcher, struct ev_io_proxy_watcher *alternate_watcher, char *data_chunk, char *shared_buffer);
void ev_io_proxy_watcher_free_pair(struct ev_loop *loop, struct ev_io_proxy_watcher *watcher);
void ev_io_proxy_watcher_free_set(struct ev_loop *loop, struct ev_io_proxy_watcher *watcher);

int ev_io_proxy_watcher_perform_read(struct ev_loop *loop, struct ev_io_proxy_watcher *watcher, int is_read_from_backend);
int ev_io_proxy_watcher_perform_write(struct ev_loop *loop, struct ev_io_proxy_watcher *watcher, int is_write_to_backend);
int ev_io_proxy_watcher_perform_immediate_write_after_read(struct ev_loop *loop, struct ev_io_proxy_watcher *watcher, size_t bytes_read, int is_write_to_backend);
int ev_io_proxy_watcher_perform_immediate_read_after_write(struct ev_loop *loop, struct ev_io_proxy_watcher *watcher, int is_read_from_backend);

#endif
