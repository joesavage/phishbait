#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "ev_io_proxy_watcher.h"
#include "utilities.h"

struct ev_io *init_ev_io_proxy_watcher(struct ev_io_proxy_watcher *watcher, struct ev_io_proxy_watcher *paired_watcher, struct ev_io_proxy_watcher *alternate_watcher, char *data_chunk, char *pairs_finished, char *custom_pair_data) {
	watcher->paired_watcher = paired_watcher;
	watcher->alternate_watcher = alternate_watcher;
	watcher->data_buffer = data_chunk;
	watcher->data_buffer[READ_BUFFER_SIZE] = '\0';
	watcher->pairs_finished = pairs_finished;
	*watcher->pairs_finished = 0;
	watcher->custom_pair_data = custom_pair_data;
	watcher->is_first_time = 1;
	watcher->request_uri = watcher->referer = NULL;
	watcher->request_uri_length = watcher->referer_length = 0;

	return (struct ev_io *)watcher;
}

void ev_io_proxy_watcher_free_pair(struct ev_loop *loop, struct ev_io_proxy_watcher *watcher) {
	ev_io_stop(loop, (struct ev_io *)watcher);
	if (++(*watcher->pairs_finished) == 2) {
		close(watcher->io.fd);
		close(watcher->paired_watcher->io.fd);
		memory_free(watcher->pairs_finished);
	}
	memory_free(watcher->data_buffer);
	if (watcher->custom_pair_data != NULL) { memory_free(watcher->custom_pair_data); }
	memory_free(watcher->paired_watcher);
	memory_free(watcher);
}

void ev_io_proxy_watcher_free_set(struct ev_loop *loop, struct ev_io_proxy_watcher *watcher) {
	struct ev_io_proxy_watcher *alternate_watcher = watcher->alternate_watcher;
	ev_io_stop(loop, &alternate_watcher->paired_watcher->io);
	ev_io_proxy_watcher_free_pair(loop, alternate_watcher);
	ev_io_proxy_watcher_free_pair(loop, watcher);
}

int ev_io_proxy_watcher_perform_read(struct ev_loop *loop, struct ev_io_proxy_watcher *watcher, int is_read_from_backend) {
	// Read from the watcher's socket into the watcher's data chunk
	// NOTE: It might be desirable in future to have an explicit 'read' timeout here.
	ssize_t bytes_read = read(watcher->io.fd, (void *)watcher->data_buffer, READ_BUFFER_SIZE);
	if (bytes_read == -1) {
		ASSERT(errno != EAGAIN && errno != EWOULDBLOCK);

		const char *name = is_read_from_backend ? "backend" : "client";
		if (is_read_from_backend || (!is_read_from_backend && (errno != ECONNRESET && errno != EPIPE))) {
			fprintf(stderr, "Failed to read data from %s with error code: %d.\n", name, errno);
		}

		if (!is_read_from_backend && watcher->is_first_time) {
			ev_io_proxy_watcher_free_set(loop, watcher);
		} else {
			ev_io_proxy_watcher_free_pair(loop, watcher);
		}
		watcher = NULL;
		return -1;
	} else if (bytes_read == 0) {
		if (!is_read_from_backend && watcher->is_first_time) {
			ev_io_proxy_watcher_free_set(loop, watcher);
		} else {
			ev_io_proxy_watcher_free_pair(loop, watcher);
		}
		watcher = NULL;
		return -1;
	}

	return bytes_read;
}

int ev_io_proxy_watcher_perform_write(struct ev_loop *loop, struct ev_io_proxy_watcher *watcher, int is_write_to_backend) {
	// Write from this watcher's data buffer into its socket
	ssize_t bytes_written = write(watcher->io.fd, (void *)watcher->data_buffer, READ_BUFFER_SIZE);
	if (bytes_written != READ_BUFFER_SIZE) {
		ASSERT(errno != EAGAIN && errno != EWOULDBLOCK);

		const char *name = is_write_to_backend ? "backend" : "client";
		if (errno == EPIPE || errno == ECONNRESET) {
			// NOTE: In future, if we're trying to write to the backend, it might be nice to serve a proper 503 error to the user.
			fprintf(stderr, "Failed to write data to %s due to EPIPE or ECONNRESET (broken connection).\n", name);
		} else {
			if (errno != EPROTOTYPE) { // Why EPROTOTYPE? OS X: http://erickt.github.io/blog/2014/11/19/adventures-in-debugging-a-potential-osx-kernel-bug/
				fprintf(stderr, "Failed to write data to %s with error code: %d.\n", name, errno);
			}
		}

		if (is_write_to_backend && watcher->is_first_time) {
			ev_io_proxy_watcher_free_set(loop, watcher);
		} else {
			ev_io_proxy_watcher_free_pair(loop, watcher);
		}
		watcher = NULL;
		return -1;
	}

	return 0;
}

int ev_io_proxy_watcher_perform_immediate_write_after_read(struct ev_loop *loop, struct ev_io_proxy_watcher *watcher, size_t bytes_read, int is_write_to_backend) {
	// Forward the watcher data chunk to the paired watcher's socket
	ssize_t bytes_written = write(watcher->paired_watcher->io.fd, watcher->data_buffer, bytes_read);
	if (bytes_read != bytes_written) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			// Stop the EV_READ from client watcher, and start the EV_WRITE to backend watcher.
			ev_io_stop(loop, (struct ev_io *)watcher);
			ev_io_start(loop, &watcher->paired_watcher->io);
		} else {
			if (errno != ECONNRESET && errno != EPIPE) {
				fprintf(stderr, "Failed to write data to backend with error code: %d.\n", errno);
			} else if (is_write_to_backend) {
				if (errno != EPROTOTYPE) { // Why EPROTOTYPE? OS X: http://erickt.github.io/blog/2014/11/19/adventures-in-debugging-a-potential-osx-kernel-bug/
					// NOTE: In future, if we're trying to write to the backend, it might be nice to serve a proper 503 error to the user.
					fprintf(stderr, "Failed to write data to backend due to EPIPE or ECONNRESET (broken connection).\n");
				}
			}
			ev_io_proxy_watcher_free_pair(loop, watcher);
			watcher = NULL;
			return -1;
		}
	}

	return 0;
}

int ev_io_proxy_watcher_perform_immediate_read_after_write(struct ev_loop *loop, struct ev_io_proxy_watcher *watcher, int is_read_from_backend) {
	// Read from the paired watcher's socket into this client's data chunk
	ssize_t bytes_read = read(watcher->paired_watcher->io.fd, watcher->data_buffer, READ_BUFFER_SIZE);
	if (bytes_read == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			// Stop the EV_WRITE watcher, and start the paired EV_READ watcher
			ev_io_stop(loop, (struct ev_io *)watcher);
			ev_io_start(loop, &watcher->paired_watcher->io);
		} else {
			fprintf(stderr, "Failed to read data from client with error code: %d.\n", errno);
			ev_io_proxy_watcher_free_pair(loop, watcher);
			watcher = NULL;
			return -1;
		}
	} else if (bytes_read == 0) {
		ev_io_proxy_watcher_free_pair(loop, watcher);
		watcher = NULL;
		return -1;
	}

	return 0;
}
