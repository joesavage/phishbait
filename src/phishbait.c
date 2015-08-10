/*
 * Phishbait - a reverse proxy for dealing with uninvited hotlinking.
 * Copyright 2015, Joe Savage
 * 
 * NOTE: This codebase assumes that we're compiling with an ASCII character set.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <ev.h>

#include "utilities.h"
#include "http_parsing.h"
#include "socket.h"
#include "ev_io_proxy_watcher.h"
#include "ev_io_connection_watcher.h"
#include "ev_io_backend_connect_watcher.h"

const char *bind_port;
const char *backend_addr;
const char *backend_port;

static int create_bind_socket(void);
static void accept_client_handler(struct ev_loop *loop, struct ev_io *w, int revents);
static void backend_connect_handler(struct ev_loop *loop, struct ev_io *w, int revents);
static void register_client_watchers(struct ev_loop *loop, int client_socket, int backend_socket);
static void read_from_client_handler(struct ev_loop *loop, struct ev_io *w, int revents);
static void write_to_backend_handler(struct ev_loop *loop, struct ev_io *w, int revents);
static void read_from_backend_handler(struct ev_loop *loop, struct ev_io *w, int revents);
static void write_to_client_handler(struct ev_loop *loop, struct ev_io *w, int revents);

// TODO: In my testing we can't quite make it to c10k quite yet, but I'm not entirely sure
// why this is. Might be to do with environment, rather than software, configuration.
// TODO: Occasionally clients seem to disconnect with "connection reset by peer" under
// high load, but I'm unsure why this happens (could be an environment configuration issue?)
// TODO: Now we've split things into multiple files, the compiler probably isn't giving us some inlining
// performance benefits which is a shame. Maybe switch to a single-file unity compilation build?
int main(int argc, char *argv[]) {
	bind_port = "31500";
	backend_addr = "localhost";
	backend_port = "http";

	int bind_socket;
	if ((bind_socket = create_bind_socket()) == -1) { exit(1); }
	
	// Setup a libev watcher for new incoming client connections.
	// TODO: In future, it'd be good if this was multi-threaded.
	signal(SIGPIPE, SIG_IGN); // Ignore the SIGPIPE signal
	struct ev_loop *loop = EV_DEFAULT;
	struct ev_io_connection_watcher client_connection_watcher;	
	client_connection_watcher.backend_addrinfo = get_host_addrinfos(backend_addr, backend_port, 0); // NOTE: I'm assuming that these won't change throughout the life of our program.
	ev_io_init(&client_connection_watcher.io, accept_client_handler, bind_socket, EV_READ);
	ev_io_start(loop, &client_connection_watcher.io);
	printf("Listening on port %s...\n", bind_port);
	ev_run(loop, 0); // Run the libev event loop

	freeaddrinfo(client_connection_watcher.backend_addrinfo);
	return 0;
}

int create_bind_socket(void) {
	// Get the 'addrinfo' structs we might want to host on
	struct addrinfo *bind_addrs = get_host_addrinfos(NULL, bind_port, AI_PASSIVE);

	// Bind to the address to host on
	int bind_socket;
	struct addrinfo *bind_addr;
	for (bind_addr = bind_addrs; bind_addr != NULL; bind_addr = bind_addr->ai_next) {
		// Find an address for the backend that we can create a socket to
		if ((bind_socket = socket(bind_addr->ai_family, bind_addr->ai_socktype, bind_addr->ai_protocol)) == -1) {
			continue;
		}

		int so_reuseaddr = 1;
		if (setsockopt(bind_socket, SOL_SOCKET, SO_REUSEADDR, &so_reuseaddr, sizeof(so_reuseaddr)) == -1) {
			fprintf(stderr, "'setsockopt' failed\n");
			return -1;
		}

		// Try to bind on the newly constructed socket
		if (!bind(bind_socket, bind_addr->ai_addr, bind_addr->ai_addrlen)) {
			break; // Success!
		}
		close(bind_socket);
	}

	// Check if we managed to bind successfully to the host
	if (bind_addr == NULL) {
		fprintf(stderr, "Failed to bind to host\n");
		return -1;
	}

	// We're done with 'addrinfo' structs
	freeaddrinfo(bind_addrs);
	bind_addrs = NULL;
	bind_addr = NULL;

	// Mark the socket we've bound on to listen for incoming connections ('backlog' should probably be configurable)
	if (listen(bind_socket, 10) == -1) {
		fprintf(stderr, "Failed to listen on host\n");
		return -1;
	}
	set_socket_nonblock(bind_socket);

	return bind_socket;
}

void accept_client_handler(struct ev_loop *loop, struct ev_io *w, int revents) {
	struct ev_io_connection_watcher *watcher = (struct ev_io_connection_watcher *)w;

	int client_socket = accept(watcher->io.fd, NULL, NULL);
	if (client_socket == -1) {
		ASSERT(errno != EAGAIN && errno != EWOULDBLOCK);
		if (errno == ENOBUFS || errno == ENOMEM) {
			fprintf(stderr, "Failed to accept client connection due to insufficient memory (may be socket buffer limits).\n");
		} else {
			fprintf(stderr, "Failed to accept client connection.\n");
		}
		// NOTE: We don't have any memory to free or sockets to close in this particular case.
		return;
	}


	// Create a backend socket, attempt to connect to it, and watch for when it becomes writable.
	// TODO: In future, it would be good if backend connection errors were handled more gracefully
	int backend_socket = obtain_next_valid_socket(&watcher->backend_addrinfo);
	if (backend_socket == -1) {
		fprintf(stderr, "Failed to obtain valid backend socket.\n");
		exit(1);
	}
	set_socket_nonblock(backend_socket);
	struct ev_io_backend_connect_watcher *backend_connect_watcher = (struct ev_io_backend_connect_watcher *)memory_alloc(sizeof(struct ev_io_backend_connect_watcher));
	backend_connect_watcher->client_socket = client_socket;
	backend_connect_watcher->backend_addrinfo = watcher->backend_addrinfo;
	if (connect(backend_socket, watcher->backend_addrinfo->ai_addr, watcher->backend_addrinfo->ai_addrlen) == -1 && errno != EINPROGRESS) {
		memory_free(backend_connect_watcher);
		close(client_socket);
		close(backend_socket);
		return;
	}
	ev_io_init(&backend_connect_watcher->io, backend_connect_handler, backend_socket, EV_WRITE);
	ev_io_start(loop, &backend_connect_watcher->io);
}

void backend_connect_handler(struct ev_loop *loop, struct ev_io *w, int revents) {
	struct ev_io_backend_connect_watcher *watcher = (struct ev_io_backend_connect_watcher *)w;
	int backend_socket = watcher->io.fd;

	int backend_connect_error;
	socklen_t result_length = sizeof(backend_connect_error);
	getsockopt(backend_socket, SOL_SOCKET, SO_ERROR, &backend_connect_error, &result_length);
	if (!backend_connect_error && !(revents & EV_ERROR)) {
		ev_io_stop(loop, &watcher->io);
		memory_free(watcher);

		register_client_watchers(loop, watcher->client_socket, backend_socket);
		return;
	}

	// If we failed to create a connection to the socket we tried last...
	// TODO: In future, it would be good if backend connection errors were handled more gracefully
	backend_socket = obtain_next_valid_socket(&watcher->backend_addrinfo);
	if (backend_socket == -1) {
		fprintf(stderr, "Failed to obtain valid backend socket.\n");
		exit(1);
	}

	if (connect(backend_socket, watcher->backend_addrinfo->ai_addr, watcher->backend_addrinfo->ai_addrlen) == -1 && errno != EINPROGRESS) {
		ev_io_stop(loop, &watcher->io);
		memory_free(watcher);
		close(watcher->client_socket);
		close(backend_socket);
		return;
	}

	ev_io_stop(loop, &watcher->io);
	ev_io_set(&watcher->io, backend_socket, EV_WRITE);
	ev_io_start(loop, &watcher->io);
}

void register_client_watchers(struct ev_loop *loop, int client_socket, int backend_socket) {
	// Create four I/O watchers for this client.
	// One pair for reading communication from the client and writing it to the backend, another
	// pair for reading communication from the backend and writing it to the client. These should
	// function such that no two watchers in a pair should be active at the same time.
	struct ev_io_proxy_watcher *read_from_client_proxy_watcher = (struct ev_io_proxy_watcher *)memory_alloc(sizeof(struct ev_io_proxy_watcher));
	struct ev_io_proxy_watcher *write_to_backend_proxy_watcher = (struct ev_io_proxy_watcher *)memory_alloc(sizeof(struct ev_io_proxy_watcher));
	struct ev_io_proxy_watcher *read_from_backend_proxy_watcher = (struct ev_io_proxy_watcher *)memory_alloc(sizeof(struct ev_io_proxy_watcher));
	struct ev_io_proxy_watcher *write_to_client_proxy_watcher   = (struct ev_io_proxy_watcher *)memory_alloc(sizeof(struct ev_io_proxy_watcher));

	char *client_data_buffer = (char *)memory_alloc(READ_BUFFER_SIZE + 1);
	char *backend_data_buffer = (char *)memory_alloc(READ_BUFFER_SIZE + 1);
	char *shared_buffer = (char *)memory_alloc(1);

	struct ev_io *read_from_client_watcher = init_ev_io_proxy_watcher(read_from_client_proxy_watcher, write_to_backend_proxy_watcher, read_from_backend_proxy_watcher, client_data_buffer, shared_buffer);
	struct ev_io *write_to_backend_watcher = init_ev_io_proxy_watcher(write_to_backend_proxy_watcher, read_from_client_proxy_watcher, write_to_client_proxy_watcher, client_data_buffer, shared_buffer);
	struct ev_io *read_from_backend_watcher = init_ev_io_proxy_watcher(read_from_backend_proxy_watcher, write_to_client_proxy_watcher, read_from_client_proxy_watcher, backend_data_buffer, shared_buffer);
	struct ev_io *write_to_client_watcher = init_ev_io_proxy_watcher(write_to_client_proxy_watcher, read_from_backend_proxy_watcher, write_to_backend_proxy_watcher, backend_data_buffer, shared_buffer);

	// TODO: In future, it might be a good idea to have some kind of timeout destruction of these.
	ev_io_init(read_from_client_watcher, read_from_client_handler, client_socket, EV_READ);
	ev_io_init(write_to_backend_watcher, write_to_backend_handler, backend_socket, EV_WRITE);
	ev_io_init(read_from_backend_watcher, read_from_backend_handler, backend_socket, EV_READ);
	ev_io_init(write_to_client_watcher, write_to_client_handler, client_socket, EV_WRITE);

	// Start the EV_READ watchers for the client and backend
	ev_io_start(loop, read_from_client_watcher);
	ev_io_start(loop, read_from_backend_watcher);
}

void read_from_client_handler(struct ev_loop *loop, struct ev_io *w, int revents) {
	struct ev_io_proxy_watcher *watcher = (struct ev_io_proxy_watcher *)w;
	ASSERT(!(revents & EV_ERROR));

	// Read from the client into this client's data chunk
	ssize_t bytes_read;
	if ((bytes_read = ev_io_proxy_watcher_perform_read(loop, watcher, 0)) == -1) { return; }
	if (watcher->is_first_time) {
		watcher->is_first_time = 0;

		// TODO: Parse HTTP headers (if any)

		// Form an alternate request string for a 'GET' to a resource of a different name (if phishing), and then
		// close off the connection with the client (i.e. free this pair). If we use the same extension, the
		// administrator can just add files with whatever he thinks will be hotlinked and everything will work great.
		// That way, phishing requests also go through whatever other pipeline might be behind this reverse proxy
		// which is very good (i.e. if we're in front of Varnish, then it can cache phishing requests too.).
	}

	// Forward the client's request to the back-end
	if (ev_io_proxy_watcher_perform_immediate_write_after_read(loop, watcher, bytes_read, 1) == -1) { return; }
	if (watcher->paired_watcher->is_first_time) {
			watcher->paired_watcher->is_first_time = 0;
	}

#if 0
	// Parse the client's request and forward it to the back-end
	int parsed_header_successfully = 0, is_phishing_refferal = 0;
	const char *request_uri = NULL, *referer = NULL;
	size_t request_uri_length = 0, referer_length = 0;
	{
		// Null-terminated HTTP request string (with null buffer, just in case)
		// TODO: How large do we want MAXIMUM_REQUEST_HEADER_SIZE to be?
		char request_buffer_head[MAXIMUM_REQUEST_HEADER_SIZE + REQUEST_HEADER_NULL_BUFFER_SIZE];
		memset(request_buffer_head + MAXIMUM_REQUEST_HEADER_SIZE, 0, REQUEST_HEADER_NULL_BUFFER_SIZE);

		// TODO: It might be desirable in future to have an explicit 'read' timeout here.
		ssize_t bytes_read = read(watcher.io.fd, request_buffer_head, sizeof(request_buffer_head) - REQUEST_HEADER_NULL_BUFFER_SIZE);

		if (bytes_read == -1) {
			fprintf(stderr, "Failed to read client header data.\n");
			ASSERT(0);
			return;
		} else if (bytes_read != 0) {
			// Parse request HTTP 'Referer' header.
			// Given the tool's purpose, we just pass on any malformed / odd HTTP requests (plus, this is good for performance)
			if (parse_http_request_header(request_buffer_head, &request_uri, &request_uri_length, &referer, &referer_length)) {
				if (referer && referer_length > 0) {
					// printf("REFERER URI: %.*s\n", (int)referer_length, referer);

					is_phishing_refferal = is_referer_blacklisted(referer, referer_length);
				}

				if (request_uri) {
					// printf("REQ URI: %.*s\n\n", (int)request_uri_length, request_uri);
				}
			}

			// Forward the client's request to the back-end
			ssize_t bytes_written = write(backend_socket, request_buffer_head, bytes_read);
			ASSERT(bytes_written == bytes_read);
			// TODO: Send the rest of the request to the backend! (Currently we only send the first 'read')
			// char request_buffer_tail[READ_BUFER_SIZE];
		}
	}

	// TODO: We need to store this data (request_uri/ext, is_phishing, etc.) with the request through the watcher so we can respond appropriately

	// TODO: Set up the backend response watcher?
	#endif
}

void write_to_backend_handler(struct ev_loop *loop, struct ev_io *w, int revents) {
	struct ev_io_proxy_watcher *watcher = (struct ev_io_proxy_watcher *)w;
	ASSERT(!(revents & EV_ERROR));

	// Write from this client's data chunk to the backend
	if (ev_io_proxy_watcher_perform_write(loop, watcher, 1) == -1) {
		return;
	}

	if (watcher->is_first_time) {
		watcher->is_first_time = 0;
	}

	// Read from the client into this client's data chunk
	if (ev_io_proxy_watcher_perform_immediate_read_after_write(loop, watcher, 0) == -1) { return; }
	if (watcher->paired_watcher->is_first_time) {
			watcher->paired_watcher->is_first_time = 0;
	}
}

void read_from_backend_handler(struct ev_loop *loop, struct ev_io *w, int revents) {
	struct ev_io_proxy_watcher *watcher = (struct ev_io_proxy_watcher *)w;
	ASSERT(!(revents & EV_ERROR));

	// Read from the backend into this client's backend data chunk
	ssize_t bytes_read;
	if ((bytes_read = ev_io_proxy_watcher_perform_read(loop, watcher, 1)) == -1) { return; }
	if (watcher->is_first_time) { watcher->is_first_time = 0; }

	// Forward the backend's response to the client
	if (ev_io_proxy_watcher_perform_immediate_write_after_read(loop, watcher, bytes_read, 0) == -1) { return; }
	if (watcher->paired_watcher->is_first_time) {
			watcher->paired_watcher->is_first_time = 0;
	}
}

void write_to_client_handler(struct ev_loop *loop, struct ev_io *w, int revents) {
	struct ev_io_proxy_watcher *watcher = (struct ev_io_proxy_watcher *)w;
	ASSERT(!(revents & EV_ERROR));

	// Write from this client's backend data chunk to the client
	if (ev_io_proxy_watcher_perform_write(loop, watcher, 0) == -1) { return; }
	if (watcher->is_first_time) { watcher->is_first_time = 0; }

	// Read from the backend into this client's backend data chunk
	if (ev_io_proxy_watcher_perform_immediate_read_after_write(loop, watcher, 1) == -1) { return; }
	if (watcher->paired_watcher->is_first_time) {
			watcher->paired_watcher->is_first_time = 0;
	}
}
