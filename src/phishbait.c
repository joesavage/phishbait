/*
 * Phishbait - a reverse proxy for dealing with uninvited hotlinking.
 * NOTE: This codebase assumes that we're compiling with an ASCII character set.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <ev.h>

#include "utilities.h"
#include "http_parsing.h"
#include "socket.h"
#include "ev_io_proxy_watcher.h"
#include "ev_io_client_connect_watcher.h"
#include "ev_io_backend_connect_watcher.h"

static void usage(const char *program_name);
static int create_listen_socket(const char *listen_port, int listen_queue_backlog);
static void client_connect_handler(struct ev_loop *loop, struct ev_io *w, int revents);
static void backend_connect_handler(struct ev_loop *loop, struct ev_io *w, int revents);
static void register_client_watchers(struct ev_loop *loop, int client_socket, int backend_socket);
static void read_from_client_handler(struct ev_loop *loop, struct ev_io *w, int revents);
static void write_to_backend_handler(struct ev_loop *loop, struct ev_io *w, int revents);
static void read_from_backend_handler(struct ev_loop *loop, struct ev_io *w, int revents);
static void write_to_client_handler(struct ev_loop *loop, struct ev_io *w, int revents);

// NOTE: In my testing we can't quite make it to c10k quite yet, but I'm not entirely sure
// why this is. Might be to do with environment, rather than software, configuration.
// NOTE: Now we've split things into multiple files, the compiler probably isn't giving us some inlining
// performance benefits which is a shame. Could inline some functions in headers.
// NOTE: Under medium load, clients may get "connection reset by peer" from the server.
// This seems to be because of the 'backlog' value, which can be adjusted appropriately.
int main(int argc, char *argv[]) {
	const char *program_name = argv[0];
	const char *listen_port = "3080", *backend_addr = "localhost", *backend_port = "http";
	int listen_queue_backlog = 128; // NOTE: What this value 'should' be seems to be controversial.

	// Parse CLI args
	{
		if (argc < 3) { usage(program_name); }
		backend_addr = argv[1];
		backend_port = argv[2];
		argc -= 2;
		argv += 2;

		extern char *optarg;
		extern int optind;
		int ch;
		while ((ch = getopt(argc, argv, "h?p:q:")) != EOF) {
			switch(ch) {
				case 'p':
					listen_port = optarg;
					break;
				case 'q':
					listen_queue_backlog = atoi(optarg);
					if (listen_queue_backlog <= 0) {
						fprintf(stderr, "phishbait: illegal queue backlog value.\n");
						exit(2);
					}
					break;
				case '?':
				case 'h':
				default:
					usage(program_name);
			}
		}
		argc -= optind;
		argv += optind;
	}

	int listen_socket;
	if ((listen_socket = create_listen_socket(listen_port, listen_queue_backlog)) == -1) { exit(1); }
	
	// Setup a libev watcher for new incoming client connections.
	// NOTE: In future, it'd be good if this was multi-threaded.
	signal(SIGPIPE, SIG_IGN); // Ignore the SIGPIPE signal
	struct ev_loop *loop = EV_DEFAULT;
	struct ev_io_client_connect_watcher client_connect_watcher;	
	client_connect_watcher.backend_addrinfo = get_host_addrinfos(backend_addr, backend_port, 0); // NOTE: I'm assuming that these won't change throughout the life of our program.
	ev_io_init(&client_connect_watcher.io, client_connect_handler, listen_socket, EV_READ);
	ev_io_start(loop, &client_connect_watcher.io);
	printf("Forwarding connections from 0.0.0.0:%s to %s:%s...\n", listen_port, backend_addr, backend_port);
	ev_run(loop, 0); // Run the libev event loop

	freeaddrinfo(client_connect_watcher.backend_addrinfo);
	return 0;
}

void usage(const char *program_name) {
	fprintf(stderr, "usage: %s backend_host backend_port [-p listen_port] [-q queue_backlog]\n", program_name);
	exit(1);
}

int create_listen_socket(const char *listen_port, int listen_queue_backlog) {
	// Get the 'addrinfo' structs we might want to host on
	struct addrinfo *listen_addrs = get_host_addrinfos(NULL, listen_port, AI_PASSIVE);

	// Bind to the address to host on
	int listen_socket;
	struct addrinfo *listen_addr;
	for (listen_addr = listen_addrs; listen_addr != NULL; listen_addr = listen_addr->ai_next) {
		// Find an addrinfo for the backend that we can create a socket with
		if ((listen_socket = socket(listen_addr->ai_family, listen_addr->ai_socktype, listen_addr->ai_protocol)) == -1) {
			continue;
		}

		int so_reuseaddr = 1;
		if (setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, &so_reuseaddr, sizeof(so_reuseaddr)) == -1) {
			fprintf(stderr, "'setsockopt' failed.\n");
			return -1;
		}

		// Try to bind on the newly constructed socket
		if (!bind(listen_socket, listen_addr->ai_addr, listen_addr->ai_addrlen)) {
			break; // Success!
		}
		close(listen_socket);
	}

	// Check if we managed to bind successfully to the host
	if (listen_addr == NULL) {
		fprintf(stderr, "Failed to bind to host.\n");
		return -1;
	}

	// We're done with the 'addrinfo' structs
	freeaddrinfo(listen_addrs);
	listen_addrs = NULL;
	listen_addr = NULL;

	// Mark the socket we've bound on to listen for incoming connections
	if (listen(listen_socket, listen_queue_backlog) == -1) {
		fprintf(stderr, "Failed to listen on host.\n");
		return -1;
	}
	set_socket_nonblock(listen_socket);

	return listen_socket;
}

void client_connect_handler(struct ev_loop *loop, struct ev_io *w, int revents) {
	struct ev_io_client_connect_watcher *watcher = (struct ev_io_client_connect_watcher *)w;

	int client_socket = accept(watcher->io.fd, NULL, NULL);
	if (client_socket == -1) {
		ASSERT(errno != EAGAIN && errno != EWOULDBLOCK);
		if (errno == ENOBUFS || errno == ENOMEM) {
			fprintf(stderr, "Failed to accept client connection due to insufficient memory (may be socket buffer limits).\n");
		} else {
			fprintf(stderr, "Failed to accept client connection with error code: %d.\n", errno);
		}
		// NOTE: We don't have any memory to free or sockets to close in this particular case.
		return;
	}


	// Create a backend socket, attempt to connect to it, and watch for when it becomes writable.
	// NOTE: In future, it would be good if backend connection errors resulted in user notification of these issues
	struct addrinfo *backend_addrinfo = watcher->backend_addrinfo;
	int backend_socket = obtain_next_valid_socket(&backend_addrinfo);
	if (backend_socket == -1) {
		close(client_socket);
		return;
	}
	set_socket_nonblock(backend_socket);
	struct ev_io_backend_connect_watcher *backend_connect_watcher = (struct ev_io_backend_connect_watcher *)memory_alloc(sizeof(struct ev_io_backend_connect_watcher));
	backend_connect_watcher->client_socket = client_socket;
	backend_connect_watcher->backend_addrinfo = backend_addrinfo;
	if (connect(backend_socket, backend_addrinfo->ai_addr, backend_addrinfo->ai_addrlen) == -1 && errno != EINPROGRESS) {
		memory_free(backend_connect_watcher);
		close(client_socket);
		close(backend_socket);
		return;
	}

	// Create a libev watcher for the backend socket becoming writable (i.e. 'connect' finished)
	ev_io_init(&backend_connect_watcher->io, backend_connect_handler, backend_socket, EV_WRITE);
	ev_io_start(loop, &backend_connect_watcher->io);
}

void backend_connect_handler(struct ev_loop *loop, struct ev_io *w, int revents) {
	struct ev_io_backend_connect_watcher *watcher = (struct ev_io_backend_connect_watcher *)w;
	int backend_socket = watcher->io.fd;
	int client_socket = watcher->client_socket;

	int backend_connect_error;
	socklen_t result_length = sizeof(backend_connect_error);
	getsockopt(backend_socket, SOL_SOCKET, SO_ERROR, &backend_connect_error, &result_length);
	if (!backend_connect_error && !(revents & EV_ERROR)) {
		ev_io_stop(loop, &watcher->io);
		memory_free(watcher);

		register_client_watchers(loop, client_socket, backend_socket);
		return;
	}

	// If we failed to create a connection to the socket we tried last...
	// NOTE: In future, it would be good if backend connection errors resulted in user notification of these issues
	backend_socket = obtain_next_valid_socket(&watcher->backend_addrinfo);
	if (backend_socket == -1) {
		ev_io_stop(loop, &watcher->io);
		memory_free(watcher);
		close(client_socket);
		return;
	}

	if (connect(backend_socket, watcher->backend_addrinfo->ai_addr, watcher->backend_addrinfo->ai_addrlen) == -1 && errno != EINPROGRESS) {
		ev_io_stop(loop, &watcher->io);
		memory_free(watcher);
		close(client_socket);
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
	char *pairs_finished = (char *)memory_alloc(1);
	char *client_custom_pair_data = (char *)memory_alloc(1);

	struct ev_io *read_from_client_watcher = init_ev_io_proxy_watcher(read_from_client_proxy_watcher, write_to_backend_proxy_watcher, read_from_backend_proxy_watcher, client_data_buffer, pairs_finished, client_custom_pair_data);
	struct ev_io *write_to_backend_watcher = init_ev_io_proxy_watcher(write_to_backend_proxy_watcher, read_from_client_proxy_watcher, write_to_client_proxy_watcher, client_data_buffer, pairs_finished, client_custom_pair_data);
	struct ev_io *read_from_backend_watcher = init_ev_io_proxy_watcher(read_from_backend_proxy_watcher, write_to_client_proxy_watcher, read_from_client_proxy_watcher, backend_data_buffer, pairs_finished, NULL);
	struct ev_io *write_to_client_watcher = init_ev_io_proxy_watcher(write_to_client_proxy_watcher, read_from_backend_proxy_watcher, write_to_backend_proxy_watcher, backend_data_buffer, pairs_finished, NULL);

	// NOTE: In future, it might be a good idea to have some kind of timeout destruction of these.
	ev_io_init(read_from_client_watcher, read_from_client_handler, client_socket, EV_READ);
	ev_io_init(write_to_backend_watcher, write_to_backend_handler, backend_socket, EV_WRITE);
	ev_io_init(read_from_backend_watcher, read_from_backend_handler, backend_socket, EV_READ);
	ev_io_init(write_to_client_watcher, write_to_client_handler, client_socket, EV_WRITE);

	// Start the EV_READ watchers for the client and backend
	ev_io_start(loop, read_from_client_watcher);
	ev_io_start(loop, read_from_backend_watcher);
}

static int is_referer_blacklisted(const char *referer, size_t referer_length) {
	// NOTE: This code can get hit once per client request (that's pretty frequently).
	// If you're modifying this routine, try to make sure the code is fast.
	// NOTE: Depending on the performance characteristics of this code, you may wish to
	// utilize some form of caching here (using some subset of the 'referer' string as a key).
	// In such a scenario both blacklist and whitelist caching would likely be beneficial.
	return referer_length % 2;
}

void read_from_client_handler(struct ev_loop *loop, struct ev_io *w, int revents) {
	struct ev_io_proxy_watcher *watcher = (struct ev_io_proxy_watcher *)w;
	ASSERT(!(revents & EV_ERROR));

	// Read from the client into this client's data chunk
	ssize_t bytes_read;
	if ((bytes_read = ev_io_proxy_watcher_perform_read(loop, watcher, 0)) == -1) { return; }
	if (watcher->is_first_time) {
		watcher->is_first_time = 0;

		// Parse request HTTP headers for a 'referer' and the request URI.
		// Given the tool's purpose, we just pass any malformed / odd HTTP requests (plus, this is good for performance).		
		const char *request_uri = NULL, *referer = NULL, *host = NULL, *request_ext = NULL;
		size_t request_uri_length = 0, referer_length = 0, host_length = 0, request_ext_length = 0;
		if (parse_http_request_header(watcher->data_buffer, &request_uri, &request_uri_length, &referer, &referer_length, &host, &host_length)) {
			if (referer && referer_length > 0 && request_uri && request_uri_length > 0 && host && host_length > 0) {

				char *new_request = memory_alloc(READ_BUFFER_SIZE + 1); // NOTE: Unsure whether a heap alloc & ptr switch is faster than a stack alloc & memcpy here.
				if (file_extension(request_uri, request_uri_length, &request_ext, &request_ext_length) == -1) {
					request_ext = "html";
					request_ext_length = 4;
				}

				// If this referer is blacklisted, send a different request through the pipeline than the client wrote.
				// This allows for serving alterate resource to blacklisted referers through a normal client->server
				// pipline (the request can still run through varnish, nginx, etc.).
				if (is_referer_blacklisted(referer, referer_length)) {
					// Form an alternate GET request for a resource of a different name if the request we just read is from a blacklisted source.
					if (snprintf(new_request, READ_BUFFER_SIZE + 1, "GET /phishing.%.*s HTTP/1.1\r\nHost: %.*s\r\n\r\n", (int)request_ext_length, request_ext, (int)host_length, host) < 0) {
						memory_free(new_request);
						ev_io_proxy_watcher_free_set(loop, watcher);
						return;
					}
					memory_free(watcher->data_buffer);
					watcher->data_buffer = new_request;
					bytes_read = strlen(new_request);
					watcher->custom_pair_data[0] = 1; // We're using this as a flag for 'is_blacklisted_referer'
				} else {
					memory_free(new_request);
				}
			}
		}
	}

	// Forward the client's request to the back-end
	if (ev_io_proxy_watcher_perform_immediate_write_after_read(loop, watcher, bytes_read, 1) == -1) { return; }
	if (watcher->paired_watcher->is_first_time) {
			watcher->paired_watcher->is_first_time = 0;
			if (watcher->custom_pair_data[0]) { ev_io_proxy_watcher_free_pair(loop, watcher); }
	}
}

void write_to_backend_handler(struct ev_loop *loop, struct ev_io *w, int revents) {
	struct ev_io_proxy_watcher *watcher = (struct ev_io_proxy_watcher *)w;
	ASSERT(!(revents & EV_ERROR));

	// Write from this client's data chunk to the backend
	if (ev_io_proxy_watcher_perform_write(loop, watcher, 1) == -1) {
		return;
	}

	if (watcher->is_first_time) {
		if (watcher->custom_pair_data[0]) { ev_io_proxy_watcher_free_pair(loop, watcher); }
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
