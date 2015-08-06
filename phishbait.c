#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define DEBUG 1

#if DEBUG
#include <string.h>
#include <assert.h>
#define ASSERT(cond) assert(cond)
#else
#define ASSERT(cond)
#endif

struct addrinfo *get_host_addrinfos(const char *host_addr, const char *host_port, int ai_flags) {
	struct addrinfo *result;

	// We're looking for IPv4/IPv6 streaming sockets
	struct addrinfo hints = {};
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = ai_flags;

	int error_code;
	if ((error_code = getaddrinfo(host_addr, host_port, &hints, &result))) {
		host_addr = host_addr ? host_addr : "NULL";
		host_port = host_port ? host_port : "NULL";
		fprintf(stderr, "'getaddrinfo' failed for host '%s' on port '%s', with error code: %d\n", host_addr, host_port, error_code);
		exit(1);
	}

	return result;
}

int create_backend_socket(const char *backend_addr, const char *backend_port) {
	// Get the back-end 'addrinfo' structs
	struct addrinfo *backend_addrinfos = get_host_addrinfos(backend_addr, backend_port, 0);

	// Establish a connection to the back-end server
	int backend_socket;
	struct addrinfo *backend_addrinfo;
	for (backend_addrinfo = backend_addrinfos; backend_addrinfo != NULL; backend_addrinfo = backend_addrinfo->ai_next) {
		// Try to create a socket to this particular back-end addrinfo
		if ((backend_socket = socket(backend_addrinfo->ai_family, backend_addrinfo->ai_socktype, backend_addrinfo->ai_protocol)) == -1) {
			continue;
		}

		// Try to connect to the newly constructed socket
		if (!connect(backend_socket, backend_addrinfo->ai_addr, backend_addrinfo->ai_addrlen)) {
			break; // Success!
		}
		close(backend_socket);
	}

	// Check if we managed to connect successfully to the back-end
	if (backend_addrinfo == NULL) {
		fprintf(stderr, "Failed to connect to backend '%s'\n", backend_addr);
		exit(1);
	}

	// We're done with 'addrinfo' structs
	freeaddrinfo(backend_addrinfos);
	backend_addrinfos = NULL;
	backend_addrinfo = NULL;

	return backend_socket;
}

void process_request(int client_socket, int backend_socket) {
	// Forward the client's request to the back-end
	// TODO: There may be weird HTTP stuff (partial responses and timeouts and things) that we need to deal with here.
	// TODO: Figure out how much data we want to read from the requester for HTTP headers.
	{
		char client_buffer[4096];
		ssize_t bytes_read = read(client_socket, client_buffer, sizeof(client_buffer)); // TODO: Timeout?
		if (bytes_read == -1) {
			// TODO: log
			assert(0);
		} else if (bytes_read != 0) {
			ssize_t bytes_written = write(backend_socket, client_buffer, bytes_read);
			ASSERT(bytes_written == bytes_read);
		}
	}

	// TODO: Parse client HTTP request headers (carefully!)

#if 1
	// Forward the back-end's response to the client
	{
		char backend_buffer[4096];
		ssize_t bytes_read;

		// For whatever reason, this loop is really slow the second time around in testing.
		// I'm guessing that it waits a while to check there's definitely no more data to pass or something?
		while ((bytes_read = read(backend_socket, backend_buffer, sizeof(backend_buffer)))) {
			ssize_t bytes_written = write(client_socket, backend_buffer, bytes_read);
			ASSERT(bytes_written == bytes_read);
		}
	}
#else
	char *data = "HTTP/1.1 200 OK\r\n\r\nHello, this is a test!";
	write(client_socket, data, strlen(data));
#endif
}

int main(int argc, char *argv[]) {
	const char *bind_port = "31500";
	const char *backend_addr = "localhost";
	const char *backend_port = "http";

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

#if DEBUG
		// In debug, allow 'bind' to reuse addresses/sockets (we don't close the socket on ^C right now, which is annoying for debugging)
		int so_reuseaddr = 1;
		if (setsockopt(bind_socket, SOL_SOCKET, SO_REUSEADDR, &so_reuseaddr, sizeof(so_reuseaddr)) == -1) {
			fprintf(stderr, "'setsockopt' failed\n");
			exit(1);
		}
#endif

		// Try to bind on the newly constructed socket
		if (!bind(bind_socket, bind_addr->ai_addr, bind_addr->ai_addrlen)) {
			break; // Success!
		}
		close(bind_socket);
	}

	// Check if we managed to bind successfully to the host
	if (bind_addr == NULL) {
		fprintf(stderr, "Failed to bind to host\n");
		exit(1);
	}

	// We're done with 'addrinfo' structs
	freeaddrinfo(bind_addrs);
	bind_addrs = NULL;
	bind_addr = NULL;

	// Mark the socket we've bound on to listen for incoming connections
	// The 'backlog' value here should be configurable, but I'll leave this functionality
	// until 'epoll' is implemented (as it might change some things up).
	if (listen(bind_socket, 50) == -1) {
		fprintf(stderr, "Failed to listen on host\n");
		exit(1);
	}

	// Accept and deal with clients
	// TODO: Use 'epoll' event notification for more efficient (less blocking) single-thread usage
	// TODO: Along with regular optimisation work, look carefully at the syscalls. I haven't done any
	// benchmarking yet, but I suspect the context switches here aren't going to be helpful for performance.
	// TODO: Consider multi-threading options
	printf("Listening on port %s...\n", bind_port);
	while (1) {
		int client_socket = accept(bind_socket, NULL, NULL); // We may want to take this 'sockaddr' info in future
		if (client_socket == -1) {
			fprintf(stderr, "Failed to accept connection from client\n");
			continue; // We could probably deal with more specifics errors better here
		}

		// It would be nice if we could reuse this across multiple clients, but when I try
		// that things break. So we just recreate the socket for every client for now.
		int backend_socket = create_backend_socket(backend_addr, backend_port);

		process_request(client_socket, backend_socket);
		printf("Processed request for client\n");

		close(backend_socket);
		close(client_socket);
	}

	close(bind_socket);
	return 0;
}