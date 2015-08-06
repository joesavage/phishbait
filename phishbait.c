#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define DEBUG 1

#if DEBUG
#include <assert.h>
#define ASSERT(cond) assert(cond)
#else
#define ASSERT(cond)
#endif

void process_request(int client_socket, const char *backend_addr, const char *backend_port) {
	// Get the back-end 'addrinfo's
	struct addrinfo *backend_addrinfos;
	{
		// We're looking for IPv4/IPv6 streaming sockets
		struct addrinfo hints = {};
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;

		int error_code;
		if ((error_code = getaddrinfo(backend_addr, backend_port, &hints, &backend_addrinfos))) {
			fprintf(stderr, "'getaddrinfo(3)' failed for backend '%s', with error code: %d\n", backend_addr, error_code);
			exit(1);
		}
	}

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


	// Forward the client's request to the back-end
	// TODO: There may be weird HTTP stuff (partial responses and timeouts and things) that we need to deal with here.
	// TODO: Figure out how much data we want to read from the requester for HTTP headers.
	{
		char client_buffer[2048];
		ssize_t bytes_read = read(client_socket, client_buffer, sizeof(client_buffer)); // TODO: Timeout?
		if (bytes_read == -1) {
			// TODO: log
		} else if (bytes_read != 0) {
			ssize_t bytes_written = write(backend_socket, client_buffer, bytes_read);
			ASSERT(bytes_written == bytes_read);
		}
	}

	// TODO: Parse client HTTP request headers (carefully!)

	// Forward the back-end's response to the client
	{
		char server_buffer[2048];
		ssize_t bytes_read;
		while ((bytes_read = read(backend_socket, server_buffer, sizeof(server_buffer)))) {
			ssize_t bytes_written = write(client_socket, server_buffer, bytes_read);
			ASSERT(bytes_written == bytes_read);
		}
	}

	close(backend_socket);
}

int main(int argc, char *argv[]) {
	const char *bind_port = "31500";
	const char *backend_addr = "localhost";
	const char *backend_port = "http";

	// Get the 'addrinfo' to host on
	struct addrinfo *bind_addrs;
	{
		struct addrinfo hints = {};
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = AI_PASSIVE;

		int error_code;
		if ((error_code = getaddrinfo(NULL, bind_port, &hints, &bind_addrs))) {
			fprintf(stderr, "'getaddrinfo(3)' failed with error code: %d\n", error_code);
			exit(1);
		}
	}

	// Bind to the address to host on
	int bind_socket;
	struct addrinfo *bind_addr;
	for (bind_addr = bind_addrs; bind_addr != NULL; bind_addr = bind_addr->ai_next) {
		// Find an address for the backend that we can create a socket to
		if ((bind_socket = socket(bind_addr->ai_family, bind_addr->ai_socktype, bind_addr->ai_protocol)) == -1) {
			continue;
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
		exit(1);
	}

	// We're done with 'addrinfo' structs
	freeaddrinfo(bind_addrs);
	bind_addrs = NULL;
	bind_addr = NULL;

	// Mark the socket we've bound on to listen for incoming connections
	// TODO: Explore changing the 'backlog' value from 1
	if (listen(bind_socket, 1) == -1) {
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
		// TODO: We may want to take 'sockaddr' info in future
		int client_socket = accept(bind_socket, NULL, NULL);
		if (client_socket == -1) {
			fprintf(stderr, "Failed to accept connection from client\n");
			exit(1); // TODO: We probably shouldn't 'exit' on this case (log or whatever)
		}

		// TODO: We probably don't want to do the back-end address lookup for /every/ client
		// when it should be the same for all clients (hence: just do it once).
		process_request(client_socket, backend_addr, backend_port);
		printf("Processed request for client\n");

		close(client_socket);
	}

	close(bind_socket);
	return 0;
}