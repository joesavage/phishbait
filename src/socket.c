#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include "socket.h"

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

void set_socket_nonblock(int socket) {
	if (fcntl(socket, F_SETFL, O_NONBLOCK)) {
		fprintf(stderr, "Failed to change socket to non-blocking (O_NONBLOCK)\n");
		exit(1);
	}
}

int obtain_next_valid_socket(struct addrinfo **addrinfos) {
	int current_socket = -1;
	struct addrinfo *current_addrinfo;
	for (current_addrinfo = *addrinfos; current_addrinfo != NULL; current_addrinfo = current_addrinfo->ai_next) {
		if ((current_socket = socket(current_addrinfo->ai_family, current_addrinfo->ai_socktype, current_addrinfo->ai_protocol))) {
			break;
		}
		close(current_socket);
	}

	*addrinfos = current_addrinfo;
	return current_addrinfo == NULL ? -1 : current_socket;
}
