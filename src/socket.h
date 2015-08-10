#ifndef SOCKET_H
#define SOCKET_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

struct addrinfo *get_host_addrinfos(const char *host_addr, const char *host_port, int ai_flags);
void set_socket_nonblock(int socket);
int obtain_next_valid_socket(struct addrinfo **addrinfos);

#endif
