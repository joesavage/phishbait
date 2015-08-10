/*
 * Phishbait - a reverse proxy for dealing with uninvited hotlinking.
 * Copyright 2015, Joe Savage
 * 
 * NOTE: This codebase assumes that we're compiling with an ASCII character set.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <ev.h>

#define DEBUG 1

#if DEBUG
#include <assert.h>
#define ASSERT(cond) assert(cond)
#else
#define ASSERT(cond)
#endif

#define READ_BUFFER_SIZE 4090

const char *bind_port;
const char *backend_addr;
const char *backend_port;

// TODO: We need to split this into multiple files really soon.

static inline int match_string(const char **cursor, char *str) {
	const char *cursor_str = *cursor;
	size_t strlength = strlen(str);
	if (!strncmp(cursor_str, str, strlength)) {
		*cursor = cursor_str + strlength;
		return 1;
	}
	return 0;
}

static inline int is_alpha(char ch) {
	return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z');
}

static inline int is_digit(char ch) {
	return (ch >= '0' && ch <= '9');
}

static inline int is_pchar(char ch) {
	// RFC3986: pchar = unreserved / pct-encoded / sub-delims / ":" / "@"
	//              unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"
	//                  "ALPHA (%41-%5A and %61-%7A), DIGIT (%30-%39)"
	//              pct-encoded = "%" HEXDIG HEXDIG
	//              sub-delims  = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
	// NOTE: This isn't a strict parse, because we allow '%' anywhere rather than just in 'pct-encoded'.
	return is_alpha(ch) || is_digit(ch) || (ch >= '&' && ch <= '.') || ch == '_' || ch == ':' || ch == '~' || ch == ';' || ch == '=' || ch == '@' || ch == '!' || ch == '$' || ch == '%';
}

static inline size_t parse_http_uri_rougly(const char **cursor) {
	// RFC7230: request-target = origin-form / absolute-form / authority-form / asterisk-form
	//              origin-form = absolute-path [ "?" query ]
	//                  absolute-path = 1*( "/" segment )
	//                      segment = *pchar
	//                          pchar = unreserved / pct-encoded / sub-delims / ":" / "@"
	//                              unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"
	//                              pct-encoded = "%" HEXDIG HEXDIG
	//                              sub-delims  = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
	//              authority-form = authority
	//                  authority = [ userinfo "@" ] host [ ":" port ]
	//              absolute-form = absolute-URI
	//                  absolute-URI = scheme ":" hier-part [ "?" query ]
	//                      hier-part = ("//" authority path-abempty) / path-absolute / path-rootless / path-empty
	//              asterisk-form = "*"
	// RFC7231: Referer = absolute-URI / partial-URI
	//              partial-URI = relative-part [ "?" query ]
	//                  relative-part = ("//" authority path-abempty) / path-absolute / path-noscheme / path-empty
	// NOTE: We don't /super/ care about every little part here, so this is just a rough parse for a string with combinations of 'pchar' and '/' characters.
	const char *uri_start = *cursor;
	const char *uri_end = uri_start;
	while (is_pchar(*uri_end) || *uri_end == '/') {
		++uri_end;
	}
	*cursor = uri_end;
	return uri_end - uri_start;
}

static inline int skip_number(const char **cursor) {
	const char *cursor_str = *cursor;
	if (!is_digit(*cursor_str++)) {
		return 0;
	}

	while (is_digit(*cursor_str)) {
		++cursor_str;
	}
	*cursor = cursor_str;
	return 1;
}

static inline void skip_to_next_sp(const char **cursor) {
	const char *cursor_str = *cursor;
	while (*cursor_str != ' ' && *cursor_str != '\0') {
		++cursor_str;
	}
	*cursor = cursor_str;
}

static inline void skip_http_ows(const char **cursor) {
	// OWS = *( SP / HTAB ),  RWS = 1*( SP / HTAB ), BWS = OWS
	const char *cursor_str = *cursor;
	while (*cursor_str == ' ' || *cursor_str == '\t') {
		++cursor_str;
	}
	*cursor = cursor_str;
}

static inline int peek_http_newline(const char *cursor) {
	// Accept '\r\n' or '\n' (returning the number of characters peeked)
	if (cursor[0] == '\r') {
		return (cursor[1] == '\n' ? 2 : 1);
	}
	return cursor[0] == '\n';
}

static inline int skip_past_next_http_newline(const char **cursor) {
	const char *cursor_str = *cursor;
	while (*cursor_str != '\r' && *cursor_str != '\n' && *cursor_str != '\0') {
		++cursor_str;
	}

	int newline_characters_peeked = peek_http_newline(cursor_str);
	if (newline_characters_peeked) {
		*cursor = cursor_str + newline_characters_peeked;
		return 1;
	}

	return 0;
}

// RFC7230
int parse_http_request_header(const char *cursor, const char **request_uri_out, size_t *request_uri_length_out, const char **referer_out, size_t *referer_length_out) {
	// Parse HTTP 'Request-Line' [RFC7230 3.1.1]: 'method SP request-target SP HTTP-Version CRLF'
	if (!match_string(&cursor, "GET ")) { return 0; } // 'method SP'

	*request_uri_out = cursor;
	if (!(*request_uri_length_out = parse_http_uri_rougly(&cursor))) { return 0; } // 'request-target'
	skip_to_next_sp(&cursor); // Skip any remainder of the URI that we didn't parse (e.g. querystring)

	if (!match_string(&cursor, " HTTP/")) { return 0; } // 'SP HTTP/'
	if (!skip_number(&cursor)) { return 0; } // '1*DIGIT'
	if (!match_string(&cursor, ".")) { return 0; } // '.'
	if (!skip_number(&cursor)) { return 0; } // '1*DIGIT'

	// RFC7230 3.2
	//     "field-name ":" OWS field-value OWS"
	//         field-value    = *( field-content / obs-fold )
	//             field-content  = field-vchar [ 1*( SP / HTAB ) field-vchar ]
	//                 field-vchar    = VCHAR / obs-text
	// NOTE: This implementation does not support obsolete line folding (i.e. 'obs-fold')
	while (skip_past_next_http_newline(&cursor)) {
		if (peek_http_newline(cursor)) {
			break;
		} else if (match_string(&cursor, "Referer:")) {
			skip_http_ows(&cursor); // 'OWS'

			// I don't believe the referer field value can be a 'quoted-string'
			*referer_out = cursor;
			*referer_length_out = parse_http_uri_rougly(&cursor); // 'field-value'
			break;
		}
	}

	return 1;
}

// TODO: Don't use malloc/free directly. Plus, check allocation errors.
static void *memory_alloc(size_t size) {
	return malloc(size);
}
static void memory_free(void *memory) {
	return free(memory);
}

void process_client_request(int client_socket) {
	
#if 0
	// TODO: Check request_uri file extension (if it's an image, we can have some fun - etc.)
	// (It would be good if the replacements for certain file extensions were configurable)
#if 0
	// Forward the back-end's response to the client
	{
		char response_buffer[READ_BUFER_SIZE];
		ssize_t bytes_read;

		// This is really slow to return when it's figuring out whether it's finished reading everything or not.
		while ((bytes_read = read(backend_socket, response_buffer, sizeof(response_buffer)))) {
			ssize_t bytes_written = write(client_socket, response_buffer, bytes_read);
			ASSERT(bytes_written == bytes_read);
		}
	}
#else
	char response[256] = {};
	if (is_phishing_refferal) {
		strcpy(response, "HTTP/1.1 200 OK\r\n\r\nPHISHING ALERT!\n");
	} else {
		strcpy(response, "HTTP/1.1 200 OK\r\n\r\nHello, this is a test!\n");
	}
	write(client_socket, response, strlen(response));
#endif
#endif
}

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

static inline void set_socket_nonblock(int socket) {
	if (fcntl(socket, F_SETFL, O_NONBLOCK)) {
		fprintf(stderr, "Failed to change socket to non-blocking (O_NONBLOCK)\n");
		exit(1);
	}
}

struct ev_io_proxy_watcher {
	ev_io io;
	ev_io *paired_watcher, *alternate_watcher;
	char is_first_time;
	char *data_buffer;
	char *pairs_finished;

	const char *request_uri, *referer;
	size_t request_uri_length, referer_length;
};

static struct ev_io *init_ev_io_proxy_watcher(struct ev_io_proxy_watcher *watcher, struct ev_io_proxy_watcher *paired_watcher, struct ev_io_proxy_watcher *alternate_watcher, char *data_chunk, char *shared_buffer) {
	watcher->pairs_finished = shared_buffer;
	*watcher->pairs_finished = 0;
	watcher->data_buffer = data_chunk;
	watcher->data_buffer[READ_BUFFER_SIZE] = '\0';
	watcher->is_first_time = 1;
	watcher->paired_watcher = (struct ev_io *)paired_watcher;
	watcher->alternate_watcher = (struct ev_io *)alternate_watcher;
	watcher->request_uri = watcher->referer = NULL;
	watcher->request_uri_length = watcher->referer_length = 0;

	return (struct ev_io *)watcher;
}

static void ev_io_proxy_watcher_free_pair(struct ev_loop *loop, struct ev_io_proxy_watcher *watcher) {
	ev_io_stop(loop, (struct ev_io *)watcher);
	if (++(*watcher->pairs_finished) == 2) {
		close(watcher->io.fd);
		close(watcher->paired_watcher->fd);
		memory_free(watcher->pairs_finished);
	}
	memory_free(watcher->data_buffer);
	memory_free(watcher->paired_watcher);
	memory_free(watcher);
}

static void ev_io_proxy_watcher_free_set(struct ev_loop *loop, struct ev_io_proxy_watcher *watcher) {
	struct ev_io_proxy_watcher *alternate_watcher = (struct ev_io_proxy_watcher *)watcher->alternate_watcher;
	ev_io_stop(loop, alternate_watcher->paired_watcher);
	ev_io_proxy_watcher_free_pair(loop, alternate_watcher);
	ev_io_proxy_watcher_free_pair(loop, watcher);
}

static void read_from_backend_handler(struct ev_loop *loop, struct ev_io *w, int revents) {
	struct ev_io_proxy_watcher *watcher = (struct ev_io_proxy_watcher *)w;
	ASSERT(!(revents & EV_ERROR));

	// Read from the backend into this client's backend data chunk
	ssize_t bytes_read = read(watcher->io.fd, (void *)watcher->data_buffer, READ_BUFFER_SIZE);
	if (bytes_read == -1) {
		ASSERT(errno != EAGAIN && errno != EWOULDBLOCK);
		fprintf(stderr, "Failed to read data from backend with error code: %d.\n", errno);
		ev_io_proxy_watcher_free_pair(loop, watcher);
		watcher = NULL;
		return;
	} else if (bytes_read == 0) { // TODO: Check if RDHUP and HUP and ERR are cases we can check for to also hit this case.
		ev_io_proxy_watcher_free_pair(loop, watcher);
		watcher = NULL;
		return;
	}

	if (watcher->is_first_time) {
		watcher->is_first_time = 0;
	}

	// Forward the backend's response to the client
	ssize_t bytes_written = write(watcher->paired_watcher->fd, watcher->data_buffer, bytes_read);
	if (bytes_read != bytes_written) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			// Stop the backend EV_READ watcher, and start the client EV_WRITE watcher
			ev_io_stop(loop, (struct ev_io *)watcher);
			ev_io_start(loop, watcher->paired_watcher);
		} else {
			if (errno != ECONNRESET && errno != EPIPE) {
				fprintf(stderr, "Failed to write to client with error code: %d.\n", errno);
			}
			ev_io_proxy_watcher_free_pair(loop, watcher);
			watcher = NULL;
			return;
		}
	} else if (((struct ev_io_proxy_watcher *)watcher->paired_watcher)->is_first_time) {
			((struct ev_io_proxy_watcher *)watcher->paired_watcher)->is_first_time = 0;
	}
}

static void write_to_client_handler(struct ev_loop *loop, struct ev_io *w, int revents) {
	struct ev_io_proxy_watcher *watcher = (struct ev_io_proxy_watcher *)w;
	ASSERT(!(revents & EV_ERROR));

	// Write from this client's backend data chunk to the client
	// TODO: FACTOR: into 'ev_io_proxy_watcher_perform_write' (but we need customisability for different errors each way.. hmm..)
	ssize_t bytes_written = write(watcher->io.fd, (void *)watcher->data_buffer, READ_BUFFER_SIZE);
	if (bytes_written != READ_BUFFER_SIZE) {
		ASSERT(errno != EAGAIN && errno != EWOULDBLOCK);
		fprintf(stderr, "Failed to write data to backend with error code: %d.\n", errno);
		ev_io_proxy_watcher_free_pair(loop, watcher);
		watcher = NULL;
		return;
	}

	if (watcher->is_first_time) {
		watcher->is_first_time = 0;
	}

	// Read from the backend into this client's backend data chunk
	// TODO: FACTOR: into 'ev_io_proxy_watcher_perform_immediate_read_after_write'
	ssize_t bytes_read = read(watcher->paired_watcher->fd, watcher->data_buffer, READ_BUFFER_SIZE);
	if (bytes_read == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			ev_io_stop(loop, (struct ev_io *)watcher);
			ev_io_start(loop, watcher->paired_watcher);
		} else {
			fprintf(stderr, "Failed to read data from backend with error code: %d.\n", errno);
			ev_io_proxy_watcher_free_pair(loop, watcher);
			watcher = NULL;
			return;
		}
	} else if (bytes_read == 0) {
		ev_io_proxy_watcher_free_pair(loop, watcher);
		watcher = NULL;
		return;
	} else if (((struct ev_io_proxy_watcher *)watcher->paired_watcher)->is_first_time) {
			((struct ev_io_proxy_watcher *)watcher->paired_watcher)->is_first_time = 0;
	}
}

static void read_from_client_handler(struct ev_loop *loop, struct ev_io *w, int revents) {
	struct ev_io_proxy_watcher *watcher = (struct ev_io_proxy_watcher *)w;
	ASSERT(!(revents & EV_ERROR));

	// Read from the client into this client's data chunk
	// TODO: FACTOR: into 'ev_io_proxy_watcher_perform_read'
	// TODO: It might be desirable in future to have an explicit 'read' timeout here.
	ssize_t bytes_read = read(watcher->io.fd, (void *)watcher->data_buffer, READ_BUFFER_SIZE);
	if (bytes_read == -1) {
		ASSERT(errno != EAGAIN && errno != EWOULDBLOCK);
		if (errno != ECONNRESET && errno != EPIPE) {
			fprintf(stderr, "Failed to read data from client with error code: %d.\n", errno);
		}

		if (watcher->is_first_time) {
			ev_io_proxy_watcher_free_set(loop, watcher);
		} else {
			ev_io_proxy_watcher_free_pair(loop, watcher);
		}
		watcher = NULL;
		return;
	} else if (bytes_read == 0) { // TODO: RDHUP and a few other cases might also want to hit this case? CHECK!
		if (watcher->is_first_time) {
			ev_io_proxy_watcher_free_set(loop, watcher);
		} else {
			ev_io_proxy_watcher_free_pair(loop, watcher);
		}
		watcher = NULL;
		return;
	}

	if (watcher->is_first_time) {
		watcher->is_first_time = 0;

		// TODO: Parse HTTP headers (if any)

	}

	// Forward the client's request to the back-end
	// TODO: FACTOR: into 'ev_io_proxy_watcher_perform_immediate_write_after_read' (but we need customisability for different errors each way.. hmm..)
	ssize_t bytes_written = write(watcher->paired_watcher->fd, watcher->data_buffer, bytes_read);
	if (bytes_read != bytes_written) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			// Stop the EV_READ from client watcher, and start the EV_WRITE to backend watcher.
			ev_io_stop(loop, (struct ev_io *)watcher);
			ev_io_start(loop, watcher->paired_watcher);
		} else {
			if (errno == EPIPE || errno == ECONNRESET) {
				// TODO: In future, if we're trying to write to the server, it might be nice to serve a proper 503 error to the user.
				fprintf(stderr, "Failed to write data to backend due to EPIPE or ECONNRESET (broken connection).\n");
			} else {
				fprintf(stderr, "Failed to write data to backend with error code: %d.\n", errno);
			}
			ev_io_proxy_watcher_free_pair(loop, watcher);
			watcher = NULL;
			return;
		}
	} else if (((struct ev_io_proxy_watcher *)watcher->paired_watcher)->is_first_time) {
			((struct ev_io_proxy_watcher *)watcher->paired_watcher)->is_first_time = 0;
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

static void write_to_backend_handler(struct ev_loop *loop, struct ev_io *w, int revents) {
	struct ev_io_proxy_watcher *watcher = (struct ev_io_proxy_watcher *)w;
	ASSERT(!(revents & EV_ERROR));

	// Write from this client's data chunk to the backend
	// TODO: FACTOR: into 'ev_io_proxy_watcher_perform_write' (but we need customisability for different errors each way.. hmm..)
	ssize_t bytes_written = write(watcher->io.fd, (void *)watcher->data_buffer, READ_BUFFER_SIZE);
	if (bytes_written != READ_BUFFER_SIZE) {
		ASSERT(errno != EAGAIN && errno != EWOULDBLOCK);
		if (errno == EPIPE || errno == ECONNRESET) {
			// TODO: In future, if we're trying to write to the server, it might be nice to serve a proper 503 error to the user.
			fprintf(stderr, "Failed to write data to backend due to EPIPE or ECONNRESET (broken connection).\n");
		} else {
			fprintf(stderr, "Failed to write data to backend with error code: %d.\n", errno);
		}

		if (watcher->is_first_time) {
			ev_io_proxy_watcher_free_set(loop, watcher);
		} else {
			ev_io_proxy_watcher_free_pair(loop, watcher);
		}
		watcher = NULL;
		return;
	}

	if (watcher->is_first_time) {
		watcher->is_first_time = 0;
	}

	// Read from the client into this client's data chunk
	// TODO: FACTOR: into 'ev_io_proxy_watcher_perform_immediate_read_after_write'
	ssize_t bytes_read = read(watcher->paired_watcher->fd, watcher->data_buffer, READ_BUFFER_SIZE);
	if (bytes_read == -1) {
		int error_code = errno;
		if (error_code == EAGAIN || error_code == EWOULDBLOCK) {
			// Stop the EV_WRITE to backend watcher, and start the EV_READ from client watcher
			ev_io_stop(loop, (struct ev_io *)watcher);
			ev_io_start(loop, watcher->paired_watcher);
		} else {
			fprintf(stderr, "Error %d 'read'ing from client\n", error_code);
		}
		ev_io_proxy_watcher_free_pair(loop, watcher);
		watcher = NULL;
		return;
	} else if (bytes_read == 0) {
		ev_io_proxy_watcher_free_pair(loop, watcher);
		watcher = NULL;
		return;
	} else if (((struct ev_io_proxy_watcher *)watcher->paired_watcher)->is_first_time) {
			((struct ev_io_proxy_watcher *)watcher->paired_watcher)->is_first_time = 0;
	}
}

struct ev_io_connection_watcher {
	struct ev_io io;
	struct addrinfo *backend_addrinfo;
};

struct ev_io_backend_connect_watcher {
	struct ev_io io;
	int client_socket;
	struct addrinfo *backend_addrinfo;
};

static void register_client_watchers(struct ev_loop *loop, int client_socket, int backend_socket) {
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

static inline int obtain_next_valid_socket(struct addrinfo **addrinfos) {
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

static void backend_connect_handler(struct ev_loop *loop, struct ev_io *w, int revents) {
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

static void accept_client_handler(struct ev_loop *loop, struct ev_io *w, int revents) {
	struct ev_io_connection_watcher *watcher = (struct ev_io_connection_watcher *)w;

	int client_socket = accept(watcher->io.fd, NULL, NULL);
	if (client_socket == -1) {
		ASSERT(errno != EAGAIN && errno != EWOULDBLOCK);
		if (errno == ENOBUFS || errno == ENOMEM) {
			fprintf(stderr, "Failed to accept client connection due to insufficient memory (may be socket buffer limits).\n");
		} else {
			fprintf(stderr, "Failed to accept client connection.\n");
		}
		// We don't have any memory to free or sockets to close in this particular case.
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

// TODO: In my testing we can't quite make it to c10k quite yet, but I'm not entirely sure
// why this is. Might be to do with environment, rather than software, configuration.
// TODO: Occasionally clients seem to disconnect with "connection reset by peer" under
// high load, but I'm unsure why this happens (could be an environment configuration issue?)
int main(int argc, char *argv[]) {
	bind_port = "31500"; // TODO: Accept these params as CLI args
	backend_addr = "localhost";
	backend_port = "http";

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
			exit(1);
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

	// Mark the socket we've bound on to listen for incoming connections ('backlog' should probably be configurable)
	if (listen(bind_socket, 10) == -1) {
		fprintf(stderr, "Failed to listen on host\n");
		exit(1);
	}
	set_socket_nonblock(bind_socket);


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