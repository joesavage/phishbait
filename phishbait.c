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

#define MAXIMUM_REQUEST_HEADER_SIZE 2048

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

// static inline int is_whitespace(char ch) {
// 	// NOTE: This code assumes the compiler uses an ASCII text encoding.
// 	return ch == ' ' || (ch >= '\t' && ch <= '\r');
// }

// struct req_header_position {
// 	char *cursor;
// 	int last_no_of_lines_passed;
// };

// struct req_header_position skip_whitespace(char *cursor) {
// 	struct req_header_position result = {};
// 	while (is_whitespace(*cursor)) {
// 		if (cursor[0] == '\r') {
// 			if (cursor[1] == '\n') {
// 				++cursor;
// 			}
// 			++cursor;
// 			++result.last_no_of_lines_passed;
// 		} else if (cursor[0] == '\n') {
// 			if (cursor[1] == '\r') {
// 				++cursor;
// 			}
// 			++cursor;
// 			++result.last_no_of_lines_passed;
// 		} else {
// 			++cursor;
// 		}
// 	}

// 	result.cursor = cursor;
// 	return result;
// }

// struct req_header_position skip_non_whitespace(char *cursor) {
// 	struct req_header_position result;
// 	result.cursor = cursor;
// 	result.last_no_of_lines_passed = 0;

// 	while (!is_whitespace(result.cursor[0]) && result.cursor[0] != '\0') {
// 		++result.cursor;
// 	}

// 	return result;
// }

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
	// NOTE: I'm assuming that we're compiling with an ASCII character set.
	// NOTE: This isn't a strict parse, because we allow '%' anywhere rather than just in 'pct-encoded'.
	return is_alpha(ch) || is_digit(ch) || (ch >= '&' && ch <= '.') || ch == '_' || ch == ':' || ch == '~' || ch == ';' || ch == '=' || ch == '@' || ch == '!' || ch == '$' || ch == '%';
}

static inline size_t parse_http_uri_rougly(const char **cursor) {
	// RFC7230: request-target = origin-form / absolute-form / authority-form / asterisk-form
	//              origin-form = absolute-path [ "?" query ]        ; Relative path
	//                  absolute-path = 1*( "/" segment )
	//                      segment = *pchar
	//                          pchar = unreserved / pct-encoded / sub-delims / ":" / "@"
	//                              unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"
	//                              pct-encoded = "%" HEXDIG HEXDIG
	//                              sub-delims  = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
	//              authority-form = authority        ; Authority path (without scheme)
	//                  authority = [ userinfo "@" ] host [ ":" port ]
	//                      userinfo = *( unreserved / pct-encoded / sub-delims / ":" )
	//                      host = IP-literal / IPv4address / reg-name
	//                          IP-literal  = "[" ( IPv6address / IPvFuture  ) "]"
	//                              IPv6address = https://tools.ietf.org/html/rfc3986#section-3.2.2
	//                              IPvFuture  = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
	//                          IPv4address = dec-octet "." dec-octet "." dec-octet "." dec-octet
	//                          reg-name    = *( unreserved / pct-encoded / sub-delims )
	//                      port = *DIGIT
	//              absolute-form = absolute-URI        ; Absolute path (with scheme, etc.)
	//                  absolute-URI = scheme ":" hier-part [ "?" query ]
	//                      hier-part = ("//" authority path-abempty) / path-absolute / path-rootless / path-empty
	//                          path-abempty  = *( "/" segment )        ; Begins with a slash or is empty
	//                          path-absolute = "/" [ segment-nz *( "/" segment ) ]        ; Begins with a slash (but not a '//', in this context)
	//                              segment-nz    = 1*pchar        ; Non-zero segment
	//                          path-rootless = segment-nz *( "/" segment )        ; Doesn't begin with a '/'
	//                          path-empty    = 0<pchar>        ; Empty (zero characters)
	//              asterisk-form = "*"
	// RFC7231: Referer = absolute-URI / partial-URI
	//              partial-URI = relative-part [ "?" query ]
	//                  relative-part = ("//" authority path-abempty) / path-absolute / path-noscheme / path-empty        ; Like hier-part, but without rootless (no leading '/'), and with noscheme.
	//                      path-noscheme = segment-nz-nc *( "/" segment )
	//                          segment-nz-nc = 1*( unreserved / pct-encoded / sub-delims / "@" )        ; Non-zero segment with no colons
	// NOTE: For this particular purpose, we don't /super/ care about every little part so this is just a rough parse
	// assuming we're looking for a string with combinations of 'pchar' and '/' characters.
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
	//         NOTE: This implementation does not support obsolete line folding (i.e. 'obs-fold')
	while (skip_past_next_http_newline(&cursor)) {
		if (peek_http_newline(cursor)) {
			break;
		} else if (match_string(&cursor, "Referer:")) {
			skip_http_ows(&cursor); // 'OWS'

			// TODO: I don't believe the referer field value can be a 'quoted-string' [Check!]
			*referer_out = cursor;
			*referer_length_out = parse_http_uri_rougly(&cursor); // 'field-value'
			break;
		}
	}

	return 1;
}

void process_request(int client_socket, int backend_socket) {
	// Forward the client's request to the back-end
	// TODO: There may be weird HTTP stuff (partial responses and timeouts and things) that we need to deal with here.
	char request_buffer_head[MAXIMUM_REQUEST_HEADER_SIZE + 1]; // TODO: How large do we want this to be?
	// char char request_buffer_tail[MAXIMUM_REQUEST_HEADER_SIZE]; // TODO: Send the rest of the request to the server! (Currently we only send the first 'read')
	{
		ssize_t bytes_read = read(client_socket, request_buffer_head, sizeof(request_buffer_head) - 1); // TODO: Timeout?
		if (bytes_read == -1) {
			// TODO: log
			ASSERT(0);
			return;
		} else if (bytes_read != 0) {
			ssize_t bytes_written = write(backend_socket, request_buffer_head, bytes_read);
			ASSERT(bytes_written == bytes_read);
		}
	}

	// Parse request HTTP 'Referer' header.
	// Given the purpose of this tool, malformed or odd HTTP requests are passed without further checking.
	// Not only is this beneficial for performance, but given the purpose of this tool - the users
	// effected by phishing issues will likely be using sane, relatively-compliant web browsers.

	// Is there a practical limit on this? TODO: Currently, we probably have overflow issues with these.
	int is_phishing_refferal = 0;
	const char *request_uri, *referer;
	size_t request_uri_length, referer_length;
	if (parse_http_request_header(request_buffer_head, &request_uri, &request_uri_length, &referer, &referer_length)) {
		if (referer && referer_length > 0) {
			printf("REFERER URI: %.*s\n", (int)referer_length, referer);
			is_phishing_refferal = referer_length % 2;
		}

		if (request_uri) {
			printf("REQ URI: %.*s\n\n", (int)request_uri_length, request_uri);
		}
	}
	

#if 0
	// Forward the back-end's response to the client
	{
		char response_buffer[4096];
		ssize_t bytes_read;

		// For whatever reason, this loop is really slow the second time around in testing.
		// I'm guessing that it waits a while to check there's definitely no more data to pass or something?
		// Switching to using 'epoll' should probably help this considerably.
		while ((bytes_read = read(backend_socket, response_buffer, sizeof(response_buffer) - 1))) {
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

		close(backend_socket);
		close(client_socket);
	}

	close(bind_socket);
	return 0;
}