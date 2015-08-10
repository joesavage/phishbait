#include <string.h>

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
int parse_http_request_header(const char *cursor, const char **request_uri_out, size_t *request_uri_length_out, const char **referer_out, size_t *referer_length_out, const char **host_out, size_t *host_length_out) {
	// Parse HTTP 'Request-Line' [RFC7230 3.1.1]: 'method SP request-target SP HTTP-Version CRLF'
	if (!match_string(&cursor, "GET ")) { return 0; } // 'method SP'

	*request_uri_out = cursor;
	if (!(*request_uri_length_out = parse_http_uri_rougly(&cursor))) { return 0; } // 'request-target'
	skip_to_next_sp(&cursor); // Skip any remainder of the URI that we didn't parse (e.g. querystring)

	if (!match_string(&cursor, " HTTP/")) { return 0; } // 'SP HTTP/'
	if (!skip_number(&cursor)) { return 0; } // '1*DIGIT'
	if (!match_string(&cursor, ".")) { return 0; } // '.'
	if (!skip_number(&cursor)) { return 0; } // '1*DIGIT'

	int fields_matched = 0;

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
			if (++fields_matched == 2) { break; }
		} else if (match_string(&cursor, "Host:")) {
			skip_http_ows(&cursor); // 'OWS'

			*host_out = cursor;
			*host_length_out = parse_http_uri_rougly(&cursor); // 'field-value'
			if (++fields_matched == 2) { break; }
		}
	}

	return 1;
}
