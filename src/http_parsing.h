#ifndef HTTP_PARSING_H
#define HTTP_PARSING_H

// The HTTP parsing code in this project isn't designed to work outside of this very limited use case (where we don't
// care /too/ much about parse accuracy, but do care about performance, and only want the 'referer' and 'request uri').
int parse_http_request_header(const char *cursor, const char **request_uri_out, size_t *request_uri_length_out, const char **referer_out, size_t *referer_length_out);

#endif
