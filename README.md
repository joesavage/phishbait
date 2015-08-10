# phishbait

`phishbait` is a reverse proxy for HTTP servers that want to serve alternate content to a subset of websites (e.g. phishing sites) that hotlink resources. The program is designed to work on OS X and Linux, but shouldn't be too difficult to port to Windows.

The project makes use of the [libev](http://software.schmorp.de/pkg/libev.html) library for fast event-driven I/O.

