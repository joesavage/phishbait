# phishbait

`phishbait` is a reverse proxy for HTTP servers that want to serve different content to a subset of websites (e.g. phishing sites) that hotlink resources. The application is designed to work on OS X and Linux, but shouldn't be too difficult to port to Windows.

HTTP GET requests from blacklisted referers are modified to requests with the filename 'phishing' and the file extension of the original request - this means requests via blacklisted referers go through a normal request pipeline (through any other reverse proxies, etc.), and that different types of replacement resources can be served up for different requested file extensions (including HTML files [e.g. for phishing sites that redirect to yours after stealing credentials], CSS files [e.g. change the styles of a phishing site that hotlinks stylesheets], image files [e.g. replace hotlinked images with warning images], etc.).

**This application has not been tested with any real rigor, and so is not currently suitable for use in a production environment.** It also isn't quite ready for high traffic environments yet - from my local testing it can handle a couple of hundred concurrent requests fairly reliably, but things may be different in different environments. Adding multi-threading and optimising the code via the results of proper profiling are performance-related tasks I'm hoping to complete in future.

This project makes use of the [libev](http://software.schmorp.de/pkg/libev.html) library for fast event-driven I/O.

Usage: `phishbait backend_host backend_port [-p listen_port] [-q queue_backlog]`

Demonstration (both websites link the exact same image resources):
![](/example.gif?raw=true)
