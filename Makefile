CC=clang
CFLAGS=-O0 -ggdb
LDLIBS=-lev
SRCDIR=src
DESTDIR=src
SOURCES=$(wildcard $(SRCDIR)/*.c)
HEADERS=$(wildcard $(SRCDIR)/*.h)
OBJECTS=$(SOURCES:$(SRCDIR)/%.c=$(DESTDIR)/%.o)

phishbait: clean $(OBJECTS)
	$(CC) -o phishbait $(OBJECTS) $(LDLIBS)

ev_io_backend_connect_watcher.o:
	$(CC) $(CPPFLAGS) -c $< -o $@

ev_io_connection_watcher.o:
	$(CC) $(CPPFLAGS) -c $< -o $@

ev_io_proxy_watcher.o:
	$(CC) $(CPPFLAGS) -c $< -o $@

http_parsing.o:
	$(CC) $(CPPFLAGS) -c $< -o $@

phishbait.o:
	$(CC) $(CPPFLAGS) -c $< -o $@

socket.o:
	$(CC) $(CPPFLAGS) -c $< -o $@

utilities.o:
	$(CC) $(CPPFLAGS) -c $< -o $@



.PHONY:: phishbait clean

clean:
	rm -rf $(OBJECTS)
