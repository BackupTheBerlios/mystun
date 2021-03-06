# Makefile

CC     = gcc
CFLAGS = -DOPENSSL_NO_KRB5
LIBS   = -lssl
# for Solaris
#LIBS   =-ssl -lresolv -lsocket -lnsl

ifeq ($(DEBUG),1)
    CFLAGS += -g
endif

SERVERNAME = mystun-server
CLIENTNAME = mystun-client

DESTDIR ?= /usr/local
INSTALL ?= install
BIN-DIR ?= bin/


all: server client

client: client.h client.c main.o utils.o udp_server.o stun_parse.o stun_create.o ip_addr.o clientlib.o server.o
	echo "MAKING CLIENT"
	$(CC) $(CFLAGS) -DCOMPILE_CLIENT main.o utils.o udp_server.o stun_parse.o stun_create.o ip_addr.o clientlib.o server.o -o $(CLIENTNAME)  client.c $(LIBS)

server: utils.o udp_server.o stun_parse.o stun_create.o ip_addr.o server.o main.o
	echo "MAKING SERVER"
	$(CC) $(CFLAGS) -DCOMPILE_SERVER utils.o udp_server.o stun_parse.o stun_create.o ip_addr.o server.o -o $(SERVERNAME)  main.c $(LIBS)

main.o: main.c
	$(CC) $(CFLAGS) -o main.o -c main.c

utils.o: utils.h utils.c
	$(CC) $(CFLAGS) -o utils.o -c utils.c

udp_server.o: udp_server.h udp_server.c
	$(CC) $(CFLAGS) -o udp_server.o -c udp_server.c

stun_parse.o: stun_parse.h stun_parse.c
	$(CC) $(CFLAGS) -o stun_parse.o -c stun_parse.c

stun_create.o: stun_create.h stun_create.c
	$(CC) $(CFLAGS) -o stun_create.o -c stun_create.c

ip_addr.o: ip_addr.h ip_addr.c
	$(CC) $(CFLAGS) -o ip_addr.o -c ip_addr.c

server.o: server.h server.c
	$(CC) $(CFLAGS) -o server.o -c server.c

clientlib.o: clientlib.h clientlib.c
	$(CC) $(CFLAGS) -o clientlib.o -c clientlib.c

clean:
	rm -f *.o $(SERVERNAME) $(CLIENTNAME)

install: all mk-install-dirs install-bin

install-server: server mk-install-dirs install-server-bin

mk-install-dirs: $(DESTDIR)/$(BIN-DIR)

$(DESTDIR)/$(BIN-DIR):
	mkdir -p $(DESTDIR)/$(BIN-DIR)

install-bin: $(DESTDIR)/$(BIN-DIR)
	$(INSTALL) $(SERVERNAME) $(DESTDIR)/$(BIN-DIR)
	$(INSTALL) $(CLIENTNAME) $(DESTDIR)/$(BIN-DIR)

install-server-bin: $(DESTDIR)/$(BIN-DIR)
	$(INSTALL) $(SERVERNAME) $(DESTDIR)/$(BIN-DIR)

