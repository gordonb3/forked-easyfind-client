ifdef CROSS_COMPILE
CC      = $(CROSS_COMPILE)g++
else
CC      = $(shell g++ -dumpmachine)-g++
endif
CFLAGS  +=  -I. -c -Wall
LDFLAGS +=  -lcurl
OBJ     = ef.o ef-lib.o
LIBS	= $(patsubst %.cpp,%.o,$(wildcard jsoncpp/*.cpp))
DEPS    = ef-lib.h

all: ef

ef: $(OBJ) $(LIBS)
	$(CC) $(OBJ) $(LIBS) $(LDFLAGS) -o ef

%.o: %.cpp $(DEP)
	$(CC) $(CFLAGS) $(EXTRAFLAGS) $< -o $@

distclean: clean

clean:
	rm -f $(OBJ) $(LIBS) ef

install: all
	install -d -m 0755 $(DESTDIR)/usr/bin
	install -m 0755 ef $(DESTDIR)/usr/bin
	ln -sf ef $(DESTDIR)/usr/bin/efd

uninstall:
	rm -f $(DESTDIR)/usr/bin/efd $(DESTDIR)/usr/bin/ef
	rmdir --ignore-fail-on-non-empty -p $(DESTDIR)/usr/bin

