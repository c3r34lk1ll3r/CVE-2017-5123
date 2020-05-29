CC=gcc
CFLAGS=-O0
LDFLAGS=-lpthread

EXE=exploit
SOURCES=main.c 

all:
	$(CC) $(CFLAGS) $(SOURCES) -o $(EXE) $(LDFLAGS) 
install: all
	cp ./exploit ~/exploit
clean:
	rm -f $(EXE)
