
CC = gcc
CFLAGS = -Wall -g -O0
LDFLAGS = -pthread -lmta_crypt -lmta_rand -lrt
OBJFILES = launcher.o decrypter.o server.o utils.o
TARGET =  server decrypter launcher
RM = rm -f   # rm command


.PHONY: all
all: $(TARGET)	


launcher: launcher.o utils.o 
	$(CC) $(CFLAGS) -o launcher launcher.o utils.o $(LDFLAGS)

server: server.o utils.o 
	$(CC) $(CFLAGS) -o server server.o utils.o $(LDFLAGS)

decrypter: decrypter.o utils.o 
	$(CC) $(CFLAGS) -o decrypter decrypter.o utils.o $(LDFLAGS)

utils.o: datastructs.h



.PHONY: clean
clean:
	-${RM} $(TARGET) ${OBJFILES}	