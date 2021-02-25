
CC = gcc
CFLAGS = -Wall -g
LDLIBS = -pthread -lmta_crypt -lmta_rand -lrt
OBJFILES = launcher.o decrypter.o server.o utils.o
TARGET =  server decrypter launcher
RM = rm -f   # rm command

.PHONY: all
all: $(TARGET)	

$(TARGET) : utils.o

$(TARGET:=.o): datastructs.h

.PHONY: clean
clean:
	-${RM} $(TARGET) ${OBJFILES}	