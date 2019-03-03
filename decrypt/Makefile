CC = gcc
CFLAGS = -g -W -Wall
TARGET = test
OBJECTS = main.o decrypt.o

$(TARGET) : $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS)

main.o : decrypt.h main.c
decrypt.o : decrypt.h decrypt.c

clean : 
	rm -rf $(TARGET) $(OBJECTS)

