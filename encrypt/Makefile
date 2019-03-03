CC = gcc
CFLAGS = -g -W -Wall
TARGET = test
OBJECTS = main.o encrypt.o

$(TARGET) : $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS)

main.o : encrypt.h main.c
encrypt.o : encrypt.h encrypt.c

clean : 
	rm -rf $(OBJECTS) $(TARGET)
