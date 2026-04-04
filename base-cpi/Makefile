CC = gcc
CFLAGS = -O3 -march=native -Wall -Wextra

TARGET = base-cpi
SRC = base-cpi.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)
