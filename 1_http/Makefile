CC = gcc
CFLAGS = -Wall -Wextra -std=c99
SRCS = server.c logger.c fixed_response.c path_response.c static_file.c header_time.c form_input.c
OBJS = $(SRCS:.c=.o)
TARGET = webserver

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
