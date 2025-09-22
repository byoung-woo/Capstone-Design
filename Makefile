# Makefile
CC = gcc

# 소스 파일 목록에 rule_checker.c 추가
SRCS = src/main.c src/db_manager.c src/response_builder.c src/login_handler.c src/signup_handler.c src/logger.c src/ssl_handler.c src/router.c src/rule_checker.c

OBJS = $(SRCS:.c=.o)
TARGET = webserver
LIBS = -lssl -lcrypto -lcjson -lsqlite3
INCLUDES = -Iinclude/
CFLAGS = -g -Wall -pthread

all: $(TARGET)

$(TARGET): $(OBJS)
	@echo "Linking $(TARGET)..."
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET) $(LIBS)
	@echo "Build complete."

%.o: %.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	@echo "Cleaning up..."
	$(RM) $(OBJS) $(TARGET)
	@echo "Cleanup complete."

.PHONY: all clean