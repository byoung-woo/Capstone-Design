CC      := gcc
CFLAGS  := -Wall -g
LDFLAGS := -lssl -lcrypto   # HTTPS 서버를 유지하려면 이 라인 그대로
# 만약 HTTP 서버만 쓰실 거면, '-lssl -lcrypto' 제거

# 서버용 소스
SRCS_SRV := ssl_init.c server.c path_response.c logger.c
OBJS_SRV := $(SRCS_SRV:.c=.o)

# 클라이언트용 소스 (평문 HTTP)
SRCS_CL  := client.c
OBJS_CL  := $(SRCS_CL:.c=.o)

.PHONY: all clean

all: server client

server: $(OBJS_SRV)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

client: $(OBJS_CL)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(OBJS_SRV) $(OBJS_CL) server client
