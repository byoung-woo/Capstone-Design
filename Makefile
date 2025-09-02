# Makefile
# C 소스 파일 컴파일 및 링크를 자동화하는 스크립트

# 컴파일러 설정
CC = gcc

# 소스 파일 목록
SRCS = src/main.c src/logger.c src/ssl_handler.c src/router.c src/response_builder.c src/db_manager.c

# 오브젝트 파일 목록 (자동 생성)
OBJS = $(SRCS:.c=.o)

# 실행 파일명
TARGET = webserver

# 라이브러리 목록
# OpenSSL 라이브러리 (SSL/TLS 통신)
# cJSON 라이브러리 (JSON 로그 포맷팅)
LIBS = -lssl -lcrypto -lcjson -lsqlite3

# 포함 디렉토리 설정 (헤더 파일 경로)
INCLUDES = -Iinclude/

# 컴파일 옵션
# -g: 디버깅 정보 포함
# -Wall: 모든 경고 메시지 활성화
# -pthread: 스레드 지원 활성화
CFLAGS = -g -Wall -pthread

# 기본 빌드 타겟: 모든 오브젝트 파일을 컴파일하여 최종 실행 파일 생성
all: $(TARGET)

$(TARGET): $(OBJS)
	@echo "Linking $(TARGET)..."
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET) $(LIBS)
	@echo "Build complete."

# 각 C 소스 파일을 오브젝트 파일로 컴파일
%.o: %.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# 소스 파일 정리: 오브젝트 파일과 실행 파일을 삭제
clean:
	@echo "Cleaning up..."
	$(RM) $(OBJS) $(TARGET)
	@echo "Cleanup complete."

.PHONY: all clean
