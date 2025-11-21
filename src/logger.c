#define _GNU_SOURCE // [추가] strcasestr 함수 사용을 위해
// src/logger.c (TLS/SSL 암호화 적용 및 비동기 로깅)
// [수정] AI 모델이 요구하는 HTTP 컨텐츠 기반 로깅으로 변경
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <cjson/cJSON.h>
#include <unistd.h>
#include <pthread.h> // [추가] 스레드 및 동기화
// OpenSSL 헤더 추가
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "logger.h"
#include "webserver.h"

#define ANALYZER_IP "172.20.10.2" // AI 분석 서버 IP 주소
#define ANALYZER_PORT 5140
#define LOG_QUEUE_SIZE 100 // [추가] 로그 큐 최대 크기

// --- 로그 큐 관련 전역 변수 ---
static char* log_queue[LOG_QUEUE_SIZE]; // 로그 메시지를 저장할 큐 (NULL로 초기화)
static int log_queue_head = 0;
static int log_queue_tail = 0;
static int log_queue_count = 0; // 현재 큐에 있는 로그 수

static pthread_mutex_t log_queue_mutex; // 큐 접근을 위한 뮤텍스
static pthread_cond_t log_queue_cond;   // 큐에 로그가 들어왔음을 알리는 조건 변수

static FILE* access_log_file;
static FILE* attack_log_file;

// --- 큐 초기화 및 관리 함수 ---
void init_log_queue() {
    pthread_mutex_init(&log_queue_mutex, NULL);
    pthread_cond_init(&log_queue_cond, NULL);
}

// 큐에 로그를 푸시하고 대기 중인 스레드에게 알림 (호출자가 할당한 메모리 소유권 이전)
static void push_log_to_queue(char* json_log_with_newline) {
// ... existing code ...
    pthread_mutex_lock(&log_queue_mutex);

    if (log_queue_count < LOG_QUEUE_SIZE) {
        log_queue[log_queue_tail] = json_log_with_newline; // 메모리 소유권 이전
        log_queue_tail = (log_queue_tail + 1) % LOG_QUEUE_SIZE;
        log_queue_count++;
        pthread_cond_signal(&log_queue_cond); // [추가] 대기 중인 log_sender_thread에 알림
    } else {
        log_error("Log queue is full. Dropping log message.");
        free(json_log_with_newline); // 버려진 로그는 해제
    }

    pthread_mutex_unlock(&log_queue_mutex);
}

// 큐에서 로그를 팝 (log_sender_thread 전용)
static char* pop_log_from_queue() {
    char* log_to_send = NULL;
    
    pthread_mutex_lock(&log_queue_mutex);

    // 큐가 비어있으면 시그널을 기다립니다.
    while (log_queue_count == 0) {
        pthread_cond_wait(&log_queue_cond, &log_queue_mutex);
    }

    log_to_send = log_queue[log_queue_head];
    log_queue[log_queue_head] = NULL; // 포인터 정리
    log_queue_head = (log_queue_head + 1) % LOG_QUEUE_SIZE;
    log_queue_count--;

    pthread_mutex_unlock(&log_queue_mutex);
    return log_to_send;
}

// --- 로깅 기본 함수 ---

void init_logger() {
    access_log_file = fopen(ACCESS_LOG_FILE, "a");
    attack_log_file = fopen(ATTACK_LOG_FILE, "a");
    if (access_log_file == NULL || attack_log_file == NULL) {
        perror("Failed to open log files");
        exit(1);
    }
}

void log_error(const char* message) {
    if (!attack_log_file) return;
    time_t now = time(NULL);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
    fprintf(attack_log_file, "[%s] %s\n", time_str, message);
    fflush(attack_log_file);
}

// --- 로그 전송 스레드 구현 ---

// AI 분석 서버로 로그를 SSL 통신으로 전송하는 핵심 로직 (재연결 포함)
static void send_log_over_ssl(const char* log_with_newline) {
    int sock;
    struct sockaddr_in serv_addr;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;

    // 1. SSL 클라이언트 컨텍스트 생성
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ctx) {
        log_error("Failed to create SSL context for analyzer client.");
        return;
    }

    // 2. TCP 소켓 생성 및 연결
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        log_error("Socket creation error for analyzer");
        SSL_CTX_free(ctx);
        return;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(ANALYZER_PORT);
    if (inet_pton(AF_INET, ANALYZER_IP, &serv_addr.sin_addr) <= 0) {
        log_error("Invalid address/ Address not supported");
        close(sock);
        SSL_CTX_free(ctx);
        return;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        // AI 서버가 연결되지 않은 경우 에러만 기록하고 종료 (메인 스레드를 블록하지 않음)
        log_error("Connection Failed to analyzer server (Non-blocking)");
        close(sock);
        SSL_CTX_free(ctx);
        return;
    }

    // 3. SSL 객체 생성 및 소켓과 연결
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    // 4. SSL 핸드셰이크 수행
    if (SSL_connect(ssl) <= 0) {
        log_error("SSL handshake failed with analyzer server.");
        ERR_print_errors_fp(stderr);
    } else {
        // 5. 암호화된 채널로 데이터 전송
        SSL_write(ssl, log_with_newline, strlen(log_with_newline));
    }

    // 6. 자원 해제
    if(ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    close(sock);
    SSL_CTX_free(ctx);
}


// [추가] 로그 전송 전용 스레드 함수
void* log_sender_thread(void* arg) {
    char* json_log = NULL;

    while (1) {
        // 1. 큐에서 로그 메시지를 대기하며 꺼냄 (큐가 비어있으면 대기)
        json_log = pop_log_from_queue();

        if (json_log) {
            // 2. AI 분석 서버로 로그 전송 (이 작업이 스레드 내부에서 비동기적으로 실행됨)
            send_log_over_ssl(json_log);
            
            // 3. 큐에서 소유권을 가져온 메모리 해제
            free(json_log);
            json_log = NULL;
        }
    }
    return NULL;
}

// --- [신규] AI 모델 호환을 위한 헬퍼 함수 ---

/**
 * @brief raw_buffer에서 User-Agent 헤더 값을 찾아 반환합니다.
 * @param raw_request 전체 HTTP 요청 원본 버퍼
 * @return User-Agent 문자열 (동적 할당됨, 사용 후 free 필요) 또는 "N/A" (실패 시).
 * [수정] User-Agent를 찾지 못하면 "N/A" 대신 NULL을 반환하여 JSON에 추가되지 않도록 함.
 */
static char* get_user_agent_from_raw(const char* raw_request) {
    if (!raw_request) return NULL;

    const char* header_key = "User-Agent: ";
    const char* start = strstr(raw_request, header_key);

    if (!start) {
        // 대소문자 구분 없이 재시도 (U'u'ser-Agent)
        start = strcasestr(raw_request, header_key);
    }

    if (!start) return NULL;

    start += strlen(header_key); // "User-Agent: " 다음 위치로 포인터 이동

    // 값의 끝(다음 \r\n)을 찾음
    const char* end = strstr(start, "\r\n");
    if (!end) return NULL; // 헤더 형식이 잘못된 경우

    size_t length = end - start;
    char* user_agent = (char*)malloc(length + 1);
    if (!user_agent) return NULL;

    strncpy(user_agent, start, length);
    user_agent[length] = '\0';

    return user_agent;
}


// --- [수정] AI 모델이 요구하는 HTTP 컨텐츠 기반 로깅 함수 ---
void log_request(HttpRequest* request) {
    time_t now = time(NULL);
    struct tm* t = localtime(&now);
    char iso_time_str[64];
    strftime(iso_time_str, sizeof(iso_time_str), "%Y-%m-%dT%H:%M:%S%z", t);

    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    getpeername(request->client_socket, (struct sockaddr*)&addr, &addr_len);
    char* client_ip = inet_ntoa(addr.sin_addr);

    // [수정] AI 모델이 학습한 '컨텐츠' 기반 특성을 JSON에 추가
    cJSON* log_json = cJSON_CreateObject();
    
    // (참고) timestamp와 client_ip는 모델 학습에는 사용되지 않았지만,
    // 로깅 및 추적을 위해 여전히 유용하므로 포함합니다.
    cJSON_AddStringToObject(log_json, "timestamp", iso_time_str);
    cJSON_AddStringToObject(log_json, "client_ip", client_ip);

    // --- AI 모델 학습에 사용된 핵심 필드 ---
    
    // 1. request_method (모델 입력: categorical_features)
    if (request->method) {
        cJSON_AddStringToObject(log_json, "request_method", request->method);
    } else {
        cJSON_AddStringToObject(log_json, "request_method", "N/A");
    }

    // 2. request_path (모델 입력: numeric_features, rule features)
    if (request->path) {
        cJSON_AddStringToObject(log_json, "request_path", request->path);
    } else {
        cJSON_AddStringToObject(log_json, "request_path", "/");
    }

    // 3. http_version (모델 입력: categorical_features)
    if (request->version) {
        cJSON_AddStringToObject(log_json, "http_version", request->version);
    } else {
        cJSON_AddStringToObject(log_json, "http_version", "HTTP/1.1");
    }

    // 4. request_body (모델 입력: numeric_features, rule features, high_cardinality_features)
    if (request->body) {
        cJSON_AddStringToObject(log_json, "request_body", request->body);
    } else {
        cJSON_AddStringToObject(log_json, "request_body", ""); // 모델이 ""(빈 문자열)로 학습함
    }

    // 5. user_agent (모델 입력: high_cardinality_features)
    // raw_buffer에서 직접 파싱 시도
    char* user_agent = get_user_agent_from_raw(request->raw_buffer);
    if (user_agent) {
        cJSON_AddStringToObject(log_json, "user_agent", user_agent);
        free(user_agent); // 헬퍼 함수에서 할당된 메모리 해제
    } else {
        cJSON_AddStringToObject(log_json, "user_agent", "N/A"); // 찾지 못한 경우
    }

    // --- [삭제] 기존 네트워크 통계 정보 (AI 모델이 학습하지 않음) ---
    /*
    cJSON_AddNumberToObject(log_json, "flow duration", request->flow_duration);
    cJSON_AddNumberToObject(log_json, "total fwd packets", request->fwd_packets);
    cJSON_AddNumberToObject(log_json, "total backward packets", request->bwd_packets);
    cJSON_AddNumberToObject(log_json, "total length of fwd packets", request->fwd_bytes);
    cJSON_AddNumberToObject(log_json, "total length of bwd packets", request->bwd_bytes);
    
    double duration_sec = (request->flow_duration / 1000000.0) + 1e-6;
    cJSON_AddNumberToObject(log_json, "flow bytes/s", (request->fwd_bytes + request->bwd_bytes) / duration_sec);
    cJSON_AddNumberToObject(log_json, "flow packets/s", (request->fwd_packets + request->bwd_packets) / duration_sec);
    cJSON_AddNumberToObject(log_json, "packets per second", (request->fwd_packets + request->bwd_packets) / duration_sec);
    */
    // --- [삭제 완료] ---

    char* json_string = cJSON_PrintUnformatted(log_json);
    if (json_string) {
        // 1. 파일에 동기적으로 로그 기록 (Access Log)
        if (access_log_file) {
            fprintf(access_log_file, "%s\n", json_string);
            fflush(access_log_file);
        }
        
        // 2. 비동기 전송을 위해 큐에 푸시 (메인 스레드 블록킹 최소화)
        if (request->blocked_by_waf == 0) {
            char* log_to_send = malloc(strlen(json_string) + 2);
            strcpy(log_to_send, json_string);
            strcat(log_to_send, "\n");
            
            // 큐에 푸시하고 메모리 소유권 이전
            push_log_to_queue(log_to_send); 
        }
        
        free(json_string);
    }
    
    cJSON_Delete(log_json);
}

void cleanup_logger() {
    if (access_log_file) fclose(access_log_file);
    if (attack_log_file) fclose(attack_log_file);
}

