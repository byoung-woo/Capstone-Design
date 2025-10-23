// src/logger.c (TLS/SSL 암호화 적용 및 비동기 로깅)
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

// --- 메인 핸들링 함수 (비동기 로그 기록 및 파싱 최적화) ---


// [수정] 0으로 하드코딩된 불필요한 특성들을 모두 제거한 log_request 함수
void log_request(HttpRequest* request) {
    time_t now = time(NULL);
    struct tm* t = localtime(&now);
    char iso_time_str[64];
    strftime(iso_time_str, sizeof(iso_time_str), "%Y-%m-%dT%H:%M:%S%z", t);

    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    getpeername(request->client_socket, (struct sockaddr*)&addr, &addr_len);
    char* client_ip = inet_ntoa(addr.sin_addr);

    // [수정] C 서버가 '실제로' 계산하는 통계 정보만 JSON에 추가
    cJSON* log_json = cJSON_CreateObject();
    cJSON_AddStringToObject(log_json, "timestamp", iso_time_str);
    cJSON_AddStringToObject(log_json, "client_ip", client_ip);

    // --- 핵심 통계 정보 추가 ---
    // (AI 모델이 이 특성들만으로 재학습되어야 합니다)
    cJSON_AddNumberToObject(log_json, "flow duration", request->flow_duration);
    cJSON_AddNumberToObject(log_json, "total fwd packets", request->fwd_packets);
    cJSON_AddNumberToObject(log_json, "total backward packets", request->bwd_packets);
    cJSON_AddNumberToObject(log_json, "total length of fwd packets", request->fwd_bytes);
    cJSON_AddNumberToObject(log_json, "total length of bwd packets", request->bwd_bytes);
    
    // 1e-6은 0으로 나누는 것을 방지하기 위함
    double duration_sec = (request->flow_duration / 1000000.0) + 1e-6;
    cJSON_AddNumberToObject(log_json, "flow bytes/s", (request->fwd_bytes + request->bwd_bytes) / duration_sec);
    cJSON_AddNumberToObject(log_json, "flow packets/s", (request->fwd_packets + request->bwd_packets) / duration_sec);
    cJSON_AddNumberToObject(log_json, "packets per second", (request->fwd_packets + request->bwd_packets) / duration_sec);

    // (참고) HttpRequest 구조체에는 더 많은 정보가 있으나 (예: method, path),
    // 현재 AI 모델(CIC-IDS2017)은 이 통계 특성들만 사용합니다.
    // 만약 모델 학습에 method, path 등을 사용했다면 C 서버에서도 여기서 추가해야 합니다.
    // (예: cJSON_AddStringToObject(log_json, "request_method", request->method);)
    // (예: cJSON_AddStringToObject(log_json, "request_body", request->body ? request->body : "");)

    // --- [수정 완료] 0으로 하드코딩된 나머지 모든 특성들 삭제 ---
    // -----------------------------------------------------

    char* json_string = cJSON_PrintUnformatted(log_json);
    if (json_string) {
        // 1. 파일에 동기적으로 로그 기록 (Access Log)
        if (access_log_file) {
            fprintf(access_log_file, "%s\n", json_string);
            fflush(access_log_file);
        }
        
        // 2. 비동기 전송을 위해 큐에 푸시 (메인 스레드 블록킹 최소화)
        char* log_to_send = malloc(strlen(json_string) + 2);
        if (log_to_send) {
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