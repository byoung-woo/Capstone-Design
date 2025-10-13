// include/ip_manager.h
#ifndef IP_MANAGER_H
#define IP_MANAGER_H

#include "webserver.h"
#include <pthread.h> // pthread 사용을 위해 추가

// --- 정책 설정 ---
#define IP_TABLE_SIZE 1024
#define REQUEST_LIMIT 20
#define TIME_WINDOW_SECONDS 5
#define BLOCK_DURATION_SECONDS 60
#define FILE_CHECK_INTERVAL_SECONDS 10 // 파일 변경 감지 주기 (10초)

// ... (IPStatus 열거형은 기존과 동일) ...
typedef enum {
    IP_ALLOWED,
    IP_WHITELISTED,
    IP_BLACKLISTED,
    IP_DYNAMICALLY_BLOCKED,
    IP_TEMP_BLOCKED_BY_WAF
} IPStatus;


// IP 관리 모듈 초기화
void init_ip_manager();

// IP 관리 모듈 자원 해제
void cleanup_ip_manager();

// IP의 상태를 종합적으로 확인하는 함수
IPStatus check_ip_status(const char* ip_str);

// WAF 룰 위반 시 IP를 동적으로 차단하는 함수
void block_ip_dynamically(const char* ip_str);

// 특정 IP의 차단을 즉시 해제하는 함수
void unblock_ip(const char* ip_str);

// 파일 변경을 감시하는 스레드 함수
void* ip_list_monitor_thread(void* arg);

#endif