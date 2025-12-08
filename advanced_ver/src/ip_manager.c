// src/ip_manager.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/stat.h> 
#include <unistd.h>  

#include "ip_manager.h" 
#include "logger.h"

// --- 자료구조 정의 ---

// 동적 차단(Graylist)용 노드
typedef struct DynamicIPNode {
    char ip[INET_ADDRSTRLEN];
    int request_count;
    time_t first_request_time;
    time_t blocked_until;
    struct DynamicIPNode* next;
} DynamicIPNode;

// 화이트리스트/블랙리스트용 노드
typedef struct StaticIPNode {
    char ip[INET_ADDRSTRLEN];
    struct StaticIPNode* next;
} StaticIPNode;


// --- 해시 테이블 및 전역 변수 ---
static StaticIPNode* whitelist_table[IP_TABLE_SIZE];
static StaticIPNode* blacklist_table[IP_TABLE_SIZE];
static DynamicIPNode* dynamic_block_table[IP_TABLE_SIZE];
static pthread_mutex_t ip_manager_mutex;

static time_t whitelist_last_mod_time = 0;
static time_t blacklist_last_mod_time = 0;
static volatile int keep_running = 1;


// --- 해시 함수 ---
static unsigned int hash_ip(const char* ip_str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *ip_str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash % IP_TABLE_SIZE;
}

// --- 메모리 해제 함수 ---
static void cleanup_static_list(StaticIPNode* table[]) {
    for (int i = 0; i < IP_TABLE_SIZE; i++) {
        StaticIPNode* current = table[i];
        while (current != NULL) {
            StaticIPNode* temp = current;
            current = current->next;
            free(temp);
        }
        table[i] = NULL;
    }
}

// --- 리스트 로딩 함수 ---
static void load_ip_list_from_file(const char* filepath, StaticIPNode* table[], time_t* last_mod_time) {
    struct stat file_stat;
    if (stat(filepath, &file_stat) != 0) {
        log_error("Could not stat IP list file.");
        return;
    }

    FILE* file = fopen(filepath, "r");
    if (!file) {
        log_error("Could not open IP list file.");
        return;
    }
    
    // 파일을 성공적으로 열었을 때만 리스트를 비움
    cleanup_static_list(table);

    char line[INET_ADDRSTRLEN];
    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\r\n")] = 0;
        unsigned int index = hash_ip(line);
        StaticIPNode* newNode = (StaticIPNode*)malloc(sizeof(StaticIPNode));
        strncpy(newNode->ip, line, INET_ADDRSTRLEN);
        newNode->next = table[index];
        table[index] = newNode;
    }
    fclose(file);
    *last_mod_time = file_stat.st_mtime;
}



// 동적 차단 리스트의 메모리를 해제하는 함수

static void cleanup_dynamic_list() {
    for (int i = 0; i < IP_TABLE_SIZE; i++) {
        DynamicIPNode* current = dynamic_block_table[i];
        while (current != NULL) {
            DynamicIPNode* temp = current;
            current = current->next;
            free(temp);
        }
    }
}

/**
 * @brief IP 관리 모듈을 초기화합니다.
 * @details 해시 테이블 초기화, 뮤텍스 생성, 초기 화이트리스트/블랙리스트 로드를 수행합니다.
 */

void init_ip_manager() {
    for (int i = 0; i < IP_TABLE_SIZE; i++) {
        whitelist_table[i] = NULL;
        blacklist_table[i] = NULL;
        dynamic_block_table[i] = NULL;
    }
    pthread_mutex_init(&ip_manager_mutex, NULL);
    load_ip_list_from_file("ip_whitelist.txt", whitelist_table, &whitelist_last_mod_time);
    load_ip_list_from_file("ip_blacklist.txt", blacklist_table, &blacklist_last_mod_time);
    log_error("IP manager initialized with initial lists.");
}

/**
 * @brief IP 관리 모듈 사용을 종료하고 자원을 해제합니다.
 */

void cleanup_ip_manager() {
    keep_running = 0;
    cleanup_static_list(whitelist_table);
    cleanup_static_list(blacklist_table);
    cleanup_dynamic_list();
    pthread_mutex_destroy(&ip_manager_mutex);
    log_error("IP manager cleaned up.");
}

/**
 * @brief 특정 IP의 보안 상태(차단 여부 등)를 확인합니다.
 * @details 
 * 1. 화이트리스트 확인 (통과)
 * 2. 블랙리스트 확인 (영구 차단)
 * 3. 동적 차단(Graylist) 확인 및 Rate Limiting 로직 적용
 * - 짧은 시간(TIME_WINDOW) 동안 과도한 요청(REQUEST_LIMIT) 발생 시 임시 차단
 * * @param ip_str 확인할 클라이언트 IP 주소
 * @return IPStatus (ALLOWED, WHITELISTED, BLACKLISTED, DYNAMICALLY_BLOCKED 등)
 */

IPStatus check_ip_status(const char* ip_str) {
    pthread_mutex_lock(&ip_manager_mutex); // 스레드 안전성 보장
    unsigned int index = hash_ip(ip_str);
    time_t now = time(NULL);
    
    // 1. 화이트리스트 검사
    StaticIPNode* wl_node = whitelist_table[index];
    while(wl_node) {
        if (strcmp(wl_node->ip, ip_str) == 0) {
            pthread_mutex_unlock(&ip_manager_mutex);
            return IP_WHITELISTED;
        }
        wl_node = wl_node->next;
    }

    // 2. 블랙리스트 검사
    StaticIPNode* bl_node = blacklist_table[index];
    while(bl_node) {
        if (strcmp(bl_node->ip, ip_str) == 0) {
            pthread_mutex_unlock(&ip_manager_mutex);
            return IP_BLACKLISTED;
        }
        bl_node = bl_node->next;
    }

    // 3. 동적 차단 및 Rate Limiting 검사
    DynamicIPNode* dyn_node = dynamic_block_table[index];
    while (dyn_node != NULL && strcmp(dyn_node->ip, ip_str) != 0) {
        dyn_node = dyn_node->next;
    }

    if (dyn_node == NULL) {
        // 새로운 접속 IP인 경우 노드 생성
        dyn_node = (DynamicIPNode*)malloc(sizeof(DynamicIPNode));
        strncpy(dyn_node->ip, ip_str, INET_ADDRSTRLEN);
        dyn_node->request_count = 1;
        dyn_node->first_request_time = now;
        dyn_node->blocked_until = 0;
        dyn_node->next = dynamic_block_table[index];
        dynamic_block_table[index] = dyn_node;
    } else {
        // 기존 접속 IP인 경우

        // 이미 차단된 상태인지 확인
        if (dyn_node->blocked_until > now) {
            pthread_mutex_unlock(&ip_manager_mutex);
            return IP_DYNAMICALLY_BLOCKED;
        }

        // 시간 윈도우가 지났으면 카운트 초기화
        if (now - dyn_node->first_request_time > TIME_WINDOW_SECONDS) {
            dyn_node->request_count = 1;
            dyn_node->first_request_time = now;
        } else {
            dyn_node->request_count++;
        }

        // 요청 제한 초과 시 차단 설정
        if (dyn_node->request_count > REQUEST_LIMIT) {
            dyn_node->blocked_until = now + BLOCK_DURATION_SECONDS;
            pthread_mutex_unlock(&ip_manager_mutex);
            return IP_DYNAMICALLY_BLOCKED;
        }
    }

    pthread_mutex_unlock(&ip_manager_mutex);
    return IP_ALLOWED;
}

/**
 * @brief WAF 등 외부 요인에 의해 IP를 즉시 동적으로 차단합니다.
 * @param ip_str 차단할 IP 주소
 */
void block_ip_dynamically(const char* ip_str) {
    pthread_mutex_lock(&ip_manager_mutex);
    unsigned int index = hash_ip(ip_str);
    DynamicIPNode* node = dynamic_block_table[index];
    time_t now = time(NULL);

    // 해당 IP 노드 찾기
    while (node != NULL && strcmp(node->ip, ip_str) != 0) {
        node = node->next;
    }

    // 노드가 있으면 차단 시간 설정 (노드가 없으면 무시하거나 새로 생성할 수 있음)
    if (node != NULL) {
        node->blocked_until = now + BLOCK_DURATION_SECONDS;
    }
    pthread_mutex_unlock(&ip_manager_mutex);
}

/**
 * @brief 관리자에 의해 특정 IP의 차단을 즉시 해제합니다.
 * @param ip_str 차단 해제할 IP 주소
 */

void unblock_ip(const char* ip_str) {
    pthread_mutex_lock(&ip_manager_mutex);
    unsigned int index = hash_ip(ip_str);
    DynamicIPNode* node = dynamic_block_table[index];
    while (node != NULL && strcmp(node->ip, ip_str) != 0) {
        node = node->next;
    }
    if (node != NULL) {
        node->blocked_until = 0;
        node->request_count = 0;
        char log_msg[128];
        snprintf(log_msg, sizeof(log_msg), "[IP UNBLOCKED] client_ip=\"%s\" has been manually unblocked.", ip_str);
        log_error(log_msg);
    }
    pthread_mutex_unlock(&ip_manager_mutex);
}


/**
 * @brief 설정 파일(Whitelist/Blacklist) 변경을 감시하는 백그라운드 스레드 함수
 * @details 주기적으로 파일의 수정 시간(mtime)을 확인하여 변경 시 리스트를 리로드합니다.
 * @param arg 스레드 인자 (사용하지 않음)
 */
void* ip_list_monitor_thread(void* arg) {
    while (keep_running) {
        sleep(FILE_CHECK_INTERVAL_SECONDS); // 주기적 대기
        
        struct stat file_stat;
        
        // Whitelist 파일 감시
        if (stat("ip_whitelist.txt", &file_stat) == 0) {
            if (file_stat.st_mtime != whitelist_last_mod_time) {
                log_error("Whitelist file has changed. Reloading...");
                pthread_mutex_lock(&ip_manager_mutex);
                load_ip_list_from_file("ip_whitelist.txt", whitelist_table, &whitelist_last_mod_time);
                pthread_mutex_unlock(&ip_manager_mutex);
                log_error("Whitelist reloaded.");
            }
        }
        // Blacklist 파일 감시
        if (stat("ip_blacklist.txt", &file_stat) == 0) {
            if (file_stat.st_mtime != blacklist_last_mod_time) {
                log_error("Blacklist file has changed. Reloading...");
                pthread_mutex_lock(&ip_manager_mutex);
                load_ip_list_from_file("ip_blacklist.txt", blacklist_table, &blacklist_last_mod_time);
                pthread_mutex_unlock(&ip_manager_mutex);
                log_error("Blacklist reloaded.");
            }
        }
    }
    return NULL;
}