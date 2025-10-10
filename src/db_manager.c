#include <stdio.h>
#include <sqlite3.h>
#include "db_manager.h"
#include "webserver.h" 
#include <openssl/rand.h> 
#include <openssl/evp.h>  
#include <string.h>      

#define SALT_LEN 16
#define HASH_LEN 64
#define PBKDF2_ITERATIONS 100000 // [수정] 4096 -> 100000으로 증가. 해싱 강도 강화.

// 데이터베이스 핸들러
static sqlite3 *db;

static int callback(void *NotUsed, int argc, char **argv, char **azColName) {
    // 이 예제에서는 사용하지 않음
    return 0;
}

// 데이터베이스 초기화 및 테이블 생성
void init_database() {
    int rc = sqlite3_open(DB_FILE, &db); // LOG_FILE 경로를 webserver.db로 변경

    if (rc) {
        log_error("Failed to open database.");
        return;
    } else {
        log_error("Database opened successfully.");
    }
    
    // users 테이블 생성 (ID, 사용자명, 암호화된 비밀번호, 역할)
    const char *sql = "CREATE TABLE IF NOT EXISTS users("
                      "ID INTEGER PRIMARY KEY AUTOINCREMENT,"
                      "username TEXT NOT NULL UNIQUE,"
                      "salt TEXT NOT NULL,"
                      "hashed_password TEXT NOT NULL,"
                      "role TEXT NOT NULL DEFAULT 'user');";
    
    char *err_msg = 0;
    rc = sqlite3_exec(db, sql, callback, 0, &err_msg);
    
    if (rc != SQLITE_OK) {
        log_error("SQL error on table creation.");
        sqlite3_free(err_msg);
    } else {
        log_error("Users table created successfully.");
    }

    // 데이터베이스 종료 (서버 실행 시에는 연결 유지)
    // sqlite3_close(db);
}

// 사용자 인증 함수
int authenticate_user(const char* username, const char* password) {
    sqlite3_stmt *stmt;
    char sql[] = "SELECT salt, hashed_password FROM users WHERE username = ?;";
    int authenticated = 0;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
        log_error("SQL prepare error for authentication.");
        return 0;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* salt_hex = sqlite3_column_text(stmt, 0);
        const unsigned char* stored_hash_hex = sqlite3_column_text(stmt, 1);

        unsigned char new_hash[HASH_LEN];
        // PBKDF2_HMAC_SHA256을 사용하여 입력된 비밀번호를 해싱
        PKCS5_PBKDF2_HMAC(password, strlen(password),
                          salt_hex, strlen((char*)salt_hex), PBKDF2_ITERATIONS, EVP_sha256(), // [수정] PBKDF2_ITERATIONS 사용
                          HASH_LEN, new_hash);
        
        // 생성된 해시를 16진수 문자열로 변환하여 비교
        char new_hash_hex[HASH_LEN * 2 + 1];
        for (int i = 0; i < HASH_LEN; i++) {
            sprintf(new_hash_hex + (i * 2), "%02x", new_hash[i]);
        }
        
        if (strcmp((char*)stored_hash_hex, new_hash_hex) == 0) {
            authenticated = 1; // 해시가 일치하면 인증 성공
        }
    }

    sqlite3_finalize(stmt);
    return authenticated;
}


int insert_user(const char* username, const char* password) {
    const char* sql = "INSERT INTO users (username, salt, hashed_password) VALUES (?, ?, ?);";
    sqlite3_stmt* stmt;
    
    // 1. 솔트 생성
    unsigned char salt[SALT_LEN];
    if (!RAND_bytes(salt, sizeof(salt))) {
        log_error("Failed to generate salt.");
        return 0;
    }
    char salt_hex[SALT_LEN * 2 + 1];
    for(int i = 0; i < SALT_LEN; i++) {
        sprintf(salt_hex + (i * 2), "%02x", salt[i]);
    }

    // 2. 비밀번호 해싱
    unsigned char hash[HASH_LEN];
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password), 
                           (unsigned char*)salt_hex, strlen(salt_hex), PBKDF2_ITERATIONS, EVP_sha256(), // [수정] PBKDF2_ITERATIONS 사용
                           HASH_LEN, hash)) {
        log_error("Failed to hash password.");
        return 0;
    }
    char hash_hex[HASH_LEN * 2 + 1];
    for (int i = 0; i < HASH_LEN; i++) {
        sprintf(hash_hex + (i * 2), "%02x", hash[i]);
    }

    // 3. 데이터베이스에 저장
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
        log_error("SQL prepare error for user insertion.");
        return 0;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, salt_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, hash_hex, -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        log_error("SQL step error during user insertion.");
        sqlite3_finalize(stmt);
        return 0;
    }

    sqlite3_finalize(stmt);
    return 1;
}
// 데이터베이스 연결을 닫고 자원을 정리하는 함수
// 데이터베이스 연결을 닫고 자원을 정리하는 함수
void cleanup_database() {
    if (db) {
        sqlite3_close(db);
        log_error("Database connection closed successfully.");
        db = NULL;
    }
}