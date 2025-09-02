#include <stdio.h>
#include <sqlite3.h>
#include "db_manager.h"
#include "webserver.h" // log_error 함수 사용을 위해 포함

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
                      "password TEXT NOT NULL,"
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