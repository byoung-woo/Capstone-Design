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

// 사용자 인증 함수
int authenticate_user(const char* username, const char* password) {
    char* sql;
    int rc;
    int authenticated = 0;
    sqlite3_stmt *stmt;

    // SQL Injection 방지를 위해 파라미터 바인딩 사용
    sql = "SELECT COUNT(*) FROM users WHERE username = ? AND password = ?;";

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        log_error("SQL prepare error.");
        return 0;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, password, -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        if (sqlite3_column_int(stmt, 0) > 0) {
            authenticated = 1;
        }
    }

    sqlite3_finalize(stmt);
    return authenticated;
}

// 새로운 사용자를 데이터베이스에 삽입하는 함수
int insert_user(const char* username, const char* password) {
    const char* sql = "INSERT INTO users (username, password) VALUES (?, ?);";
    sqlite3_stmt* stmt;
    int rc;

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        log_error("SQL prepare error for user insertion.");
        return 0;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, password, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        log_error("SQL step error during user insertion.");
        sqlite3_finalize(stmt);
        return 0; // 삽입 실패
    }

    sqlite3_finalize(stmt);
    return 1; // 삽입 성공
}
