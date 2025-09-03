#ifndef DB_MANAGER_H
#define DB_MANAGER_H

// 데이터베이스를 초기화하고 users 테이블을 생성하는 함수
void init_database();
// 사용자 인증 함수
int authenticate_user(const char* username, const char* password);
#endif