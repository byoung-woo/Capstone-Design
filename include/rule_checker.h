// include/rule_checker.h
#ifndef RULE_CHECKER_H
#define RULE_CHECKER_H

#include "webserver.h"

// 요청에 공격 패턴이 있는지 확인하는 함수
// 공격이 탐지되면 1을, 아니면 0을 반환합니다.
int is_attack_detected(HttpRequest* request);

// JSON 파일에서 룰을 로드하는 함수
void load_rules_from_file(const char* filepath);

// 로드된 룰을 메모리에서 해제하는 함수
void cleanup_rules();

#endif