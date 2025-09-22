// include/rule_checker.h
#ifndef RULE_CHECKER_H
#define RULE_CHECKER_H

#include "webserver.h"

// 요청에 공격 패턴이 있는지 확인하는 함수
// 공격이 탐지되면 1을, 아니면 0을 반환합니다.
int is_attack_detected(HttpRequest* request);

#endif