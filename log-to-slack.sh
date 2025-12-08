#!/bin/bash

# config.sh 파일을 읽어와서 그 안에 있는 WEBHOOK_URL 변수를 로드합니다.
source ./config.sh

# WEBHOOK_URL 변수가 비어있는지 확인 (config.sh 파일이 없거나 내용이 비었을 경우)
if [ -z "$WEBHOOK_URL" ]; then
    echo "오류: WEBHOOK_URL이 config.sh 파일에 설정되지 않았습니다."
    exit 1
fi

# 감시할 로그 파일
LOG_FILE="./webserver_attack.log"

# 사용할 알림 템플릿 파일 경로
TEMPLATE_FILE="./templates/waf_alert.json"

echo "Start monitoring $LOG_FILE for attacks..."

# tail -fn0: 파일의 끝부분을 실시간으로 감시 (파일이 로테이트되어도 추적)
tail -fn0 "$LOG_FILE" | while read -r line ; do

  # [ATTACK DETECTED] 문자열이 포함된 라인을 감지
  if [[ "$line" == *"[ATTACK DETECTED]"* ]]; then
    echo "Attack Detected! Sending notification to Slack..."

    # sed를 사용하여 로그 라인에서 필요한 정보 추출
    CLIENT_IP=$(echo "$line" | sed -n 's/.*client_ip="\([^"]*\)".*/\1/p')
    REQUEST_PATH=$(echo "$line" | sed -n 's/.*request_path="\([^"]*\)".*/\1/p')
    
    # 공격 유형(attack_type)과 실제 패턴(rule)을 분리하여 파싱
    # C 코드(rule_checker.c)가 "attack_type="과 "rule="을 로그에 남기는 것을 활용
    DETECTED_RULE_NAME=$(echo "$line" | sed -n 's/.*attack_type="\([^"]*\)".*/\1/p')
    DETECTED_PATTERN=$(echo "$line" | sed -n 's/.*rule="\([^"]*\)".*/\1/p')
    
    DETECTED_IN=$(echo "$line" | sed -n 's/.*location="\([^"]*\)".*/\1/p')
    TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

    # Slack 메시지에 포함될 정적 텍스트
    RISK_LEVEL="🔴 High"
    
    # 실제 조치 사항(IP 임시 차단)을 명시
    # C 코드(router.c)가 block_ip_dynamically를 호출하는 것을 반영
    ACTION_TAKEN="🛡️ Request Blocked (403) + IP 60초 임시 차단 (Graylist)"
    RECOMMENDATION="해당 IP의 추가적인 로그를 확인하고, 공격이 지속될 경우 방화벽에서 IP를 차단하는 것을 고려하세요."

    # jq를 사용하여 JSON 페이로드를 생성
    # jq에 rule_name과 pattern 변수를 전달 (기존 detect_rule 제거)
    JSON_PAYLOAD=$(jq -n \
      --arg ip "$CLIENT_IP" \
      --arg path "$REQUEST_PATH" \
      --arg rule_name "$DETECTED_RULE_NAME" \
      --arg pattern "$DETECTED_PATTERN" \
      --arg detect_in "$DETECTED_IN" \
      --arg risk "$RISK_LEVEL" \
      --arg action "$ACTION_TAKEN" \
      --arg recommend "$RECOMMENDATION" \
      --arg ts "$TIMESTAMP" \
      -f "$TEMPLATE_FILE")

    # curl을 사용하여 Slack Webhook으로 JSON 전송
    curl -X POST -H 'Content-type: application/json' --data "$JSON_PAYLOAD" "$WEBHOOK_URL"
    echo -e "\nNotification sent.\n"
  fi
done