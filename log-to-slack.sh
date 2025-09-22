#!/bin/bash

# config.sh 파일을 읽어와서 그 안에 있는 WEBHOOK_URL 변수를 로드합니다.
source ./config.sh

# WEBHOOK_URL 변수가 비어있는지 확인 (config.sh 파일이 없거나 내용이 비었을 경우)
if [ -z "$WEBHOOK_URL" ]; then
    echo "오류: WEBHOOK_URL이 config.sh 파일에 설정되지 않았습니다."
    exit 1
fi

# 감시할 로그 파일
# LOG_FILE="/home/user/web-server1/webserver.log"
LOG_FILE="/home/user/web-server1/webserver_attack.log"

# 사용할 알림 템플릿 파일 경로
TEMPLATE_FILE="./templates/waf_alert.json"

echo "Start monitoring $LOG_FILE for attacks..."

# (이하 스크립트 내용은 이전과 동일합니다)
tail -fn0 "$LOG_FILE" | while read -r line ; do

  if [[ "$line" == *"[ATTACK DETECTED]"* ]]; then
    echo "Attack Detected! Sending notification to Slack..."

    CLIENT_IP=$(echo "$line" | sed -n 's/.*client_ip="\([^"]*\)".*/\1/p')
    REQUEST_PATH=$(echo "$line" | sed -n 's/.*request_path="\([^"]*\)".*/\1/p')
    DETECTED_RULE=$(echo "$line" | sed -n 's/.*rule="\([^"]*\)".*/\1/p')
    DETECTED_IN=$(echo "$line" | sed -n 's/.*location="\([^"]*\)".*/\1/p')
    TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

    RISK_LEVEL="🔴 High"
    ACTION_TAKEN="🛡️ Request Blocked (403 Forbidden)"
    RECOMMENDATION="해당 IP의 추가적인 로그를 확인하고, 공격이 지속될 경우 방화벽에서 IP를 차단하는 것을 고려하세요."

    JSON_PAYLOAD=$(jq -n \
      --arg ip "$CLIENT_IP" \
      --arg path "$REQUEST_PATH" \
      --arg detect_rule "$DETECTED_RULE" \
      --arg detect_in "$DETECTED_IN" \
      --arg risk "$RISK_LEVEL" \
      --arg action "$ACTION_TAKEN" \
      --arg recommend "$RECOMMENDATION" \
      --arg ts "$TIMESTAMP" \
      -f "$TEMPLATE_FILE")

    curl -X POST -H 'Content-type: application/json' --data "$JSON_PAYLOAD" "$WEBHOOK_URL"
    echo -e "\nNotification sent.\n"
  fi
done