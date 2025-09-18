#!/bin/bash

# 슬랙 웹훅 URL을 여기에 붙여넣으세요.
WEBHOOK_URL="https://hooks.slack.com/services/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"

# Snort 로그 파일 경로
LOG_FILE="/var/log/snort/alert"

# Snort 로그를 실시간으로 감시하고 처리
tail -fn0 "$LOG_FILE" | while read -r line ; do
  # 로그가 경보의 시작([**]로 시작하는 줄)인지 확인
  if [[ "$line" == "[**]"* ]]; then
    
    # 경보의 첫 줄에서 SID와 메시지 추출
    SID=$(echo "$line" | awk -F'[][:]' '{print $3}')
    RULE_MSG=$(echo "$line" | awk -F'[][:]' '{print $5}' | xargs)
    
    # 경보의 나머지 줄을 읽어 하나의 메시지로 합치기
    ALERT_BODY="$line"
    while read -r next_line && [[ "$next_line" != "[**]"* ]] && [[ -n "$next_line" ]]; do
      ALERT_BODY+=$'\n'"$next_line"
    done
    
    # Snort 로그에서 IP와 타임스탬프 추출
    IP=$(echo "$ALERT_BODY" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
    TIMESTAMP=$(date -d "$(echo "$ALERT_BODY" | grep -oE '[0-9]{2}\/[0-9]{2}-[0-9]{2}:[0-9]{2}:[0-9]{2}')" +"%Y-%m-%d %H:%M:%S")

    # 경보 메시지 내용 (간단한 규칙의 경우 Rule Name 사용)
    DETECT_MSG="$RULE_MSG"
    
    # 예시 값 (Snort 로그에 포함되지 않으므로 임의로 설정)
    RISK_SCORE="0.91"
    ACTION_TAKEN="IP 10분 차단"
    STATUS_CODE="404"
    PATH_INFO="/SLACK_TEST_TRIGGER"

    # jq를 사용하여 복잡한 JSON 페이로드 생성
    JSON_PAYLOAD=$(jq -n \
      --arg ip "$IP" \
      --arg risk "$RISK_SCORE" \
      --arg path "$PATH_INFO" \
      --arg detect "$DETECT_MSG" \
      --arg action "$ACTION_TAKEN" \
      --arg status "$STATUS_CODE" \
      --arg ts "$TIMESTAMP" \
      --arg server "rpi-01" \
      '{
        "text": "[🚨 이상행위 탐지] 위험도: \($risk)",
        "blocks": [
          {
            "type": "header",
            "text": {"type": "plain_text","text": "🚨 이상행위 탐지 (임베디드 HTTPS 서버)"}
          },
          {
            "type": "section",
            "fields": [
              {"type": "mrkdwn","text": "*IP:*\n\($ip)"},
              {"type": "mrkdwn","text": "*위험도:*\n\($risk)"},
              {"type": "mrkdwn","text": "*경로:*\n\($path)"},
              {"type": "mrkdwn","text": "*탐지:*\n\($detect)"},
              {"type": "mrkdwn","text": "*조치:*\n\($action)"},
              {"type": "mrkdwn","text": "*상태코드:*\n\($status)"}
            ]
          },
          {
            "type": "context",
            "elements": [
              {"type": "mrkdwn","text": "ts=\($ts) KST • server=\($server)"}
            ]
          }
        ]
      }')

    # curl을 사용하여 슬랙 웹훅으로 전송
    curl -X POST -H 'Content-type: application/json' --data "$JSON_PAYLOAD" "$WEBHOOK_URL"
  fi
done