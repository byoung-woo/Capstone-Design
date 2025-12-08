# 🧠 AI Log Analyzer (2nd Layer Defense)

## 📌 개요
이 모듈은 **C-WAF 웹 서버('4_waf_ai_server')**로부터 수신한 HTTP 요청 로그를 실시간으로 분석하는 **AI 기반 2차 방어 시스템**입니다.
**Autoencoder** 딥러닝 모델을 사용하여 정상 트래픽 패턴을 학습했으며, 이를 벗어나는 비정상(Anomaly) 요청을 탐지하여 관리자에게 알림을 보냅니다.

---

## 🛠️ 주요 기능
1. **실시간 로그 수신**: C 웹 서버와 SSL 소켓 통신을 통해 암호화된 로그를 수신합니다.  
2. **데이터 전처리**: 수신된 로그에서 Feature(URL 길이, 엔트로피, 특수문자 빈도 등)를 추출하고 벡터화합니다.  
3. **이상 탐지 (Anomaly Detection)**:  
   - 학습된 **Autoencoder** 모델을 통해 복원 오차(Reconstruction Error)를 계산합니다.  
   - 오차가 임계값(`THRESHOLD`)을 초과하면 공격으로 간주합니다.  
4. **Slack 알림**: 공격 탐지 시, 위험도(High/Medium/Low)와 공격 유형을 분석하여 Slack으로 경고를 전송합니다.

---

## 📂 디렉토리 구조
```plaintext
ai_engine/
├── ai_analyzer.py          # 메인 실행 파일 (AI 서버)
├── requirements.txt        # 필요 라이브러리 목록
├── config_example.json     # 설정 파일 예시 (Slack Webhook)
├── README.md               # 설명서 (현재 파일)
│
├── models/                 # 학습된 모델 및 전처리 객체
│   ├── autoencoder_final.keras
│   ├── preprocessor_final.joblib
│   ├── hasher_final.joblib
│   └── feature_columns_final.joblib
│
└── templates/              # Slack 알림 메시지 템플릿
    └── ai_alert.json
```

---

## ⚙️ 설치 및 설정 가이드

### 1️⃣ Python 환경 설정 및 라이브러리 설치
Python 3.8 이상 환경에서 다음 명령어를 실행하여 필수 패키지를 설치합니다.
```bash
cd ai_engine
pip install -r requirements.txt
```

### 2️⃣ 설정 파일 생성 (Slack 알림용)
`config_example.json` 파일을 복사하여 `config.json`을 생성하고, 본인의 Slack Webhook URL을 입력합니다.
```bash
cp config_example.json config.json
```

`config.json` 편집:
```json
{
  "SLACK_WEBHOOK_URL": "https://hooks.slack.com/services/T00000/B00000/XXXXXX"
}
```

> ⚠️ `config.json` 파일은 보안 정보가 포함되어 있으므로 Git에 업로드하지 마세요.  
> (`.gitignore`에 이미 추가되어 있음)

---

### 3️⃣ SSL 인증서 확인
이 서버는 C 웹 서버와 보안 통신을 하기 위해 상위 디렉토리의 인증서를 참조합니다.  
아래 경로에 인증서 파일이 존재하는지 확인하세요.

```bash
../certs/server.crt
../certs/server.key
```

---

## 🚀 실행 방법
C 웹 서버를 실행하기 전에 **AI 분석 서버**를 먼저 실행하여 대기 상태로 만듭니다.
```bash
# ai_engine 디렉토리 내부에서 실행
python ai_analyzer.py
```

**실행 성공 시 로그 예시:**
```plaintext
✅ AI 모델 및 리소스 로드 완료
✅ SSL 인증서를 성공적으로 로드했습니다.
✅ AI 분석 서버가 시작되었습니다. 0.0.0.0:5140에서 '암호화된' 로그를 기다립니다...
```

---

## 📊 모델 정보
- **알고리즘**: Autoencoder (Unsupervised Learning)  
- **학습 데이터**: CSIC 2010 Web Intrusion Dataset (Normal Traffic)  
- **탐지 원리**: 정상 데이터를 학습한 모델이 공격 데이터를 입력받으면, 복원 오차(MSE)가 커지는 원리를 이용합니다.  
- **임계값 (Threshold)**: 0.0479 (Precision-Recall Curve 기반 최적화)

---

## ⚠️ 문제 해결 (Troubleshooting)

**Q.** `FileNotFoundError: ... certs/server.crt` 오류가 발생합니다.  
**A.** `certs` 폴더가 `ai_engine`의 상위 폴더(`4_waf_ai_server`)에 있는지 확인하세요.  
인증서가 없다면 **OpenSSL** 명령어로 새로 생성해야 합니다.

**Q.** `ConnectionRefusedError`가 발생합니다.  
**A.** AI 서버(`ai_analyzer.py`)가 실행 중인지 확인하세요.  
C 웹 서버는 로그 전송 실패 시 에러를 기록하지만 동작은 중단되지 않습니다.

---

## 💡 팁
이 파일을 `ai_engine` 폴더에 넣어두면, 프로젝트를 보는 사람(또는 심사위원)이  
**"이 폴더는 어떤 역할을 하고, 어떻게 실행하는지"** 명확하게 이해할 수 있어  
프로젝트의 완성도와 전문성이 크게 향상됩니다.
