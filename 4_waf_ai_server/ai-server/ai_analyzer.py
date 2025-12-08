# ai_analyzer.py 
import socket
import json
import requests
import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow import keras
from joblib import load
from urllib.parse import unquote_plus
import os
import re
import math
import ssl
import warnings
import gc

# --- 0. 경고 메시지 무시 설정 ---
warnings.filterwarnings('ignore', category=UserWarning)

# --- 1. 설정부  ---
HOST = '0.0.0.0'
PORT = 5140

# --- 경로 설정 주의!!! ---
MODEL_PATH = './autoencoder_final.keras'
PREPROCESSOR_PATH = './preprocessor_final.joblib'
HASHER_PATH = './hasher_final.joblib'
COLUMNS_PATH = './feature_columns_final.joblib'
# ------------------------------------
SLACK_TEMPLATE_PATH = './templates/ai_alert.json'
CONFIG_PATH = './config.json'

# --- 임계값 설정 (노트북 결과값으로 변경 필요) ---
THRESHOLD = 1.3 

# --- 슬랙 웹훅 URL 로드 ---
try:
    with open(CONFIG_PATH, 'r') as f:
        config = json.load(f)
        SLACK_WEBHOOK_URL = config.get("SLACK_WEBHOOK_URL")
    if not SLACK_WEBHOOK_URL:
        print("⚠️ 경고: config.json 파일에 SLACK_WEBHOOK_URL이 비어있습니다.")
    else:
        print("✅ config.json에서 슬랙 웹훅 URL을 성공적으로 로드했습니다.")
except FileNotFoundError:
    SLACK_WEBHOOK_URL = None
    print(f"⚠️ 경고: '{CONFIG_PATH}' 파일을 찾을 수 없습니다.")
except json.JSONDecodeError:
    SLACK_WEBHOOK_URL = None
    print(f"⚠️ 경고: '{CONFIG_PATH}' 파일의 형식이 잘못되었습니다.")

# --- 2. 모델 및 전처리기 로드 ---
try:
    model = keras.models.load_model(MODEL_PATH)
    preprocessor = load(PREPROCESSOR_PATH)
    hasher = load(HASHER_PATH)
    feature_columns = load(COLUMNS_PATH)
    with open(SLACK_TEMPLATE_PATH, 'r') as f:
        SLACK_TEMPLATE = json.load(f)
    print("✅ AI 모델, 전처리기, 해셔, 컬럼 정보, 슬랙 템플릿을 성공적으로 로드했습니다.")
except Exception as e:
    print(f"❌ 필수 파일 로드 중 오류 발생: {e}")
    exit()

# --- 3. 데이터 전처리 함수 ---
def calculate_entropy(text):
    if pd.isna(text) or text == '': return 0.0
    text = str(text);
    if not text: return 0.0
    probabilities = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum([p * math.log2(p) for p in probabilities]) if probabilities else 0.0

def avg_segment_length(path):
    segments = str(path).split('/')
    if not segments or all(s == '' for s in segments): return 0
    return np.mean([len(s) for s in segments if s])

def create_features_from_log(log_data):
    df = pd.DataFrame([log_data])

    # C 서버 로그에서 'bytes' 키가 오더라도 무시하고 사용하지 않음
    
    # 기본 특성 추출 ('request_path_length', 'request_body_length'가 중요)
    df['request_path'] = df.get('request_path', '')
    df['request_body'] = df.get('request_body', '')
    
    df['request_path_length'] = df['request_path'].str.len()
    df['request_path_special_chars'] = df['request_path'].str.count(r'[^\w\s]')
    df['request_path_entropy'] = df['request_path'].apply(calculate_entropy)
    df['request_body_length'] = df['request_body'].str.len()
    df['request_body_special_chars'] = df['request_body'].str.count(r'[^\w\s]')
    df['request_body_entropy'] = df['request_body'].apply(calculate_entropy)

    # 경로 독립적 특성
    df['path_depth'] = df['request_path'].str.count('/').fillna(0)
    df['path_avg_segment_length'] = df['request_path'].apply(avg_segment_length).fillna(0)
    df['path_has_extension'] = df['request_path'].str.contains(r'\.\w{2,4}$', regex=True).astype(int)

    # 공격 패턴 특성 및 가중치 부여
    weight = 10
    df['request_path_has_sql'] = df['request_path'].str.contains(r"(?:'|--|#|;|\b(?:or|UNION|SELECT|INSERT|UPDATE|DELETE|FROM)\b)", regex=True, case=False).astype(int) * weight
    df['request_path_has_xss'] = df['request_path'].str.contains(r"<script|javascript:|onerror|onload|<iframe|<img", regex=True, case=False).astype(int) * weight
    df['request_body_has_sql'] = df['request_body'].str.contains(r"(?:'|--|#|;|\b(?:or|UNION|SELECT|INSERT|UPDATE|DELETE|FROM)\b)", regex=True, case=False).astype(int) * weight
    df['request_body_has_xss'] = df['request_body'].str.contains(r"<script|javascript:|onerror|onload|<iframe|<img", regex=True, case=False).astype(int) * weight
    
    return df

def preprocess_log(log_data):
    try:
        feature_df = create_features_from_log(log_data)
        
        # 학습에 사용된 컬럼 정의 (bytes 제외)
        numerical_features = ['request_path_length', 'request_path_special_chars', 'request_path_entropy', 
                              'request_body_length', 'request_body_special_chars', 'request_body_entropy', 'path_depth', 
                              'path_avg_segment_length', 'path_has_extension', 'request_path_has_sql', 
                              'request_path_has_xss', 'request_body_has_sql', 'request_body_has_xss']
        low_cardinality_categorical_features = ['request_method', 'http_version']
        high_cardinality_categorical_features = ['user_agent']

        # 전처리기 적용
        processed_other = preprocessor.transform(feature_df[numerical_features + low_cardinality_categorical_features])
        hashed_features = hasher.transform(feature_df[high_cardinality_categorical_features].to_dict('records'))

        # 데이터 합치기
        final_features = np.concatenate([processed_other.toarray() if hasattr(processed_other, "toarray") else processed_other, 
                                           hashed_features.toarray() if hasattr(hashed_features, "toarray") else hashed_features], axis=1)

        # 최종 데이터프레임 생성 및 순서 맞추기
        final_df = pd.DataFrame(final_features, columns=feature_columns)
        
        return final_df

    except Exception as e:
        print(f"--- 🚨 전처리 함수 오류 ---"); print(f"오류 내용: {e}"); return None

# === [헬퍼] 등급/색상/액션/타임스탬프/패턴 요약 ===
from datetime import datetime, timezone, timedelta

def now_kst_str():
    kst = timezone(timedelta(hours=9))
    return datetime.now(kst).strftime("%Y-%m-%d %H:%M:%S KST")

def to_level(score: float) -> str:
    # score는 MSE. 표시용 등급 경계(임계값 기반)
    if score >= THRESHOLD * 3.0:
        return "High"
    if score >= THRESHOLD * 1.5:
        return "Medium"
    return "Low"

def to_color(level: str) -> str:
    return {"High": "#DC143C", "Medium": "#FFA500", "Low": "#2E8B57"}.get(level, "#2E8B57")

def normalize_score(mse: float) -> float:
    # 0~1 범위로 보기 좋게 정규화
    upper = THRESHOLD * 3.0
    return max(0.0, min(1.0, mse / upper))

def decide_action(level: str) -> str:
    if level == "High":
        return "Alert Sent (Admin Check Required)"
    if level == "Medium":
        return "Alert Sent (Admin Check Required)"
    return "Alert Sent (Admin Check Required)"

def pick_detected_in(log_data: dict) -> str:
    body = (log_data.get("request_body") or "")
    path = (log_data.get("request_path") or "")
    if body.strip():
        return "BODY"
    if "?" in path:
        return "QUERY"
    return "PATH"

def infer_attack_type(log_data: dict) -> str:
    path = (log_data.get("request_path") or "")
    body = (log_data.get("request_body") or "")
    blob = path + body
    sqli = re.search(r"(?:'|--|#|;|/\*|\*/|\b(?:or|UNION|SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b)", blob, re.I)
    xss  = re.search(r"(?:<script|javascript:|onerror|onload|<iframe|<img)", blob, re.I)
    if sqli and xss:
        return "Hybrid (SQLi/XSS-like)"
    if sqli:
        return "SQL Injection (Encoded/Obfuscated)"
    if xss:
        return "XSS (Obfuscated)"
    return "Anomalous Request"

def summarize_pattern(log_data: dict, mse: float) -> str:
    parts = []
    path = (log_data.get("request_path") or "")
    body = (log_data.get("request_body") or "")
    if len(path) > 128: parts.append("path_len>128")
    if len(body) > 256: parts.append("body_len>256")
    if re.search(r"[^\w\s]{8,}", path + body): parts.append("symbols_dense")
    if re.search(r"(?:'|--|#|;|\bUNION\b|\bSELECT\b)", path + body, re.I): parts.append("sqli_tokens")
    if re.search(r"(?:<script|javascript:|onerror|onload)", path + body, re.I): parts.append("xss_tokens")
    if mse > THRESHOLD: parts.append("recon_error↑")
    return ", ".join(parts) if parts else "--"

def real_client_ip(log_data: dict) -> str:
    xff = (log_data.get("x_forwarded_for") or log_data.get("X-Forwarded-For") or "").strip()
    if xff:
        return xff.split(",")[0].strip()
    cip = (log_data.get("client_ip") or "").strip()
    return cip if cip else "N/A"

# --- 4. 슬랙 알림 함수 ---
def send_slack_notification(log_data, mse):
    if not SLACK_WEBHOOK_URL:
        return
    try:
        level = to_level(mse)
        color = to_color(level)
        norm  = normalize_score(mse)                
        risk_score_str = f"{norm:.2f}"

        attack_type = infer_attack_type(log_data)
        detected_in = pick_detected_in(log_data)
        pattern     = summarize_pattern(log_data, mse)

        # 추천 문구
        if level == "High":
            recommendation = "해당 IP의 추가 로그를 확인하고, 공격이 지속될 경우 방화벽에서 IP를 차단하는 것을 고려하세요."
        elif level == "Medium":
            recommendation = "요청 전체 로그를 검토하여 정상 사용자 행위인지 확인하세요. 반복 시 차단 정책 적용을 검토하세요."
        else:
            recommendation = "참고용 알림입니다. 이상 징후가 반복되는지 모니터링하세요."

        action_taken = decide_action(level)

        # 치환
        payload = json.dumps(SLACK_TEMPLATE)
        payload = (payload
            .replace("($color)", color)
            .replace("($ip)", real_client_ip(log_data))
            .replace("($path)", log_data.get("request_path", "N/A"))
            .replace("($attack_type)", attack_type)
            .replace("($detected_pattern)", pattern)
            .replace("($detected_in)", detected_in)
            .replace("($risk_level)", level)
            .replace("($risk_score)", risk_score_str)
            .replace("($action_taken)", action_taken)
            .replace("($recommendation)", recommendation)
            .replace("($timestamp)", now_kst_str()))
        final_payload = json.loads(payload)
        requests.post(SLACK_WEBHOOK_URL, json=final_payload, timeout=5)
    except Exception as e:
        print(f"슬랙 알림 처리 중 오류: {e}")

# --- 5. 로그 분석 함수 ---
def analyze_log(log_line):
    try:
        log_data = json.loads(log_line)
        print(f"\n[수신] IP: {log_data.get('client_ip')}, Path: {log_data.get('request_path')}")
        
        model_input = preprocess_log(log_data)
        if model_input is None: return
        
        reconstructed = model.predict(model_input, verbose=0)
        mse = np.mean(np.power(model_input.values - reconstructed, 2), axis=1)[0]
        
        print(f"  -> AI 분석 결과: 복원 오류(MSE) {mse:.6f} (임계값: {THRESHOLD})")
        if mse > THRESHOLD:
            print(f"  -> ★★★ 공격 의심! ★★★"); 
            send_slack_notification(log_data, mse)
        
        # 메모리 정리
        del log_data, model_input, reconstructed
        gc.collect()

    except Exception as e:
        print(f"--- 🚨 분석 중 오류 ---"); print(f"오류 내용: {e}")

# --- 6. 서버 실행 코드 ---
CERT_FILE = './certs/server.crt'
KEY_FILE = './certs/server.key'

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
try:
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    print("✅ SSL 인증서를 성공적으로 로드했습니다.")
except FileNotFoundError:
    print(f"❌ SSL 인증서 파일({CERT_FILE} 또는 {KEY_FILE})을 찾을 수 없습니다.")
    exit()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    with context.wrap_socket(s, server_side=True) as ssock:
        print(f"✅ AI 분석 서버가 시작되었습니다. {HOST}:{PORT}에서 '암호화된' 로그를 기다립니다...")
        buffer = ""
        while True:
            conn, addr = ssock.accept()
            with conn:
                print(f"\n🔗 C-WebServer({addr[0]})와 '암호화된' 연결이 수립되었습니다.")
                while True:
                    data = conn.recv(1024)
                    if not data:
                        print(f"🔗 C-WebServer({addr[0]})와 연결이 끊어졌습니다.")
                        break
                    buffer += data.decode('utf-8', errors='ignore')
                    while '\n' in buffer:
                        line, buffer = buffer.split('\n', 1)
                        if line:
                            analyze_log(line)

