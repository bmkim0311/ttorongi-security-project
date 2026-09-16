# 또롱이 (Ttorongi) — 공공자전거 보안 프로젝트

공공자전거 웹 서비스를 직접 구축한 뒤 취약점을 재현하고, 애플리케이션·네트워크·보안 솔루션을 통해 보완한 후 **동일 공격을 다시 수행해 실제 차단 여부를 재검증**한 프로젝트입니다.

> 프로젝트 메시지: **만들고 → 공격하고 → 막고 → 다시 공격해 정말 막혔는지 확인한다.**

## 프로젝트 개요

- 사용자 서비스: 대여/반납, 회원·비회원 이용, QR 기반 대여, 결제/이용내역, 공지·문의
- 관리자 서비스: 사용자·대여소·자전거·대여·정비·결제·공지·문의·로그 관리
- 협력업체 서비스: 정비 작업, 자전거 재배치, 운영자료 내보내기
- DB: MariaDB 기반 서비스 데이터 분리 및 권한 적용
- 보안 구성: pfSense, Snort 3, ModSecurity WAF, Wazuh와 연계한 탐지·차단·로그 분석

## 서비스 구성

| 구분 | 기본 포트 | 역할 |
| --- | ---: | --- |
| USER | 5000 | 일반 사용자/비회원 공공자전거 서비스 |
| ADMIN | 6001 | 사원 및 관리자 접근 |
| PARTNER | 7000 | 협력업체 정비·재배치 업무 |

실습 환경은 가상머신과 사설망으로 구성했습니다. 저장소에 보이는 사설 IP와 테스트 계정 기본값은 해당 폐쇄형 실습 환경을 위한 값입니다.

## 보안 시나리오

| 시나리오 | 핵심 내용 | 주요 대응 |
| --- | --- | --- |
| A01 | 타 사용자 대여내역 조회/강제반납 등 Broken Access Control | Flask 권한 검증, WAF 보조 탐지, Wazuh 이벤트 연계 |
| A02 | 예측 가능한 QR/토큰 변조 및 재사용 | 랜덤 토큰, 대여소 검증, replay 차단, 탐지 로그 |
| A03 | 동일 자전거 동시 대여 Race Condition | DB 상태 검증 및 경쟁 구간 보완 |
| A04 | 운영자료 비인증 다운로드 | 애플리케이션 접근통제와 WAF/Snort 정책 적용 |
| A05 | 운영정보 변경 권한 및 감사로그 부족 | 역할 기반 권한과 감사 이벤트 기록 |

보완 전·후 비교에 필요한 대표 스냅샷은 [`security-scenarios/`](security-scenarios/)에 별도로 정리했습니다. 각 시나리오는 `vulnerable_snapshot.py`와 `secured_snapshot.py`로 통일했으며, 메인 서비스 코드는 A01~A05의 **보완 상태를 기준**으로 정리했습니다. 수십 개의 작업 중간 백업본은 저장소 가독성을 위해 제외했습니다.

## 프로젝트 구조

```text
.
├─ user/                 # 사용자 서비스
├─ admin/                # 관리자 서비스
├─ partner/              # 협력업체 서비스
├─ security-scenarios/   # 취약/보완 대표 스냅샷
├─ .gitignore
└─ requirements.txt
```

각 서비스의 `templates/`, `static/` 파일도 함께 포함되어 있어 기존 화면과 기능 구성을 유지합니다.

## 실행 준비

Python 3 환경에서 공통 의존성을 설치합니다.

```bash
python -m venv .venv
source .venv/bin/activate       # Linux/macOS
# .venv\Scripts\activate        # Windows
pip install -r requirements.txt
```

DB 접속정보는 각 서비스의 `.env.example`을 참고해 설정합니다. 실제 `.env` 파일은 Git에 포함하지 않습니다.

```bash
cp user/.env.example user/.env
cp admin/.env.example admin/.env
cp partner/.env.example partner/.env
```

세 서비스 모두 실행 시 각 디렉터리의 `.env`를 읽습니다. `.env`가 없거나 일부 값이 비어 있으면 기존 VM 실습 기본값을 사용하도록 구성되어 있습니다. `.env.example`에 적힌 계정과 사설 IP는 폐쇄형 가상머신 실습 환경에서만 사용한 값입니다.

서비스는 각각 별도 터미널에서 실행합니다.

```bash
# USER
cd user
python app.py

# ADMIN (별도 터미널)
cd admin
python app.py

# PARTNER (별도 터미널)
cd partner
python app.py
```

DB 스키마와 계정/권한은 기존 실습 MariaDB 구성을 전제로 합니다. 원본 과제 폴더에도 전체 MariaDB 초기 덤프는 포함되어 있지 않아, 이 저장소만으로 완전히 새로운 DB 환경을 처음부터 재구성하는 형태는 아닙니다. `partner/db_setup.sql`에는 협력업체 서비스에서 추가로 사용하는 테이블과 권한 설정이 포함되어 있습니다.

## 저장소 정리 원칙

포트폴리오 공개본에서는 기능과 화면에 필요한 코드는 유지하고 아래 항목만 제외했습니다.

- Python 가상환경과 `__pycache__`
- 작업 중 자동 생성된 대량의 `.before-*`, `.backup-*` 파일
- 실제 `.env` 파일
- 로컬 DB/로그/런타임 export 결과
- 중복 압축 백업본

따라서 현재 서비스 코드·템플릿·정적 자원과 보안 시나리오의 핵심 비교 자료는 유지하면서, GitHub에서 프로젝트 구조를 빠르게 파악할 수 있도록 정리했습니다.

## 담당 역할

팀장으로 USER·ADMIN·PARTNER 웹서비스를 구축하고, 웹·DB·보안 서버 간 전체 연동을 담당했습니다. 또한 연결 오류와 미동작 부분을 해결하며, 취약점 분석 → 보완 → 재검증 흐름으로 프로젝트를 진행했습니다.
