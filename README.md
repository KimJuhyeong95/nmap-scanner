# 🔍 Nmap 기반 멀티 타겟 취약점 스캐너
> Nmap을 기반으로 한 고급 보안 포트 스캐너 스크립트  
> TCP/UDP 스캔, OS 감지, 서비스 버전 탐지, CVE 자동 조회, ARP Ping 등 다양한 보안 진단 기능 포함

## ✅ 주요 기능
| 기능             | 설명 |
|------------------|------|
| ✅ TCP/UDP 포트 스캔 (`-sS`, `-sU`) | 빠르고 정확한 연결 포트 확인 |
| ✅ 서비스 및 버전 탐지 (`-sV`) | 포트에서 구동 중인 서비스 식별 |
| ✅ OS 감지 (`-O`) | 운영체제 종류 추정 |
| ✅ CVE 자동 조회 | 서비스 이름 기반 취약점(CVE) 검색 및 CVSS 색상 출력 |
| ✅ ARP/ICMP Ping 스캔 | 네트워크에서 활성 호스트 탐지 |
| ✅ Ping 생략 스캔 (`-Pn`) | 방화벽 우회용 탐지 |
| ✅ CIDR 대역 입력 가능 | 예: `192.168.0.0/24` 입력 시 자동 확장 |
| ✅ 결과 로그 자동 저장 | 매번 결과 파일(`nmap_scan_result.txt`)에 누적 저장 |
| ✅ 멀티스레드 스캔 | 최대 10개 타겟 동시 스캔으로 빠른 성능 |

## 📦 설치 방법
1. **Python 설치**
   - Python 3.7 이상 필요
2. **필수 모듈 설치**
pip install requests
3. nmap 설치
Linux: sudo apt install nmap
macOS: brew install nmap
Windows: nmap 공식 사이트에서 설치 후 환경변수 등록

## 📦 사용 방법
입력 예시:
스캔할 도메인/IP 또는 대역대 (콤마 구분 가능): 192.168.1.1,nmap.org,192.168.1.0/24
스캔할 포트 (예: 1-65535 또는 22,80,443): 22,80,443,1-65535
스캔 모드 선택 (fast / service / full): service

## 📦 지원 스캔 모드
모드 이름	      Nmap 옵션	      설명
fast	      -T4 -F	      빠른 포트 스캔
service	      -sS -sV	      서비스 버전 포함 TCP 스캔
full	    -sS -sV -O -T4	  서비스 + OS 감지 전체 스캔
os	            -O	          OS 감지 전용
udp	            -sU	          UDP 전용 스캔
all	          -sS -sU	      TCP+UDP 혼합 스캔
pingless	  -sS -Pn	      Ping 생략 스캔 (방화벽 우회)
arp	          -PR -sn	      ARP Ping 스캔 (LAN 환경)

## 📝 License
This project is licensed under the MIT License - see the LICENSE.txt file for details.
Copyright (c) 2025 KimJuhyeong95
