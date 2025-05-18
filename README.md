# 🔍 Nmap 기반 멀티 타겟 취약점 스캐너
이 도구는 Nmap을 기반으로 하는 Python 포트 스캐너로, **서비스 탐지**, **멀티 호스트 스캔**, **취약점(CVE) 정보 조회**, **결과 자동 저장** 기능을 포함합니다.

## ✅ 주요 기능

- Nmap을 통한 포트 스캔 (fast/service/full 모드)
- 도메인/IP 또는 CIDR 대역 스캔
- 서비스 버전 분석 및 CIRCL CVE API 기반 취약점 조회
- CVSS 점수 기반 색상 위험도 표시
- 결과 자동 파일 저장 (`output/nmap_scan_result.txt`)
- 병렬 스캔 (멀티스레딩)

## 📦 설치 방법
1. nmap 설치 (https://nmap.org/download.html)
2. requests 설치 (pip install requests)

## 📦 사용 방법
입력 예시:
스캔할 도메인/IP 또는 대역대 (콤마 구분 가능): 192.168.1.1,nmap.org,192.168.1.0/24
스캔할 포트 (예: 1-65535 또는 22,80,443): 22,80,443,1-65535
스캔 모드 선택 (fast / service / full): service

## 📝 License
This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.
Copyright (c) 2025 KimJuhyeong95