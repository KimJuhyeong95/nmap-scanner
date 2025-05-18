# SPDX-FileCopyrightText: © 2025 KimJuhyeong95 <bisyop@naver.com>
# SPDX-License-Identifier: MIT

#nmap, pip install requests 설치 필요
import subprocess
import os
from datetime import datetime
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor
import socket
import re
import requests

lock = threading.Lock()
scan_results = []

COLOR_RESET = "\033[0m"
COLOR_RED = "\033[91m"
COLOR_ORANGE = "\033[33m"
COLOR_YELLOW = "\033[93m"
COLOR_GREEN = "\033[92m"

def run_nmap(ip_or_domain, ports, args="-sS"):
    print(f"[+] {ip_or_domain}에 대한 스캔 시작!")
    command = ["nmap"] + args.split()
    if ports:
        command += ["-p", ports]
    command.append(ip_or_domain)

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print("[!] Nmap 실행 중 오류 발생:")
        print(e.stderr)
        return None

def save_output_to_file(content, filename="nmap_scan_result.txt"):
    with open(filename, "a", encoding="utf-8") as f:
        f.write(f"\nNmap Scan Result - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n")
        f.write(content)
    print(f"\n[✓] 결과가 '{filename}' 파일에 저장되었습니다.")

def extract_open_ports(nmap_output):
    open_ports = []
    lines = nmap_output.splitlines()
    for line in lines:
        if ("/tcp" in line or "/udp" in line) and "open" in line:
            open_ports.append(line.strip())
    return open_ports

def extract_services(nmap_output):
    services = []
    for line in nmap_output.splitlines():
        if re.search(r"\d+/(tcp|udp)\s+open\s+\S+", line):
            parts = line.split()
            if len(parts) >= 4:
                port = parts[0]
                service = parts[2]
                version_info = " ".join(parts[3:])
                services.append((port, service, version_info))
    return services

def extract_os_info(nmap_output):
    os_info = []
    capture = False
    for line in nmap_output.splitlines():
        if line.startswith("OS details:") or line.startswith("Aggressive OS guesses:"):
            os_info.append(line.strip())
            capture = True
        elif capture and line.strip() and not line.startswith("Network Distance:"):
            os_info.append(line.strip())
        elif capture and not line.strip():
            break
    return "\n".join(os_info) if os_info else "[*] OS 정보 없음 또는 탐지 실패"

def query_cve(vendor, product):
    try:
        url = f"https://cve.circl.lu/api/search/{vendor}/{product}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return response.json().get("data", [])
    except Exception as e:
        print(f"[!] CVE 조회 실패: {e}")
    return []

def get_cvss_color(score):
    try:
        score = float(score)
        if score >= 9.0:
            return COLOR_RED
        elif score >= 7.0:
            return COLOR_ORANGE
        elif score >= 4.0:
            return COLOR_YELLOW
        elif score > 0:
            return COLOR_GREEN
    except:
        pass
    return COLOR_RESET

def match_cves(services):
    cve_report = "\n[🛡️ 취약점 분석 결과]\n"
    for port, service, version in services:
        vendor = service.lower()
        product = service.lower()
        cves = query_cve(vendor, product)

        if cves:
            cve_report += f"\n📌 {port} - {service} ({version}) 관련 CVE:\n"
            for cve in cves[:5]:
                cve_id = cve.get("id", "")
                summary = cve.get("summary", "")[:100]
                cvss = cve.get("cvss", 0)
                color = get_cvss_color(cvss)
                cve_report += f"{color} - {cve_id} (CVSS: {cvss}): {summary}...{COLOR_RESET}\n"
        else:
            cve_report += f"\n📌 {port} - {service} ({version}): 관련 CVE 없음 또는 미확인\n"
    return cve_report

def validate_ports(port_input):
    if not port_input:
        return True  # 포트 생략 허용 (예: ARP Ping 등)
    if '-' in port_input:
        start, end = port_input.split('-')
        if not (start.isdigit() and end.isdigit()):
            return False
        return 0 <= int(start) <= 65535 and 0 <= int(end) <= 65535
    else:
        ports = port_input.split(',')
        for p in ports:
            if not p.strip().isdigit() or not (0 <= int(p.strip()) <= 65535):
                return False
        return True

def scan_target(target, ports, nmap_args="-sS"):
    try:
        socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[!] '{target}'는 유효한 도메인 또는 IP가 아닙니다.")
        return

    output = run_nmap(target, ports, nmap_args)
    if output:
        open_ports = extract_open_ports(output)
        result = f"\n[+] {target} - 열린 포트:\n" + "\n".join(open_ports) if open_ports else f"[!] {target} - 열린 포트 없음."

        if "-sV" in nmap_args:
            services = extract_services(output)
            cve_output = match_cves(services)
            result += cve_output

        if "-O" in nmap_args:
            os_info = extract_os_info(output)
            result += f"\n\n[🧠 OS 정보]\n{os_info}"

        with lock:
            scan_results.append(result)

def scan_multiple_targets(targets, ports, nmap_args="-sS"):
    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(lambda t: scan_target(t, ports, nmap_args), targets)
    return "\n".join(scan_results)

def main():
    print("SPDX-FileCopyrightText: © 2025 KimJuhyeong <bisyop@naver.com>")

    while True:
        target_input = input("스캔할 도메인/IP 또는 대역대 (콤마 구분 가능): ").strip()
        while True:
            ports = input("스캔할 포트 (예: 1-65535 또는 22,80,443, 생략 가능): ").strip()
            if validate_ports(ports):
                break
            print("[!] 유효하지 않은 포트 입력입니다. 0~65535 범위의 포트 번호를 입력하세요.")

        print("\n[!] 스캔 모드 선택:")
        print(" - fast      : 빠른 스캔 (-T4 -F)")
        print(" - service   : 서비스 버전 탐지 (-sS -sV)")
        print(" - full      : 전체 탐지 (-sS -sV -O -T4)")
        print(" - os        : OS 감지 전용 (-O)")
        print(" - udp       : UDP 포트 탐지 (-sU)")
        print(" - all       : TCP+UDP 병합 스캔 (-sS -sU)")
        print(" - pingless  : Ping 생략 (-Pn)")
        print(" - arp       : ARP ping 사용 (-PR)")
        mode = input("모드 선택: ").strip().lower()

        nmap_args = ""
        if mode == "fast":
            nmap_args = "-T4 -F"
        elif mode == "service":
            nmap_args = "-sS -sV"
        elif mode == "full":
            nmap_args = "-sS -sV -O -T4"
        elif mode == "os":
            nmap_args = "-O"
        elif mode == "udp":
            nmap_args = "-sU"
        elif mode == "all":
            nmap_args = "-sS -sU"
        elif mode == "pingless":
            nmap_args = "-sS -Pn"
        elif mode == "arp":
            nmap_args = "-PR -sn"
        else:
            print("[!] 알 수 없는 모드입니다. 기본으로 빠른 스캔 진행.")
            nmap_args = "-T4 -F"

        target_list = []
        for part in target_input.split(','):
            part = part.strip()
            try:
                network = ipaddress.ip_network(part, strict=False)
                target_list.extend([str(ip) for ip in network.hosts()])
            except ValueError:
                target_list.append(part)

        output = scan_multiple_targets(target_list, ports, nmap_args)

        if output:
            print("\n[결과 요약 - 열린 포트 및 취약점]")
            print(output)
            save_output_to_file(output)

        again = input("\n계속하시겠습니까? (y/n): ").strip().lower()
        if again != "y":
            break

if __name__ == "__main__":
    main()