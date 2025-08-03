#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ARP Spoofing Detection and Prevention Tool
Korean Windows Environment Support
"""

import os
import sys
import subprocess
import re
import json
import logging
from datetime import datetime
from typing import List, Dict, Tuple, Optional

class ARPSecurityTool:
    def __init__(self):
        self.setup_logging()
        self.arp_table: List[Dict[str, str]] = []
        self.interfaces: List[str] = []
        
    def setup_logging(self):
        """로깅 설정"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('arp_security.log', encoding='utf-8'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def check_admin_privileges(self) -> bool:
        """관리자 권한 확인"""
        try:
            return os.getuid() == 0
        except AttributeError:
            # Windows
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
            
    def run_command(self, command: str) -> Tuple[int, str]:
        """명령어 실행 (안전하게)"""
        try:
            result = subprocess.run(
                command, 
                shell=True, 
                capture_output=True, 
                text=True, 
                encoding='utf-8',
                timeout=30
            )
            return result.returncode, result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            self.logger.error(f"명령어 실행 시간 초과: {command}")
            return -1, "Command timeout"
        except Exception as e:
            self.logger.error(f"명령어 실행 오류: {command}, 오류: {str(e)}")
            return -1, str(e)
            
    def parse_arp_table(self) -> bool:
        """ARP 테이블 파싱 (개선된 버전)"""
        try:
            exit_code, output = self.run_command('arp -a')
            if exit_code != 0:
                self.logger.error("ARP 테이블을 가져오는데 실패했습니다.")
                return False
                
            self.arp_table = []
            lines = output.split('\n')
            
            for line in lines:
                line = line.strip()
                if not line or 'Interface' in line or '인터페이스' in line:
                    continue
                    
                # IP, MAC, Type 패턴 매칭
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\S+)', line)
                if match:
                    ip, mac, arp_type = match.groups()
                    self.arp_table.append({
                        'ip': ip,
                        'mac': mac.lower().replace('-', ':'),
                        'type': arp_type
                    })
                    
            self.logger.info(f"ARP 엔트리 {len(self.arp_table)}개를 파싱했습니다.")
            return True
            
        except Exception as e:
            self.logger.error(f"ARP 테이블 파싱 오류: {str(e)}")
            return False
            
    def get_network_interfaces(self) -> bool:
        """네트워크 인터페이스 목록 가져오기"""
        try:
            exit_code, output = self.run_command('netsh interface show interface')
            if exit_code != 0:
                self.logger.error("네트워크 인터페이스 정보를 가져오는데 실패했습니다.")
                return False
                
            self.interfaces = []
            lines = output.split('\n')
            
            for line in lines:
                line = line.strip()
                # "연결됨" 또는 "Connected" 상태의 인터페이스만 추출
                if '연결됨' in line or 'Connected' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        interface_name = ' '.join(parts[3:])
                        self.interfaces.append(interface_name)
                        
            self.logger.info(f"활성 네트워크 인터페이스 {len(self.interfaces)}개를 찾았습니다.")
            return True
            
        except Exception as e:
            self.logger.error(f"네트워크 인터페이스 조회 오류: {str(e)}")
            return False
            
    def detect_arp_spoofing(self) -> Tuple[bool, List[str]]:
        """ARP 스푸핑 탐지 (개선된 알고리즘)"""
        mac_to_ips = {}
        suspicious_entries = []
        
        for entry in self.arp_table:
            mac = entry['mac']
            ip = entry['ip']
            
            if mac not in mac_to_ips:
                mac_to_ips[mac] = []
            mac_to_ips[mac].append(ip)
            
        # 동일한 MAC 주소에 여러 IP가 매핑된 경우 검사
        for mac, ips in mac_to_ips.items():
            if len(ips) > 1:
                # 브로드캐스트 MAC 주소나 멀티캐스트는 제외
                if mac == 'ff:ff:ff:ff:ff:ff' or mac.startswith('01:00:5e'):
                    continue
                    
                suspicious_entries.append(f"MAC {mac}이(가) 여러 IP에 매핑됨: {', '.join(ips)}")
                
        return len(suspicious_entries) > 0, suspicious_entries
        
    def flush_arp_table(self) -> bool:
        """ARP 테이블 초기화"""
        try:
            exit_code, output = self.run_command('arp -d *')
            if exit_code == 0:
                self.logger.info("ARP 테이블이 성공적으로 초기화되었습니다.")
                return True
            else:
                self.logger.error(f"ARP 테이블 초기화 실패: {output}")
                return False
        except Exception as e:
            self.logger.error(f"ARP 테이블 초기화 오류: {str(e)}")
            return False
            
    def set_static_arp_entries(self) -> bool:
        """동적 ARP 엔트리를 정적으로 변경"""
        if not self.interfaces:
            self.logger.error("네트워크 인터페이스 정보가 없습니다.")
            return False
            
        success_count = 0
        total_count = 0
        
        for entry in self.arp_table:
            if entry['type'].lower() in ['동적', 'dynamic']:
                total_count += 1
                ip = entry['ip']
                mac = entry['mac'].replace(':', '-')  # Windows 형식으로 변환
                
                # 첫 번째 활성 인터페이스에 시도
                if self.interfaces:
                    interface = self.interfaces[0]
                    command = f'netsh interface ipv4 add neighbors "{interface}" {ip} {mac}'
                    exit_code, output = self.run_command(command)
                    
                    if exit_code == 0:
                        success_count += 1
                        self.logger.info(f"정적 ARP 엔트리 추가 성공: {ip} -> {mac}")
                    else:
                        self.logger.warning(f"정적 ARP 엔트리 추가 실패: {ip} -> {mac}, 오류: {output}")
                        
        if total_count == 0:
            self.logger.info("동적 ARP 엔트리가 없습니다.")
            return True
        else:
            self.logger.info(f"정적 ARP 엔트리 설정 완료: {success_count}/{total_count}")
            return success_count > 0
            
    def save_arp_snapshot(self, filename: str = None) -> bool:
        """현재 ARP 테이블 스냅샷 저장"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"arp_snapshot_{timestamp}.json"
            
        try:
            snapshot = {
                'timestamp': datetime.now().isoformat(),
                'arp_table': self.arp_table,
                'interfaces': self.interfaces
            }
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(snapshot, f, ensure_ascii=False, indent=2)
                
            self.logger.info(f"ARP 스냅샷이 저장되었습니다: {filename}")
            return True
            
        except Exception as e:
            self.logger.error(f"ARP 스냅샷 저장 오류: {str(e)}")
            return False
            
    def get_user_input(self, prompt: str) -> str:
        """사용자 입력 받기 (검증 포함)"""
        while True:
            try:
                response = input(prompt).strip().lower()
                if response in ['y', 'yes', 'n', 'no']:
                    return response
                else:
                    print("잘못된 입력입니다. 'y' 또는 'n'을 입력해주세요.")
            except KeyboardInterrupt:
                print("\n프로그램을 종료합니다.")
                sys.exit(0)
            except Exception as e:
                print(f"입력 오류: {str(e)}")
                
    def run(self):
        """메인 실행 함수"""
        print("=" * 60)
        print("ARP 스푸핑 탐지 및 방어 도구")
        print("=" * 60)
        
        # 관리자 권한 확인
        if not self.check_admin_privileges():
            print("경고: 이 프로그램은 관리자 권한으로 실행되어야 정상 작동합니다.")
            print("관리자 권한으로 다시 실행해주세요.")
            return
            
        # ARP 테이블 파싱
        print("ARP 테이블을 분석 중입니다...")
        if not self.parse_arp_table():
            print("ARP 테이블을 가져오는데 실패했습니다.")
            return
            
        # 네트워크 인터페이스 정보 수집
        print("네트워크 인터페이스 정보를 수집 중입니다...")
        self.get_network_interfaces()
        
        # ARP 스냅샷 저장
        self.save_arp_snapshot()
        
        # ARP 스푸핑 탐지
        is_spoofed, suspicious_entries = self.detect_arp_spoofing()
        
        if is_spoofed:
            print("\n⚠️  경고! ARP 스푸핑 공격이 감지되었습니다!")
            print("의심스러운 엔트리:")
            for entry in suspicious_entries:
                print(f"  - {entry}")
                
            response = self.get_user_input("\nARP 테이블을 초기화하시겠습니까? [y/n]: ")
            if response in ['y', 'yes']:
                if self.flush_arp_table():
                    print("✅ ARP 테이블이 성공적으로 초기화되었습니다.")
                else:
                    print("❌ ARP 테이블 초기화에 실패했습니다.")
            else:
                print("ARP 테이블을 초기화하지 않았습니다.")
                
        else:
            print("\n✅ ARP 스푸핑 공격이 감지되지 않았습니다.")
            print("동적 ARP 엔트리를 정적으로 설정하면 ARP 스푸핑을 예방할 수 있습니다.")
            
            response = self.get_user_input("동적 ARP 엔트리를 정적으로 설정하시겠습니까? [y/n]: ")
            if response in ['y', 'yes']:
                if self.set_static_arp_entries():
                    print("✅ ARP 엔트리가 정적으로 설정되었습니다.")
                else:
                    print("❌ 정적 ARP 엔트리 설정에 실패했습니다.")
            else:
                print("ARP 테이블 설정을 유지합니다.")
                
        print("\n프로그램이 완료되었습니다.")
        print(f"로그 파일: arp_security.log")

def main():
    try:
        tool = ARPSecurityTool()
        tool.run()
    except KeyboardInterrupt:
        print("\n사용자에 의해 프로그램이 중단되었습니다.")
    except Exception as e:
        print(f"예상치 못한 오류가 발생했습니다: {str(e)}")
        
if __name__ == "__main__":
    main()
