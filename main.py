import os
import subprocess

def get_arp_cache():
    try:
        output = subprocess.check_output('arp -a', shell=True, encoding='utf-8')
    except subprocess.CalledProcessError:
        return ''
    return output

def get_netsh_interfaces():
    try:
        output = subprocess.check_output('netsh interface show interface', shell=True, encoding='utf-8')
    except subprocess.CalledProcessError:
        return []
    interfaces = []
    for line in output.splitlines():
        if "전용" in line:
            parts = line.split()
            if len(parts) >= 4:
                interfaces.append(parts[-1])
    return interfaces

def parse_arp_cache(raw):
    # "유형" 기준으로 자르고 나서 파싱
    idx = raw.find("유형")
    if idx == -1:
        return [], [], []
    raw = raw[idx+6:].strip()
    raw = raw.replace('\r\n', ',').replace('     ', ',').replace(' ', '').replace(',,', ',')
    if raw.endswith(','):
        raw = raw[:-1]
    items = raw.split(',')

    IPs, MACs, Types = [], [], []
    for i in range(0, len(items), 3):
        if i+2 < len(items):
            IPs.append(items[i])
            MACs.append(items[i+1])
            Types.append(items[i+2])
    return IPs, MACs, Types

def has_arp_spoofing(mac_list):
    return len(mac_list) != len(set(mac_list))

def clear_arp_table():
    os.system('arp -d *')

def set_static_arp(interfaces, IPs, MACs, Types):
    for i, t in enumerate(Types):
        if t == "동적":
            for iface in interfaces:
                cmd = f'netsh interface ipv4 add neighbors "{iface}" {IPs[i]} {MACs[i]}'
                os.system(cmd)

def prompt_yes_no(msg):
    while True:
        ans = input(msg + ' [y/n]: ').strip().lower()
        if ans in ('y', 'n'):
            return ans == 'y'
        print("잘못된 입력입니다. y 또는 n을 입력해주세요.")

def main():
    print("프로그램이 정상 작동하려면 관리자 권한으로 실행되어야 합니다.")
    arp_raw = get_arp_cache()
    IPtable, MACtable, typeTable = parse_arp_cache(arp_raw)
    interfaces = get_netsh_interfaces()

    if not IPtable or not MACtable or not typeTable:
        print("ARP 테이블 정보를 불러오는데 실패했습니다.")
        return

    if has_arp_spoofing(MACtable):
        print("경고! ARP 스푸핑 공격 가능성이 감지되었습니다.")
        if prompt_yes_no("ARP 테이블을 초기화하시겠습니까?"):
            clear_arp_table()
            print("ARP 테이블이 초기화되었습니다.")
        else:
            print("ARP 테이블 초기화를 취소했습니다.")
    else:
        print("현재 ARP 스푸핑 공격은 감지되지 않았습니다.")
        if prompt_yes_no("동적 ARP 항목을 정적으로 재설정하시겠습니까?"):
            set_static_arp(interfaces, IPtable, MACtable, typeTable)
            print("동적 ARP 항목이 정적으로 재설정되었습니다.")
        else:
            print("ARP 항목 설정을 유지합니다.")

if __name__ == "__main__":
    main()이거 된 거야? 뭐라고 어떻게 해야 해? 
