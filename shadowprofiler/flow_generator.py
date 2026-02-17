import pyshark
import json
import os

# 配置：静默超时时间（秒），超过这个时间视为新的 Flow
SILENCE_THRESHOLD = 2.0
# 排除列表：删除所有涉及路由器的流量，避免 VLAN 转发干扰
EXCLUDE_IPS = ["192.168.0.1"]

class ForensicFlowGenerator:
    def __init__(self, pcap_file, silence_threshold=SILENCE_THRESHOLD):
        self.pcap_file = pcap_file
        self.silence_threshold = silence_threshold
        self.active_flows = {}
        self.completed_flows = []

    def should_exclude(self, packet):
        """逻辑：如果包涉及路由器 IP，则剔除"""
        if hasattr(packet, 'ip'):
            if packet.ip.src in EXCLUDE_IPS or packet.ip.dst in EXCLUDE_IPS:
                return True
        return False

    def get_flow_key(self, packet):
        """
        生成唯一的 Flow Key。
        """
        # 增加清洗逻辑
        if self.should_exclude(packet):
            return None

        # 1. IP 协议处理
        if hasattr(packet, 'ip'):
            src = packet.ip.src
            dst = packet.ip.dst
            # 识别传输层协议
            proto = packet.transport_layer if hasattr(packet, 'transport_layer') else None
            
            # 仅处理 TCP 和 UDP
            if proto not in ['TCP', 'UDP']:
                return None
            
            sport = 0
            dport = 0

            if proto == 'TCP' and hasattr(packet, 'tcp'):
                sport = packet.tcp.srcport
                dport = packet.tcp.dstport
            elif proto == 'UDP' and hasattr(packet, 'udp'):
                sport = packet.udp.srcport
                dport = packet.udp.dstport
            
            # 排序：保证双向归一，忽略路由器后的“纯净”对端
            sorted_ips = sorted([src, dst])
            sorted_ports = sorted([int(sport), int(dport)])
            
            return f"{sorted_ips[0]}:{sorted_ports[0]}-{sorted_ips[1]}:{sorted_ports[1]}-{proto}"
        
        # 2. ARP 处理
        #elif hasattr(packet, 'arp'):
        #    src = packet.arp.src_hw_mac
        #    dst = packet.arp.dst_hw_mac
        #    sorted_macs = sorted([src, dst])
        #    return f"ARP-{sorted_macs[0]}-{sorted_macs[1]}"
            
        return None

    def process(self):
        print(f"[*] Processing {self.pcap_file} (Excluding {EXCLUDE_IPS})...")
        cap = pyshark.FileCapture(self.pcap_file, keep_packets=False)
        
        count = 0
        for packet in cap:
            count += 1
            if count % 1000 == 0:
                print(f"    Processed {count} packets...", end='\r')

            try:
                # 过滤路由器流量
                key = self.get_flow_key(packet)
                if not key:
                    continue

                timestamp = float(packet.sniff_timestamp)

                if key in self.active_flows:
                    flow = self.active_flows[key]
                    if timestamp - flow['end_time'] > self.silence_threshold:
                        self.completed_flows.append(flow)
                        self.active_flows[key] = self.create_new_flow(key, packet, timestamp)
                    else:
                        self.update_flow(flow, packet, timestamp)
                else:
                    self.active_flows[key] = self.create_new_flow(key, packet, timestamp)
            
            except Exception:
                continue
        
        cap.close()
        for flow in self.active_flows.values():
            self.completed_flows.append(flow)
        
        print(f"\n[+] Done. Generated {len(self.completed_flows)} pure flows.")
        return self.completed_flows

    def create_new_flow(self, key, packet, timestamp):
        initiator_ip = packet.ip.src if hasattr(packet, 'ip') else (packet.arp.src_hw_mac if hasattr(packet, 'arp') else "unknown")
        
        flow = {
            'flow_key': key,
            'start_time': timestamp,
            'end_time': timestamp,
            'initiator': initiator_ip,
            'packet_count': 1,
            'byte_count': int(packet.length),
            'segments': []
        }
        flow['segments'].append(self.extract_segment(packet, timestamp, flow['initiator']))
        return flow

    def update_flow(self, flow, packet, timestamp):
        flow['end_time'] = timestamp
        flow['packet_count'] += 1
        flow['byte_count'] += int(packet.length)
        flow['segments'].append(self.extract_segment(packet, timestamp, flow['initiator']))

    def extract_segment(self, packet, timestamp, initiator):
        """提取用于 ABBM 验证的精细特征 (154/138 长度识别)"""
        seg = {
            'ts': timestamp,
            'len': int(packet.length),
            'dir': '->' 
        }

        src = "unknown"
        if hasattr(packet, 'ip'):
            src = packet.ip.src
            seg['src'] = src
            seg['dst'] = packet.ip.dst
        elif hasattr(packet, 'arp'):
            src = packet.arp.src_hw_mac
        
        if src != initiator:
            seg['dir'] = '<-'

        # 为 Ghost Entity 诊断保存关键信息
        if hasattr(packet, 'tcp'):
            seg['flags'] = str(packet.tcp.flags)
            # 这里记录原始负载长度，用于匹配 Shadow 里的 154 和 138
            seg['payload_len'] = int(packet.tcp.len) if hasattr(packet.tcp, 'len') else 0

        return seg

# --- 运行逻辑 ---
if __name__ == "__main__":
    PCAP_FILE = "./dos/dos.pcap" 
    OUTPUT_FILE = "./dos/attack_flows.json"

    if os.path.exists(PCAP_FILE):
        generator = ForensicFlowGenerator(PCAP_FILE)
        flows = generator.process()
        flows.sort(key=lambda x: x['start_time'])
        
        with open(OUTPUT_FILE, 'w') as f:
            json.dump(flows, f, indent=2)
        print(f"Cleaned flows saved to {OUTPUT_FILE}")