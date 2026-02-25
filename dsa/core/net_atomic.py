# netaudit/atomic.py
import pyshark
import asyncio
import os

class AtomicFlow:
    def __init__(self, start_ts, initiator, target_ip):
        self.start_ts = start_ts
        self.end_ts = start_ts
        self.initiator = initiator
        self.target_ip = target_ip
        # signature: 有符号包长序列
        self.signature = []

class ForensicFlowGenerator:
    def __init__(self, pcap_path, silence_threshold=1.5):
        self.pcap_path = pcap_path
        self.silence_threshold = silence_threshold

    def get_flows(self, target_ip):
        if not os.path.exists(self.pcap_path): return []

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        cap = pyshark.FileCapture(self.pcap_path, keep_packets=False, display_filter="tcp or udp")
        
        active_flows = {}
        completed_flows = []

        try:
            for pkt in cap:
                try:
                    src, dst = pkt.ip.src, pkt.ip.dst
                    if src != target_ip and dst != target_ip: continue
                    
                    proto = pkt.transport_layer
                    sport, dport = pkt[proto].srcport, pkt[proto].dstport
                    flow_key = tuple(sorted((src, dst))) + tuple(sorted((int(sport), int(dport)))) + (proto,)
                    
                    ts = float(pkt.sniff_timestamp)
                    val = int(pkt.length) if dst == target_ip else -int(pkt.length)

                    if flow_key in active_flows:
                        flow = active_flows[flow_key]
                        if ts - flow.end_ts > self.silence_threshold:
                            completed_flows.append(active_flows.pop(flow_key))
                            active_flows[flow_key] = self._init_flow(ts, src, target_ip, val)
                        else:
                            flow.signature.append(val)
                            flow.end_ts = ts
                    else:
                        active_flows[flow_key] = self._init_flow(ts, src, target_ip, val)
                except: continue
        finally:
            cap.close()
            
        completed_flows.extend(active_flows.values())
        return completed_flows

    def _init_flow(self, ts, src, target_ip, val):
        f = AtomicFlow(ts, src, target_ip)
        f.signature.append(val)
        return f
    
    def get_flows_all(self, gateway_ip, pi_ip="192.168.0.157"):
        """
        全量解析：将网关、树莓派及外部云端统一视为“远端/服务器端”
        """
        if not os.path.exists(self.pcap_path): return []

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        cap = pyshark.FileCapture(self.pcap_path, keep_packets=False, display_filter="tcp or udp")
        active_flows = {}
        completed_flows = []

        # 基础设施 IP 列表
        infrastructure_ips = {gateway_ip, pi_ip}
        local_prefix = "192.168."

        try:
            for pkt in cap:
                try:
                    src, dst = pkt.ip.src, pkt.ip.dst
                    
                    # --- 核心改进：定义终端设备 (Terminal Device) ---
                    # 规则：如果 IP 是内网地址，且不是网关、也不是树莓派，则它是我们要监控的“传感器”
                    src_is_device = src.startswith(local_prefix) and (src not in infrastructure_ips)
                    dst_is_device = dst.startswith(local_prefix) and (dst not in infrastructure_ips)

                    # 逻辑：传感器与外界（网关/树莓派/外网）的交互
                    if src_is_device and not dst_is_device:
                        remote_ip = src  # 传感器是发起者
                        is_inbound_to_device = False
                    elif not src_is_device and dst_is_device:
                        remote_ip = dst  # 传感器是接收者
                        is_inbound_to_device = True
                    else:
                        # 忽略：树莓派与网关的通信、树莓派与外网的通信、传感器之间的直接通信（如果有）
                        continue

                    proto = pkt.transport_layer
                    sport, dport = pkt[proto].srcport, pkt[proto].dstport
                    
                    # Flow Key：以传感器 IP 为核心，剥离对端 IP
                    flow_key = (remote_ip,) + tuple(sorted((int(sport), int(dport)))) + (proto,)
                    
                    ts = float(pkt.sniff_timestamp)
                    val = int(pkt.length) if is_inbound_to_device else -int(pkt.length)

                    if flow_key in active_flows:
                        flow = active_flows[flow_key]
                        if ts - flow.end_ts > self.silence_threshold:
                            completed_flows.append(active_flows.pop(flow_key))
                            active_flows[flow_key] = self._init_flow(ts, remote_ip, remote_ip, val)
                        else:
                            flow.signature.append(val)
                            flow.end_ts = ts
                    else:
                        active_flows[flow_key] = self._init_flow(ts, remote_ip, remote_ip, val)
                except Exception:
                    continue
        finally:
            cap.close()
            
        completed_flows.extend(active_flows.values())
        return completed_flows