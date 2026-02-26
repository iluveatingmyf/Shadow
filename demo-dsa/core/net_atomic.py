# netaudit/atomic.py
import pyshark
import asyncio
import os

class AtomicFlow:
   def __init__(self, start_ts, initiator, target_ip, src_mac=None, dst_mac=None):
        self.start_ts = start_ts
        self.end_ts = start_ts
        self.initiator = initiator
        self.target_ip = target_ip
        # signature: 有符号包长序列
        self.src_mac = src_mac
        self.dst_mac = dst_mac  # 新增：目标物理地址
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
                    
                    src_is_device = src.startswith(local_prefix) and (src not in infrastructure_ips)
                    dst_is_device = dst.startswith(local_prefix) and (dst not in infrastructure_ips)

                    # 逻辑修正：
                    if src_is_device:
                        device_ip = src
                        peer_ip = dst
                        is_inbound_to_device = False
                    elif dst_is_device:
                        device_ip = dst
                        peer_ip = src
                        is_inbound_to_device = True
                    else:
                        continue # 两个 IP 都不是传感器，忽略

                    proto = pkt.transport_layer
                    sport, dport = pkt[proto].srcport, pkt[proto].dstport
                    
                    # Flow Key 必须包含对端，否则同一传感器的不同会话会打架
                    flow_key = (device_ip, peer_ip, tuple(sorted((int(sport), int(dport)))), proto)
                    
                    ts = float(pkt.sniff_timestamp)
                    val = int(pkt.length) if is_inbound_to_device else -int(pkt.length)

                    if flow_key in active_flows:
                        flow = active_flows[flow_key]
                        if ts - flow.end_ts > self.silence_threshold:
                            completed_flows.append(active_flows.pop(flow_key))
                            active_flows[flow_key] = self._init_flow(ts, device_ip, peer_ip, val)
                        else:
                            flow.signature.append(val)
                            flow.end_ts = ts
                    else:
                        active_flows[flow_key] = self._init_flow(ts, device_ip, peer_ip, val)
                except Exception:
                    continue
        finally:
            cap.close()
            
        completed_flows.extend(active_flows.values())
        return completed_flows

    def _init_flow(self, ts, src, target_ip, val, src_mac=None, dst_mac=None):
        f = AtomicFlow(ts, src, target_ip, src_mac, dst_mac)
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
                    # 提取双向 MAC
                    curr_src_mac = pkt.eth.src if hasattr(pkt, 'eth') else None
                    curr_dst_mac = pkt.eth.dst if hasattr(pkt, 'eth') else None
                    # --- 核心改进：定义终端设备 (Terminal Device) ---
                    # 规则：如果 IP 是内网地址，且不是网关、也不是树莓派，则它是我们要监控的“传感器”
                    src_is_device = src.startswith(local_prefix) and (src not in infrastructure_ips)
                    dst_is_device = dst.startswith(local_prefix) and (dst not in infrastructure_ips)

                    # 逻辑修正：定义 device 和 peer
                    if src_is_device:
                        device_ip = src
                        peer_ip = dst
                        is_inbound_to_device = False
                    elif dst_is_device:
                        device_ip = dst
                        peer_ip = src
                        is_inbound_to_device = True
                    else:
                        continue # 忽略非设备相关的流量

                    proto = pkt.transport_layer
                    sport, dport = pkt[proto].srcport, pkt[proto].dstport
                    
                    # 关键：Flow Key 必须包含 device 和 peer，防止不同会话串线
                    flow_key = (device_ip, peer_ip, tuple(sorted((int(sport), int(dport)))), proto)
                    
                    ts = float(pkt.sniff_timestamp)
                    # 正数=发往设备(指令)，负数=设备发出(报文)
                    val = int(pkt.length) if is_inbound_to_device else -int(pkt.length)

                    if flow_key in active_flows:
                        flow = active_flows[flow_key]
                        # 检查静默时长，判断是否开启新原子流
                        if ts - flow.end_ts > self.silence_threshold:
                            completed_flows.append(active_flows.pop(flow_key))
                            active_flows[flow_key] = self._init_flow(ts, device_ip, peer_ip, val, curr_src_mac, curr_dst_mac)
                        else:
                            flow.signature.append(val)
                            flow.end_ts = ts
                    else:
                        active_flows[flow_key] = self._init_flow(ts, device_ip, peer_ip, val, curr_src_mac, curr_dst_mac)
                except Exception:
                    continue
        finally:
            cap.close()
            
        completed_flows.extend(active_flows.values())
        return completed_flows
    

