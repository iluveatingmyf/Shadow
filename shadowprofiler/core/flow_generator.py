import pyshark
import asyncio
import os

class AtomicFlow:
    def __init__(self, start_ts, initiator, target_ip):
        self.start_ts = start_ts
        self.end_ts = start_ts
        self.initiator = initiator
        self.target_ip = target_ip
        # 这里的 signature 是这个流的身段：HA发给设备为正，设备发出为负
        self.signature = [] 

class ForensicFlowGenerator:
    def __init__(self, pcap_path, silence_threshold=1.5):
        self.pcap_path = pcap_path
        self.silence_threshold = silence_threshold

    def get_flows(self, target_ip):
        """提取 PCAP 中所有涉及 target_ip 的 Atomic Flows"""
        if not os.path.exists(self.pcap_path): return []

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
            loop.close()
            
        completed_flows.extend(active_flows.values())
        return completed_flows

    def _init_flow(self, ts, src, target_ip, val):
        f = AtomicFlow(ts, src, target_ip)
        f.signature.append(val)
        return f