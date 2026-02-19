import json
import os
import glob
import numpy as np
import statistics
from scapy.all import rdpcap, IP, TCP, UDP

# ================= 配置区 =================
# 必须与您采集时的路径一致
JSONL_FILE = "experiment_traces.jsonl"
LOCAL_PCAP_DIR = "/Users/myf/smartprov/pcap"
OUTPUT_MODEL_FILE = "../data/abbm_model_final.json"

class ABBMBuilder:
    def __init__(self):
        self.raw_traces = []
        self.model = {}

    def load_data(self):
        print(f"[*] Loading traces from {JSONL_FILE}...")
        if not os.path.exists(JSONL_FILE):
            print("Error: JSONL file not found.")
            return

        with open(JSONL_FILE, 'r') as f:
            for line in f:
                try:
                    self.raw_traces.append(json.loads(line))
                except: pass
        print(f"[*] Loaded {len(self.raw_traces)} samples.")

    def _analyze_pcap_fingerprint(self, session_tag):
        """
        核心：构建 Physical Norm 的网络指纹
        因为是隔离采集，我们分析整个文件的统计特征，无需关心时间同步
        """
        # 匹配该 Session 的所有 pcap (br-lan 和 wl1)
        search_pattern = os.path.join(LOCAL_PCAP_DIR, f"{session_tag}*.pcap")
        files = glob.glob(search_pattern)
        
        total_packets = 0
        packet_sizes = []
        protocols = {"TCP": 0, "UDP": 0, "Other": 0}
        
        for p_file in files:
            try:
                packets = rdpcap(p_file)
                for pkt in packets:
                    if IP in pkt:
                        total_packets += 1
                        packet_sizes.append(len(pkt))
                        
                        if TCP in pkt: protocols["TCP"] += 1
                        elif UDP in pkt: protocols["UDP"] += 1
                        else: protocols["Other"] += 1
            except Exception as e:
                # 文件可能还没写完或损坏，跳过
                pass
        
        return {
            "count": total_packets,
            "sizes": packet_sizes,
            "protos": protocols
        }

    def build(self):
        print("[*] Building ABBM Model (Physical & Cyber Norms)...")
        
        # 1. 按 Rule ID 分组
        grouped_rules = {}
        for t in self.raw_traces:
            rid = t['rule_id']
            if rid not in grouped_rules: grouped_rules[rid] = []
            grouped_rules[rid].append(t)

        # 2. 逐个规则计算统计特征
        for rid, samples in grouped_rules.items():
            print(f"   -> Processing Rule {rid} ({len(samples)} samples)...")
            
            # 临时列表存储各维度的 metric
            cyber_delays = [] # Logic Delay
            phys_delays = []  # Network Delay
            pcap_metrics = [] # Network Fingerprints

            for s in samples:
                # --- 提取时间特征 (Cyber Norm) ---
                # 注意：这里需要根据您 jsonl 的实际结构提取时间
                # 假设您记录了 trigger_time, call_service_time, state_change_time
                
                # 安全提取嵌套字典
                try:
                    # 找到成功的 Device Trace
                    dev_traces = s['app_events']['device_details']
                    success_trace = next((d for d in dev_traces if d['success']), None)
                    
                    if not success_trace: continue
                    
                    t_trigger = s['app_events']['ha_automation_triggered']['ha_fired_at']
                    t_call = success_trace['service_called']['ha_fired_at']
                    t_state = success_trace['state_reached']['ha_fired_at']
                    
                    if t_trigger and t_call and t_state:
                        # Logic Delay = Call - Trigger
                        cyber_delays.append(t_call - t_trigger)
                        # Physical Delay = State - Call
                        phys_delays.append(t_state - t_call)

                    # --- 提取网络特征 (Physical Norm) ---
                    pcap_tag = s['pcap_file']
                    fingerprint = self._analyze_pcap_fingerprint(pcap_tag)
                    if fingerprint['count'] > 0:
                        pcap_metrics.append(fingerprint)
                        
                except KeyError:
                    continue

            # 3. 计算统计量 (3-Sigma)
            if not cyber_delays or not phys_delays:
                print(f"      [Warn] Not enough valid data for Rule {rid}")
                continue

            def get_stats(data):
                if not data: return {"mu": 0, "sigma": 0, "limit": 0}
                mu = statistics.mean(data)
                sigma = statistics.stdev(data) if len(data) > 1 else 0
                return {
                    "mu": round(mu, 4),
                    "sigma": round(sigma, 4),
                    "limit": round(mu + 3 * sigma, 4) # 99.7% 置信区间
                }

            # 4. 聚合网络指纹
            # 计算包数量的平均值
            pkt_counts = [m['count'] for m in pcap_metrics]
            avg_count = int(statistics.mean(pkt_counts)) if pkt_counts else 0
            
            # 提取最常见的包大小 (Top 5 Packet Sizes)
            all_sizes = []
            for m in pcap_metrics: all_sizes.extend(m['sizes'])
            
            # 使用 numpy 快速计算频率最高的包大小
            common_sizes = []
            if all_sizes:
                counts = np.bincount(all_sizes)
                common_sizes = np.argsort(-counts)[:5].tolist() # Top 5

            # 5. 存入模型
            self.model[rid] = {
                "cyber_norm": { # 用于恢复
                    "logic_delay": get_stats(cyber_delays)
                },
                "physical_norm": { # 用于验证 (Shadow Matching)
                    "network_delay": get_stats(phys_delays),
                    "fingerprint": {
                        "packet_count_mu": avg_count,
                        "packet_count_tolerance": 5, # 允许波动
                        "common_sizes": common_sizes
                    }
                }
            }

        # 6. 保存
        with open(OUTPUT_MODEL_FILE, 'w') as f:
            json.dump(self.model, f, indent=4)
        print(f"[*] ABBM Model successfully built: {OUTPUT_MODEL_FILE}")

if __name__ == "__main__":
    builder = ABBMBuilder()
    builder.load_data()
    builder.build()