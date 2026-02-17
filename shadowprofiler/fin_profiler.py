import json
import os
import sys
import numpy as np
from collections import defaultdict, Counter
from prettytable import PrettyTable  # 建议安装: pip install prettytable 

# 引入你提供的 Flow Generator
from flow_parser import ForensicFlowGenerator

# ================= 配置区 =================
TRACE_LOG_PATH = "./data/experiment_traces.jsonl" 
PCAP_DIR = "./data/pcap"
PCAP_SUFFIX = "_br-lan.pcap" # 或者 _wl1.pcap，看你主要抓哪张网卡
TIME_WINDOW = 3.0            # 关联的时间窗口(秒)

class FingerprintProfiler:
    def __init__(self):
        self.raw_data = defaultdict(list)
        self.stats = {}

    def get_signed_sequence(self, flow):
        """将流转换为 [+154, -66, ...] 的序列"""
        seq = []
        # 简单判断方向：-> 为正，<- 为负
        for seg in flow['segments']:
            sign = 1 if seg['dir'] == '->' else -1
            seq.append(sign * seg['len'])
        return tuple(seq) # 转为 tuple 才能被 Counter 统计

    def run_profiling(self):
        print(f"[*] Loading traces from {TRACE_LOG_PATH}...")
        
        # 1. 读取并按 (Entity, State) 分组
        if not os.path.exists(TRACE_LOG_PATH):
            print("Trace file not found!")
            return

        with open(TRACE_LOG_PATH, 'r') as f:
            for line_idx, line in enumerate(f):
                if not line.strip(): continue
                record = json.loads(line)
                
                # 提取 App Atomic Key
                entity = record['trigger_action']['entity']
                target_state = record['trigger_action']['to_state']
                app_key = f"{entity}::{target_state}"
                
                # 提取元数据
                pcap_tag = record['pcap_file']
                t_trigger = record['trigger_action']['timestamp']
                
                # 2. 实时解析对应的 PCAP (针对每一个样本)
                seq = self.extract_sequence_from_pcap(pcap_tag, t_trigger)
                
                # 存入原始数据列表
                self.raw_data[app_key].append({
                    "sample_id": record['sample_idx'], # 第几次实验 (1-20)
                    "pcap_tag": pcap_tag,
                    "sequence": seq
                })
                print(f"    Processed {app_key} Sample {record['sample_idx']} -> {seq}")

        # 3. 计算统计置信度
        self.calculate_confidence()

    def extract_sequence_from_pcap(self, tag, t_trigger):
        pcap_path = os.path.join(PCAP_DIR, f"{tag}{PCAP_SUFFIX}")
        if not os.path.exists(pcap_path):
            return ("MISSING_PCAP",) # 标记为缺失

        # 抑制 pyshark/generator 的标准输出
        old_stdout = sys.stdout
        sys.stdout = open(os.devnull, 'w')
        
        best_flow = None
        try:
            # 调用你的解析器
            gen = ForensicFlowGenerator(pcap_path)
            flows = gen.process()
            
            # 筛选最佳流
            candidates = []
            for flow in flows:
                # 时间匹配：流开始时间在触发时间附近
                if (t_trigger - 0.5) <= flow['start_time'] <= (t_trigger + TIME_WINDOW):
                    candidates.append(flow)
            
            if candidates:
                # 规则：选字节数最多的流 (通常是控制指令)
                best_flow = sorted(candidates, key=lambda x: x['byte_count'], reverse=True)[0]
                
        except Exception:
            pass # 保持静默
        finally:
            sys.stdout = old_stdout

        if best_flow:
            return self.get_signed_sequence(best_flow)
        else:
            return ("NO_MATCHING_FLOW",) # 标记为未找到流

    def calculate_confidence(self):
        print("\n" + "="*60)
        print("FINGERPRINT CONFIDENCE REPORT")
        print("="*60)

        for app_key, samples in self.raw_data.items():
            total_samples = len(samples)
            
            # 提取所有序列
            all_seqs = [s['sequence'] for s in samples]
            
            # 统计频率
            counter = Counter(all_seqs)
            
            # 找到最主要的模式 (Dominant Pattern)
            dominant_seq, dom_count = counter.most_common(1)[0]
            confidence = (dom_count / total_samples) * 100
            
            # 记录统计结果
            self.stats[app_key] = {
                "dominant": dominant_seq,
                "confidence": confidence,
                "total": total_samples,
                "matches": dom_count,
                "outliers": []
            }

            # 找出异常样本 (Outliers)
            for s in samples:
                if s['sequence'] != dominant_seq:
                    self.stats[app_key]["outliers"].append(s)

            # --- 打印报告 ---
            self.print_key_report(app_key)

    def print_key_report(self, app_key):
        stat = self.stats[app_key]
        dom_seq_str = str(list(stat['dominant']))
        
        print(f"\nTarget: {app_key}")
        print(f"Samples: {stat['total']}")
        
        # 判定颜色 (置信度高绿色，低红色)
        color = "\033[92m" if stat['confidence'] > 85 else "\033[91m"
        reset = "\033[0m"
        
        print(f"Dominant Pattern: {dom_seq_str}")
        print(f"Confidence: {color}{stat['confidence']:.1f}% ({stat['matches']}/{stat['total']}){reset}")
        
        if stat['outliers']:
            print("Outliers (Deviations):")
            t = PrettyTable(["Sample", "PCAP Tag", "Observed Sequence"])
            t.align = "l"
            for out in stat['outliers']:
                t.add_row([out['sample_id'], out['pcap_tag'], str(list(out['sequence']))])
            print(t)
        else:
            print("Perfect Match (No outliers).")

if __name__ == "__main__":
    profiler = FingerprintProfiler()
    profiler.run_profiling()