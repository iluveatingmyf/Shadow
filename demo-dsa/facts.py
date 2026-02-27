import os
import json
from collections import Counter,defaultdict
import networkx as nx
from typing import List, Dict, Any, Tuple
from contextual_graph import ContextualGraphBuilder
from dsa_engine import DeviationSearchEngine
from selector import InteractionCausalSelector

class RCAFactExtractor:
    def __init__(self, ha_ip: str, shadow_data: Dict):
        self.ha_ip = ha_ip
        self.shadow = shadow_data
        # 物理层基准线：IP -> 期待的真实 MAC
        self.baseline_macs = {
            "192.168.0.1":"50:64:2B:40:6C:54",
            "192.168.0.157": "DC:A6:32:F3:76:22",
            "192.168.0.192": "78:11:DC:B2:60:63",
            "192.168.0.217": "CC:4D:75:44:D4:74",
            #"192.168.0.109": "2C:76:00:EC:80:AC",
            "192.168.0.48": "54:EF:44:C8:4E:93",
            "192.168.0.252": "3C:BD:3E:99:C0:45",
            "192.168.0.196": "C4:93:BB:F0:6D:F1",
            "192.168.0.61": "04:CF:8C:08:B9:18",
            "192.168.0.176": "78:11:DC:90:B7:45"
        }

    def _get_flow_map(self, node_data: Dict) -> List[Dict]:
        # 1. 优先获取聚合后的列表
        flow_ids = node_data.get('flow_ids')
        sigs = node_data.get('sig_history')
        
        # 2. 如果是单个流节点（没有聚合信息），则封装成单元素列表
        if flow_ids is None:
            flow_ids = [node_data.get('net_id')]
        if sigs is None:
            # 注意这里：要取节点本身的 sig
            sigs = [node_data.get('sig', [])]
            
        # 3. 过滤掉 None 值的清洗
        res = []
        for fid, s in zip(flow_ids, sigs):
            if fid: # 只有 ID 存在才加入
                res.append({"id": fid, "sig": self._parse_sig(s)})
        return res

    def _analyze_retransmission_patterns(self, entity_graph: nx.DiGraph) -> List[Tuple]:
        """
        维度 2 增强版：不仅定位重复包，还能列出所有受影响的具体 net_id。
        """
        facts = []
        # 结构: pkt_size -> set of net_ids
        pkt_to_netids = defaultdict(set)
        
        # 1. 扫描图中所有聚合节点，并展开其中的原始 net_id
        for _, data in entity_graph.nodes(data=True):
            flows = self._get_flow_map(data) # 使用你已有的展开函数
            print(flows)
            for f in flows:
                sig = [pkt for pkt in f['sig']]
                for val in sig:
                    if val < 70: continue # 过滤掉心跳/ACK包
                    pkt_to_netids[val].add(f['id'])

        # 2. 识别重传模式
        for pkt, ids in pkt_to_netids.items():
            if len(ids) >= 3: # 设定阈值：在 3 个或更多流中出现相同包长
                sorted_ids = sorted(list(ids))
                facts.append(("retransmission_storm", pkt, tuple(sorted_ids), {
                    "repeat_count": len(ids),
                    "affected_net_ids": sorted_ids,
                    "desc": f"Packet size {pkt} was seen repeating in flows: {', '.join(sorted_ids)}"
                }))
        return facts


    def _get_all_sigs_from_node(self, node_data: Dict) -> List[List[int]]:
        """从聚合节点中提取所有流的指纹"""
        history = node_data.get('sig_history', [])
        if not history:
            return [self._parse_sig(node_data.get('sig', []))]
        return [self._parse_sig(s) for s in history]


    def _find_shadow_entry(self, p_label: str) -> Dict:
        """
        去噪语义匹配：自动剥离类名，确保 'alarm_arm_away' 能匹配到指纹库。
        """
        # 1. 尝试直接匹配
        if p_label in self.shadow:
            return self.shadow[p_label]

        # 2. 语义拆解匹配
        try:
            # 预处理：转小写，去掉常见的类名前缀
            def clean(s):
                return s.lower().replace("alarm_control_panel.", "").strip()

            p_parts = [clean(x) for x in p_label.split('|')]
            
            for k, v in self.shadow.items():
                k_parts = [clean(x) for x in k.split('|')]
                
                # 只有当 Entity 关键词和 Action 关键词同时匹配时才通过
                if len(p_parts) == 2 and len(k_parts) == 2:
                    if (p_parts[0] in k_parts[0] or k_parts[0] in p_parts[0]) and \
                    (p_parts[1] in k_parts[1] or k_parts[1] in p_parts[1]):
                        return v
        except:
            pass
        return {}
        
    def _parse_sig(self, sig_data) -> List[int]:
        """关键修复：将指纹统一转为 List[int] 以便进行子序列匹配"""
        if not sig_data or sig_data == "None": return []
        if isinstance(sig_data, list): return sig_data
        if isinstance(sig_data, str):
            try:
                # 处理 '[-158]' 这种 JSON 字符串格式
                cleaned = sig_data.replace("'", '"')
                return json.loads(cleaned)
            except:
                return []
        return []

    def _contains_subsequence(self, full_seq: List[int], sub_seq: List[int]) -> bool:
        if not sub_seq: return False
        # 针对 IoT 指令特征包（如 203, 154, 186）做优化
        # 只要第一个关键包（特征长度）出现了，就认定该流属于该指令
        target_pkt = sub_seq[0]
        return target_pkt in full_seq

    def extract_facts(self, entity_graph: nx.DiGraph, target_ip: str, primitive: Dict) -> List[Tuple]:
        facts = []
        p_id = primitive.get('node_id', 'unknown_event')
        p_type = primitive.get('type') # MATCHED / UNSUPPORTED
        p_label = primitive.get('metadata', {}).get("label", "Unknown")

        shadow_entry = self._find_shadow_entry(p_label)
        expected_cmd = self._parse_sig(shadow_entry.get("cmd", []))

        ## 核心：定义我们要找的指令特征包（比如 203）
        cmd_pkt_size = abs(expected_cmd[0]) if expected_cmd else None

        # --- 1. 因果事实 (Causal Logic) ---
        # 建立 net_id 级别的因果链
        for u, v in entity_graph.edges():
            facts.append(("is_cause_of", u, v, {
                "u_label": entity_graph.nodes[u].get('label'),
                "v_label": entity_graph.nodes[v].get('label'),
                "delay": entity_graph.nodes[v]['ts_start'] - entity_graph.nodes[u]['ts_end']
            }))

        # --- 维度 B: 全局重传分析 ---
        # 得到事实：("retransmission_storm", pkt_size, (net_id1, net_id2...), info)
        global_retry_facts = self._analyze_retransmission_patterns(entity_graph)
        
        # 建立快速索引：哪些 net_id 重传了哪个包
        # 结构：net_id -> set of packet_sizes
        id_to_retry_pkts = defaultdict(set)
        for f_type, pkt, ids, info in global_retry_facts:
            for net_id in ids:
                id_to_retry_pkts[net_id].add(pkt)
            # 同时也保留原始的全局事实输出
            facts.append((f_type, p_id, ids, info))

        #facts.extend(global_retry_facts)
        cmd_related_net_ids = [] # 记录包含指令的 net_id
        # --- 维度 C: 流量与指纹特征 (Flow & Sig Atoms) ---
        for node_id, data in entity_graph.nodes(data=True):
            flows = self._get_flow_map(data)
            for f in flows:
                curr_net_id = f['id']
                curr_sig_abs = [abs(p) for p in f['sig']]
                
                # 1. 检查是否包含 CMD 包
                has_cmd = False
                if cmd_pkt_size and cmd_pkt_size in curr_sig_abs:
                    has_cmd = True
                    cmd_related_net_ids.append(curr_net_id)

                # 2. 检查是否属于重传流
                is_retry = curr_net_id in id_to_retry_pkts
                
                # 3. 判定是否为半程 (无响应)
                is_half = (entity_graph.out_degree(node_id) == 0 and f['id'] == flows[-1]['id'])

                # --- 重点：生成复合事实 ---
                if has_cmd:
                    if is_retry:
                        # 事实：指令包在重传
                        facts.append(("cmd_packet_retransmission", curr_net_id, cmd_pkt_size, {
                            "is_half": is_half,
                            "desc": f"CMD pkt {cmd_pkt_size} retransmitted in {curr_net_id} (Half: {is_half})"
                        }))
                    elif is_half:
                        # 事实：指令包虽然没重传，但是是半程（石沉大海）
                        facts.append(("cmd_half_command", curr_net_id, cmd_pkt_size, {
                            "desc": f"CMD pkt {cmd_pkt_size} sent in {curr_net_id} but no response"
                        }))

            # 修复 2: 未授权注入 (聚合块里只要是 Unknown 且发往 HA)
            if data.get('label') == "Unknown" and data.get('dst') == self.ha_ip:
                facts.append(("unauthorized_injection", p_id, node_id, {
                    "src": data.get('src'), "count": data.get('count')
                }))

            
            # 获取并解析当前节点的签名和历史
            # --- 维度 C: 物理偏航判定 (MAC/ARP Atoms) ---
            # 检查源 MAC
            src_ip, dst_ip = data.get('src'), data.get('dst')
            src_mac, dst_mac = data.get('src_mac'), data.get('dst_mac')
            if src_ip in self.baseline_macs and src_mac:
                if src_mac.lower() != self.baseline_macs[src_ip].lower():
                    facts.append(("src_mac_poisoned", p_id, node_id, {
                        "ip": src_ip, "expected": self.baseline_macs[src_ip], "actual": src_mac
                    }))
            # 检查目的 MAC (MITM 核心特征)
            if dst_ip in self.baseline_macs and dst_mac:
                if dst_mac.lower() != self.baseline_macs[dst_ip].lower():
                    facts.append(("dst_mac_poisoned", p_id, node_id, {
                        "ip": dst_ip, "expected": self.baseline_macs[dst_ip], "actual": dst_mac
                    }))

        # --- 维度 D: 跨层一致性 (Consistency Atoms) ---
        # 6. Shadow Command (App 说做了，网络层完全没影)
        if p_type == "UNSUPPORTED":
            has_any_cmd_flow = False
            for _, d in entity_graph.nodes(data=True):
                node_sig = self._parse_sig(d.get('sig', []))
                if expected_cmd and self._contains_subsequence(node_sig, expected_cmd):
                    has_any_cmd_flow = True
                    break
            
            if not has_any_cmd_flow:
                facts.append(("shadow_app_command", p_id, None, {
                    "expected_sig": expected_cmd,
                    "reason": "App log exists but no matching net signature found"
                }))

        return facts

# ==============================================================================
# 主程序运行区
# ==============================================================================

HA_IP = "192.168.0.157"
PCAP_FILE = "/Users/myf/shadowprov/RawLogs/A1/S2/delay/capture_br-lan.pcap" 
APP_LOG_FILE = "./data/app_atomics_A1S2Delay.json" 
PROFILES_DIR = "profiles"

def load_json(filename):
    if os.path.exists(filename):
        with open(filename, 'r', encoding='utf-8') as f: return json.load(f)
    return {}

entity_config = load_json("./profiles/entity_config.json").get("ENTITY_CONFIG", {})
shadow_data = load_json("./profiles/actuator_profiles.json")

# 1. 引擎初始化
engine = DeviationSearchEngine(PCAP_FILE, APP_LOG_FILE, PROFILES_DIR, HA_IP)
bundle = engine.get_results_bundle()
all_net_atoms = bundle['net_atomic_pool']
dsa_primitives = bundle['dsa_primitives'][:-8]

# 2. 提取因果上下文
selector = InteractionCausalSelector(all_net_atoms, entity_config)
causal_contexts = selector.batch_extract(dsa_primitives)

# 3. 实例化事实提取器
fact_extractor = RCAFactExtractor(HA_IP, shadow_data)

print(f"\n{'='*30} RCA Fact Extraction Debug {'='*30}")

all_extracted_facts = []

for ctx in causal_contexts:
    primitive = ctx['primitive']
    flows = ctx['context_flows']
    entity_id = ctx['entity_id']
    target_device_ip = entity_config.get(entity_id, "Null")

    if not flows: continue

    # 4. 构建图
    builder = ContextualGraphBuilder(HA_IP, agg_window=5.0)
    G = builder.build_micro_graph(flows)

    # 5. 执行提取
    facts = fact_extractor.extract_facts(G, target_device_ip, primitive)
    
    if facts:
        print(f"\n[ENTITY: {entity_id}]")
        print(f" Primitive: {primitive.get('label')} ({primitive['type']})")
        for f_name, ent, node_ref, data in facts:
            print(f"  └── 🔍 Fact: {f_name:<20} | Ref: {node_ref} | Info: {data}")
        all_extracted_facts.extend(facts)

print(f"\n{'='*25} TOTAL FACTS FOUND: {len(all_extracted_facts)} {'='*25}")