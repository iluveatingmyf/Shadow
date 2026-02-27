from typing import List, Dict, Set, Any
import networkx as nx
from dsa_engine import DeviationSearchEngine
from selector import InteractionCausalSelector
import os
import json

class ContextualGraphBuilder:
    def __init__(self, gateway_ip: str, agg_window: float = 10.0):
        self.gateway_ip = gateway_ip
        # 聚合窗口：5秒内的同设备、同Label流将被合并
        self.agg_window = agg_window 

    def build_micro_graph(self, context_flows: List[Dict]) -> nx.DiGraph:
        # 1. 执行流坍缩：将持续性的传感器上报聚合为 Super Node
        collapsed_nodes = self._collapse_continuous_flows(context_flows)
        
        G = nx.DiGraph()
        # 2. 添加聚合后的节点
        for node in collapsed_nodes:
            # 这里的 ts 采用该序列的起始时间，同时记录持续时长 duration
            G.add_node(
                node['net_id'], 
                ts=node['ts_start'],
                ts_end=node['ts_end'],
                duration=node['ts_end'] - node['ts_start'],
                count=node['count'],
                src=node['src'], 
                dst=node['dst'], 
                src_mac=node.get('src_mac'), # <--- 核心修复
                dst_mac=node.get('dst_mac'),
                label=node['label'],
                sig=node.get('sig'),           # 当前/首个指纹
                sig_history=node.get('sig_history', []), # 聚合历史指纹
                flow_ids=node.get('flow_ids', []),       # 聚合的原始 ID 列表
                is_collapsed=True
            )

        # 3. 添加因果边 (逻辑保持不变：dst == src 且时间接续)
        # 注意：现在由于节点减少，因果链条会清晰很多
        sorted_nodes = sorted(G.nodes(data=True), key=lambda x: x[1]['ts'])
        for i in range(len(sorted_nodes)):
            for j in range(i + 1, len(sorted_nodes)):
                n1, d1 = sorted_nodes[i]
                n2, d2 = sorted_nodes[j]
                # 这里的连边逻辑：前一个聚合块的结束时间到后一个聚合块的开始时间
                if 0 < (d2['ts'] - d1['ts_end']) < 2.0 and d1['dst'] == d2['src']:
                    G.add_edge(n1, n2)
        
        return G


    def _collapse_continuous_flows(self, flows: List[Dict]) -> List[Dict]:
        if not flows: return []
        sorted_f = sorted(flows, key=lambda x: float(x['ts'])) 
        collapsed = []

        for f in sorted_f:
            anchor = f.get('anchor', {}) or {}
            src = anchor.get('src_ip')
            dst = anchor.get('dst_ip')
            label = f.get('label', 'Unknown')
            ts = float(f['ts']) 
            current_id = f['net_id']
            # 获取当前的签名指纹
            current_sig = anchor.get('payload_digest', "[]")

            dynamic_window = self.agg_window if label != "Unknown" else 1.0

            if collapsed:
                last = collapsed[-1]
                if (src == last['src'] and dst == last['dst'] and 
                    label == last['label'] and (ts - last['ts_end']) < dynamic_window):
                    
                    last['ts_end'] = ts
                    last['count'] += 1
                    if 'flow_ids' not in last: last['flow_ids'] = [last['net_id']]
                    last['flow_ids'].append(current_id)
                    
                    # --- 核心修改：追加签名历史 ---
                    if 'sig_history' not in last:
                        last['sig_history'] = [last['sig']] # 把第一个节点的 sig 先存进去
                    last['sig_history'].append(current_sig)
                    
                    continue

            # 新建聚合节点
            collapsed.append({
                'net_id': current_id,
                'ts_start': ts,
                'ts_end': ts,
                'src': src,
                'dst': dst,
                'src_mac': anchor.get('src_mac'), 
                'dst_mac': anchor.get('dst_mac'),
                'label': label,
                'sig': current_sig,
                'sig_history': [current_sig], # 初始化历史列表
                'count': 1,
                'flow_ids': [current_id]
            })
            #print(collapsed[-1])
        return collapsed


def run_detailed_aggregation_audit(causal_contexts: List[Dict], gateway_ip: str):
    """
    审计函数：列出每个聚合节点具体合并了哪些原始 Flow
    """
    builder = ContextualGraphBuilder(gateway_ip, agg_window=5.0)
    
    print("\n" + "!"*40 + " AGGREGATION AUDIT REPORT " + "!"*40)
    
    for ctx in causal_contexts:
        ent_id = ctx['entity_id']
        flows = ctx.get('context_flows', [])
        if not flows: continue

        collapsed_nodes = builder._collapse_continuous_flows(flows)
        
        # 只针对发生过合并的实体进行详细输出
        has_agg = any(node['count'] > 1 for node in collapsed_nodes)
        
        if has_agg:
            print(f"\n[ENTITY: {ent_id}]")
            for node in collapsed_nodes:
                status = "merged" if node['count'] > 1 else "single"
                color = "\033[93m" if node['count'] > 1 else ""
                reset = "\033[0m"
                
                print(f"  > {color}Node {node['net_id']}{reset} ({status}):")
                print(f"    - Label: {node['label']}")
                print(f"    - Time: {node['ts_start']} -> {node['ts_end']} (Duration: {node['ts_end']-node['ts_start']:.2f}s)")
                print(f"    - Count: {node['count']} flows")
                if node['count'] > 1:
                    # 打印具体合并了哪些 Flow ID
                    print(f"    - Included Flow IDs: {', '.join(node['flow_ids'])}")
    
    print("\n" + "!"*100)




PCAP_FILE = "/Users/myf/shadowprov/RawLogs/A1/S2/delay/capture_br-lan.pcap" 
APP_LOG_FILE = "./data/app_atomics_A1S2Delay.json" 
PROFILES_DIR = "profiles"
def load_json(filename):
    path = os.path.join(filename)
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f: return json.load(f)
    return {}
            
# --- 新增：加载实体配置 ---
entity_config= load_json("./profiles/entity_config.json").get("ENTITY_CONFIG", {})

# 实例化引擎
# 1. 实例化引擎并获取数据
engine = DeviationSearchEngine(PCAP_FILE, APP_LOG_FILE, PROFILES_DIR, "192.168.0.1")
bundle = engine.get_results_bundle()
all_net_atoms = bundle['net_atomic_pool']
dsa_primitives = bundle['dsa_primitives'][:-8]
selector = InteractionCausalSelector(all_net_atoms, entity_config)

# 3. 批量获取因果上下文
# 现在 batch_select 已经在类中定义好了
causal_contexts = selector.batch_extract(dsa_primitives)

# 在主程序中调用
run_detailed_aggregation_audit(causal_contexts, "192.168.0.1")