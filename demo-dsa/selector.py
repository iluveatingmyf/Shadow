from dsa_engine import DeviationSearchEngine
import os
import json
import logging
from typing import List, Dict, Set, Any
logger = logging.getLogger("SELECTOR")
import collections
from datetime import datetime
import bisect
import logging
from typing import TypedDict, Optional, List, Dict, Set, Any, Tuple

class InteractionCausalSelector:
    def __init__(self, net_atomic_pool: List[Dict], entity_config: Dict[str, str], gateway_ip: str = "192.168.0.1"):
        # 确保池子按时间戳排序，方便二分查找优化性能
        self.pool = sorted(net_atomic_pool, key=lambda x: x['ts'])
        self.pool_ts = [f['ts'] for f in self.pool]
        
        self.entity_config = entity_config
        self.gateway_ip = gateway_ip
        self.window = 10.0  # 种子搜索窗口

    def _get_ips_from_flow(self, flow: Dict) -> Set[str]:
        ips = set()
        anchor = flow.get('anchor')
        if anchor:
            # 优先从 anchor 的字段里取，这最准！
            if 'src_ip' in anchor: ips.add(anchor['src_ip'])
            if 'dst_ip' in anchor: ips.add(anchor['dst_ip'])
            
            # 兜底：兼容旧的 flow_key 字符串逻辑
            if not ips and anchor.get('flow_key'):
                parts = anchor['flow_key'].split('_')
                for p in parts:
                    if "." in p: ips.add(p) # 简单的 IP 识别
        
        # 兼容 net_events 里的 target_ip
        if 'target_ip' in flow: ips.add(flow['target_ip'])
        return ips


    def select_by_propagation(self, primitive: Dict[str, Any], max_hops: int = 1) -> Dict[str, Any]:
        t0 = primitive['timestamp']
        p_type = primitive.get('type')
        m = primitive.get('metadata', {})
        label_str = m.get("label", "")
        entity_id = label_str.split('|')[0].strip() if '|' in label_str else label_str
        target_ip = self.entity_config.get(entity_id, "Null").strip()

        # Step 1: 确定种子 (Seeds)
        seeds = []
        
        if p_type in ["MATCHED", "UNCLAIMED"]:
            # 严格模式：只准使用 physical_id 绑定的流
            phys_id = primitive.get('physical_id')
            if phys_id:
                seeds = [f for f in self.pool if f.get('net_id') == phys_id]
            # 如果是这两类但没找到 physical_id，seeds 保持为空，不会进入下面的盲搜
        
        elif p_type == "UNSUPPORTED":
            # 只有 UNSUPPORTED 允许盲搜
            idx_start = bisect.bisect_left(self.pool_ts, t0 - self.window)
            idx_end = bisect.bisect_right(self.pool_ts, t0 + self.window)
            time_scope_flows = self.pool[idx_start:idx_end]
            
            for f in time_scope_flows:
                f_ips = self._get_ips_from_flow(f)
                f_label = f.get('label', 'Unknown')
                
                # 检查 IP 匹配或标签匹配
                is_target = (target_ip != "Null" and target_ip in f_ips) or (entity_id in f_label)
                if is_target:
                    seeds.append(f)

        # Step 2: 递归扩张 (Interaction Expansion)
        # 即使种子确定了，扩张时也要小心网关噪音
        expanded_set = {f['net_id']: f for f in seeds}
        current_wave = seeds

        for _ in range(max_hops):
            next_wave = []
            for seed in current_wave:
                seed_ips = self._get_ips_from_flow(seed)
                # 关键：扩张时剔除网关 IP，只按设备私有 IP 找关联流
                device_ips = seed_ips - {self.gateway_ip} 
                
                seed_ts = seed['ts']
                c_start = bisect.bisect_left(self.pool_ts, seed_ts - 1.5) # 窗口收紧到 1.5s
                c_end = bisect.bisect_right(self.pool_ts, seed_ts + 1.5)
                
                for candidate in self.pool[c_start:c_end]:
                    cid = candidate['net_id']
                    if cid in expanded_set: continue
                    
                    can_ips = self._get_ips_from_flow(candidate)
                    # 只有当非网关的设备 IP 有交集时才认为是因果相关的
                    if device_ips.intersection(can_ips):
                        expanded_set[cid] = candidate
                        next_wave.append(candidate)
            
            if not next_wave: break
            current_wave = next_wave

        return {
            "entity_id": entity_id,
            "primitive": primitive,
            "context_flows": sorted(list(expanded_set.values()), key=lambda x: x['ts'])
        }

        return {
            "entity_id": entity_id,
            "primitive": primitive,
            "context_flows": sorted(list(expanded_set.values()), key=lambda x: x['ts'])
        }

    def batch_select(self, primitives: List[Dict]) -> List[Dict]:
        """对所有节点进行因果切片，但过滤掉无意义的噪音种子"""
        results = []
        for p in primitives:
            m = p.get('metadata', {})
            label_str = m.get("label", "")
            # 提取 entity_id
            entity_id = label_str.split('|')[0].strip() if '|' in label_str else label_str
            
            # 关键门禁逻辑：
            # 1. 如果是 MATCHED 或 UNSUPPORTED，必须处理
            # 2. 如果是 UNCLAIMED，只有当它有明确的 entity_id (非 Unknown) 时才处理
            if p['type'] in ["MATCHED", "UNSUPPORTED"] or (p['type'] == "UNCLAIMED" and entity_id != "Unknown"):
                results.append(self.select_by_propagation(p))
            else:
                # 剩下的就是 Unknown + UNCLAIMED，这些是纯噪音，直接跳过
                continue
        return results

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

# 2. 初始化筛选器
# 注意：确保 entity_config 已经正确加载
selector = InteractionCausalSelector(all_net_atoms, entity_config)

# 3. 批量获取因果上下文
# 现在 batch_select 已经在类中定义好了
causal_contexts = selector.batch_select(dsa_primitives)
print("\n" + "="*140)
print(f"{'NET_ID':<8} | {'TIMESTAMP':<15} | {'DIRECTION':<45} | {'SIGNATURE (SEQ)':<40} | {'LABEL'}")
print("-" * 140)

# 4. 打印结果
for ctx in causal_contexts[:-8]:
    # --- 修复位置：从 ctx 中提取 primitive 对象 ---
    p = ctx['primitive'] 
    flows = sorted(ctx['context_flows'], key=lambda x: x['ts'])
    
    # 获取 metadata 方便后续取 app 时间戳等信息
    metadata = p.get('metadata', {})
    
    print(f"\n\033[1m[Anchor Check] {ctx['entity_id']} | Type: {p['type']} | Total Flows: {len(flows)}\033[0m")
    
    for f in flows:
        anchor = f.get('anchor') or {} 
        sig = anchor.get('payload_digest', "[]")
        
        # 提取方向
        src = anchor.get('src_ip', '?')
        dst = anchor.get('dst_ip', '?')
        direction = f"{src} -> {dst}"
        
        # 颜色标记逻辑
        color = ""
        if "203" in str(sig):
            color = "\033[91m" # 命中 GT，红色高亮
        elif f.get('label') != "Unknown":
            color = "\033[92m" # 已识别指纹，绿色
            
        ts_str = f"{f['ts']:<15.3f}"
        print(f"{color}{f['net_id']:<8} | {ts_str} | {direction:<45} | {str(sig):<40} | {f.get('label')}\033[0m")