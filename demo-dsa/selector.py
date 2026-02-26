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
        # 获取目标设备 IP
        target_device_ip = self.entity_config.get(entity_id, "Null").strip()

        # Step 1: 确定种子 (Seeds)
        seeds = []
        if p_type in ["MATCHED", "UNCLAIMED"]:
            phys_id = primitive.get('physical_id')
            if phys_id:
                seeds = [f for f in self.pool if f.get('net_id') == phys_id]
        elif p_type == "UNSUPPORTED":
            idx_start = bisect.bisect_left(self.pool_ts, t0 - self.window)
            idx_end = bisect.bisect_right(self.pool_ts, t0 + self.window)
            time_scope_flows = self.pool[idx_start:idx_end]
            for f in time_scope_flows:
                f_ips = self._get_ips_from_flow(f)
                if (target_device_ip != "Null" and target_device_ip in f_ips) or (entity_id in f.get('label', '')):
                    seeds.append(f)

        # Step 2: 通用交互扩张 (Interaction Expansion)
        # 逻辑：只要包的 Src 或 Dst 涉及目标设备 IP，即视为证据链的一部分
        expanded_set = {f['net_id']: f for f in seeds}
        
        # 定义需要追踪的“证据主体 IP 集”
        tracked_ips = {target_device_ip} if target_device_ip != "Null" else set()
        
        # 初始波次包含种子中发现的所有非网关设备 IP (应对联动场景)
        for s in seeds:
            tracked_ips.update(self._get_ips_from_flow(s) - {self.gateway_ip})

        current_wave = seeds
        for _ in range(max_hops):
            next_wave = []
            for seed in current_wave:
                seed_ts = seed['ts']
                # 扩张窗口可以稍微放宽，以捕捉潜在的重传或延迟前兆
                c_start = bisect.bisect_left(self.pool_ts, seed_ts - 2.0)
                c_end = bisect.bisect_right(self.pool_ts, seed_ts + 5.0) # 向后多看一点，覆盖 Delay
                
                for candidate in self.pool[c_start:c_end]:
                    cid = candidate['net_id']
                    if cid in expanded_set: continue
                    
                    can_ips = self._get_ips_from_flow(candidate)
                    # 通用判定：只要候选包涉及任何一个被追踪的设备 IP
                    if tracked_ips.intersection(can_ips):
                        expanded_set[cid] = candidate
                        next_wave.append(candidate)
                        # 发现新关联设备 IP，加入追踪（处理 A 触发 B 的情况）
                        new_ips = can_ips - {self.gateway_ip, "Null"}
                        tracked_ips.update(new_ips)
            
            if not next_wave: break
            current_wave = next_wave

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
    p = ctx['primitive']  
    # 在判断的同时赋值给 sig
    if (sig := p['metadata'].get('sig')) == 'VIRTUAL':
        continue
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