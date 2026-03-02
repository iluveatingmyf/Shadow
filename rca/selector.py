import os
import json
import sys
current_dir = os.path.dirname(os.path.abspath(__file__))
# 获取项目根目录 (rca/ 的上一级，即 shadowprov/)
project_root = os.path.abspath(os.path.join(current_dir, ".."))

# 1. 解决跨文件夹调用 dsa_engine 的问题
if project_root not in sys.path:
    sys.path.append(project_root)

# 2. 修改文件加载函数，使其基于根目录
def get_absolute_path(relative_path):
    """将基于根目录的相对路径转换为绝对路径"""
    return os.path.join(project_root, relative_path)
    

# 1. 解决跨文件夹调用 dsa_engine 的问题
if project_root not in sys.path:
    sys.path.append(project_root)

import logging
import collections
import bisect
from datetime import datetime
from typing import List, Dict, Set, Any
from dsa.dsa_engine import DeviationSearchEngine
logger = logging.getLogger("CAUSAL_SELECTOR")

class InteractionCausalSelector:
    """
    基于偏差约束的因果子图切片器 (Deviation-Guided Causal Slicer)
    实现论文中的 Spatio-temporal Causal Reachability Analysis
    """
    def __init__(self, net_atomic_pool: List[Dict], entity_config: Dict[str, str], gateway_ip: str = "192.168.0.1", control_plane_ip: str = "192.168.0.157"):
        # 按照时间戳排序，构建时空搜索的数据底座
        self.pool = sorted(net_atomic_pool, key=lambda x: x['ts'])
        self.pool_ts = [f['ts'] for f in self.pool]
        
        # 拓扑角色定义 (Topological Roles)
        self.control_plane_ip = control_plane_ip  # 控制面中心 (HA/Gateway)
        self.gateway_ip = gateway_ip              # 边界网关
        self.entity_config = entity_config        # 数据面实体 (Data Plane Entities)
        
        # 搜索超参
        self.base_window = 10.0   # 基础容差窗口
        self.anchor_window = 1.0  # 控制面锚点回溯极窄窗口

    def _get_ips_from_flow(self, flow: Dict) -> Set[str]:
        ips = set()
        anchor = flow.get('anchor')
        if anchor:
            if 'src_ip' in anchor: ips.add(anchor['src_ip'])
            if 'dst_ip' in anchor: ips.add(anchor['dst_ip'])
        if 'target_ip' in flow: ips.add(flow['target_ip'])
        return ips

    def slice_causal_subgraph(self, primitive: Dict[str, Any], max_hops: int = 1) -> Dict[str, Any]:
        t0 = primitive['timestamp']
        p_type = primitive.get('type')
        m = primitive.get('metadata', {})
        label_str = m.get("label", "")
        entity_id = label_str.split('|')[0].strip() if '|' in label_str else label_str
        target_device_ip = self.entity_config.get(entity_id, "Null").strip()

        seeds =[]
        tracked_ips = {target_device_ip} if target_device_ip != "Null" else set()
        # ==========================================
        # Phase 1: Causality Anchoring (锚点定位)
        # ==========================================
        if p_type in["MATCHED", "UNCLAIMED"]:
            # [物理层已证实]: 直接使用底层 Net Atomic 作为因果种子
            phys_id = primitive.get('physical_id')
            if phys_id:
                seeds =[f for f in self.pool if f.get('net_id') == phys_id]
                
        elif p_type == "UNSUPPORTED":
            # [因果断裂 / 物理层虚无]: 触发 Control-Plane Anchoring (控制面锚点回溯)
            idx_start = bisect.bisect_left(self.pool_ts, t0 - self.base_window)
            idx_end = bisect.bisect_right(self.pool_ts, t0 + self.base_window)
            
            # 1. 常规数据面拾遗
            for f in self.pool[idx_start:idx_end]:
                f_ips = self._get_ips_from_flow(f)
                if (target_device_ip != "Null" and target_device_ip in f_ips) or (entity_id in f.get('label', '')):
                    seeds.append(f)
            
            # 2. 控制面恶意注入回溯 (Cyber Event Injection)
            n_start = bisect.bisect_left(self.pool_ts, t0 - self.anchor_window)
            n_end = bisect.bisect_right(self.pool_ts, t0 + self.anchor_window)
            for f in self.pool[n_start:n_end]:
                if f in seeds: continue
                f_ips = self._get_ips_from_flow(f)
                
                # 约束：涉及控制平面，但不涉及目标设备，且未被认证(Unknown)
                if self.control_plane_ip in f_ips and target_device_ip not in f_ips:
                    if f.get('label') == "Unknown":
                        seeds.append(f)
                        # 将未知攻击者 IP 纳入追踪集合，以便后续扩展
                        new_culprit = f_ips - {self.control_plane_ip, self.gateway_ip}
                        tracked_ips.update(new_culprit)

        # ==========================================
        # Phase 2: Spatio-temporal Expansion (时空传播与子图提取)
        # ==========================================
        expanded_set = {f['net_id']: f for f in seeds}
        
        # 初始追踪集合补充
        for s in seeds:
            tracked_ips.update(self._get_ips_from_flow(s) - {self.gateway_ip})

        current_wave = seeds
        for _ in range(max_hops):
            next_wave =[]
            for seed in current_wave:
                seed_ts = seed['ts']
                # 传播时间约束: 允许向后追溯原因 (-2.0s), 向前追踪结果 (+5.0s)
                c_start = bisect.bisect_left(self.pool_ts, seed_ts - 2.0)
                c_end = bisect.bisect_right(self.pool_ts, seed_ts + 5.0) 
                
                for candidate in self.pool[c_start:c_end]:
                    cid = candidate['net_id']
                    if cid in expanded_set: continue
                    
                    can_ips = self._get_ips_from_flow(candidate)
                    # 拓扑连通性约束
                    if tracked_ips.intersection(can_ips):
                        expanded_set[cid] = candidate
                        next_wave.append(candidate)
                        tracked_ips.update(can_ips - {self.gateway_ip, "Null"})
            
            if not next_wave: break
            current_wave = next_wave

        return {
            "entity_id": entity_id,
            "primitive": primitive,
            "context_flows": sorted(list(expanded_set.values()), key=lambda x: x['ts'])
        }

    def batch_extract(self, primitives: List[Dict]) -> List[Dict]:
        results =[]
        for p in primitives:
            m = p.get('metadata', {})
            entity_id = m.get("label", "").split('|')[0].strip()
            
            # 噪音门禁：忽略纯虚拟包和无实体的 UNCLAIMED
            if m.get('sig') == 'VIRTUAL': continue
            if p['type'] == "UNCLAIMED" and entity_id == "Unknown": continue
            
            results.append(self.slice_causal_subgraph(p))
        return results

"""PCAP_FILE = get_absolute_path("RawLogs/A1/S2/delay/capture_br-lan.pcap")
PROFILES_DIR = get_absolute_path("dsa/profiles") 
ENTITY_CONFIG_PATH = get_absolute_path("dsa/profiles/entity_config.json")
APP_LOG_FILE = get_absolute_path("data/app_atomics_A1S2Delay.json")
def load_json(filename):
    path = os.path.join(filename)
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f: return json.load(f)
    return {}
            
# --- 新增：加载实体配置 ---
entity_config= load_json(ENTITY_CONFIG_PATH).get("ENTITY_CONFIG", {})

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
causal_contexts = selector.batch_extract(dsa_primitives)
print("\n" + "="*140)
print(f"{'NET_ID':<8} | {'TIMESTAMP':<15} | {'DIRECTION':<45} | {'SIGNATURE (SEQ)':<40} | {'LABEL'}")
print("-" * 140)

# 4. 打印结果
for ctx in causal_contexts[:-8]:
    p = ctx['primitive']  
    print(p)
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
        print(f"{color}{f['net_id']:<8} | {ts_str} | {direction:<45} | {str(sig):<40} | {f.get('label')}\033[0m")"""