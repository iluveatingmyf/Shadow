import logging
import json
import os
import collections
from enum import Enum
from datetime import datetime, date
from typing import TypedDict, Optional, List, Dict, Set, Any, Tuple

from core.net_atomic import ForensicFlowGenerator

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("DSA_ENGINE")

class AlignmentType(Enum):
    MATCHED = "MATCHED"              
    UNSUPPORTED = "UNSUPPORTED"      
    UNCLAIMED = "UNCLAIMED"          

class FlowAnchor(TypedDict):
    flow_key: str 
    src_ip : str
    dst_ip : str
    src_mac: str
    dst_mac: str                  
    start_time: float
    end_time: float
    packet_count: int
    payload_digest: Optional[str]    

class DSAPrimitive(TypedDict):
    type: str                        
    node_id: Optional[str]           
    physical_id: Optional[str]       
    timestamp: float                 
    metadata: Dict[str, Any]         
    anchor: Optional[FlowAnchor]     

class DeviationSearchEngine:
    def __init__(self, pcap_path: str, app_log_path: str, profiles_dir: str, gateway_ip: str):
        self.pcap_path = pcap_path
        self.app_log_path = app_log_path
        self.gateway_ip = gateway_ip
        
        self.sensor_timeout = 10.0 
        self.app_events = []
        self.net_events = []
        self.consumed_slots = collections.defaultdict(set)
        
        # 模式锁：一旦传感器触发，该 Session 锁定该指纹
        self.active_pattern_locks = {}
        # 核心修改：先清空，由 _load_profiles 填充
        self.ENTITY_CONFIG = {}
        self.AMBIGUOUS_DEVICES = set()
        self.INTEGRATED_DEVICES = set()
        self.ENTITY_MAP = {}
        self._load_profiles(profiles_dir)

    def _load_profiles(self, profiles_dir: str):
        def load_json(filename):
            path = os.path.join(profiles_dir, filename)
            if os.path.exists(path):
                with open(path, 'r', encoding='utf-8') as f: return json.load(f)
            return {}
            
        # --- 新增：加载实体配置 ---
        ent_cfg_data = load_json("entity_config.json")
        self.ENTITY_CONFIG = ent_cfg_data.get("ENTITY_CONFIG", {})
        self.AMBIGUOUS_DEVICES = set(ent_cfg_data.get("AMBIGUOUS_DEVICES", []))
        self.INTEGRATED_DEVICES = set(ent_cfg_data.get("INTEGRATED_DEVICES", []))
        # -----------------------


        self.actuator_db = load_json("actuator_profiles.json")
        raw_sensors = load_json("sensor_profiles.json")
        if not raw_sensors: raw_sensors = load_json("action_profiles.json")
            
        self.sensor_db = collections.defaultdict(list)
        if isinstance(raw_sensors, list):
            for item in raw_sensors:
                lbl = item.get('label')
                kp = item.get('key_packets', [])
                if lbl and kp: self.sensor_db[lbl].append(kp)
        else: self.sensor_db = raw_sensors 

        self.ENTITY_MAP = {
            "sensor.linp_hb01_7654_occupancy_sensor": "presence_sensor",
            "binary_sensor.lumi_bmgl01_2821_motion_sensor": "motion_sensor",
            "binary_sensor.isa_dw2hl_3ff9_contact_state": "door_sensor",
        }
        
        raw_idle = load_json("idle_fingerprints.json")
        self.idle_elements = {40, 52, 60, 66}
        if isinstance(raw_idle, dict):
            for tk, patterns in raw_idle.items():
                for p in patterns: 
                    for val in p: self.idle_elements.add(abs(val))

    
    # 修改 _is_subsequence 的调用逻辑或重写一个严格校验
    def _is_strict_subset(self, pattern: List[int], flow_sig: List[int]) -> bool:
        """要求 pattern 必须完整地、按顺序作为子集存在于 flow_sig 中"""
        if not pattern: return False
        it = iter(flow_sig)
        # 不再使用 margin，要求值必须完全相等
        return all(s in it for s in pattern)

    def get_results_bundle(self) -> Dict[str, Any]:
        """
        返回一个包含全量网络原子池和对齐结果的数据包
        """
        # 确保已经运行了分析
        if not self.net_events:
            primitives = self.run_alignment()
        else:
            primitives = self.run_alignment() # 或者是直接获取已有的结果

        return {
            "net_atomic_pool": self.net_events,  # 每一个都带 net_id 的全量池
            "dsa_primitives": primitives }       # 跨层对齐后的结果
            
    def _is_subsequence(self, target_pkts: List[int], flow_sig: List[int], ignore_sign: bool = False, margin: int = 0) -> bool:
        if not target_pkts: return False
        it = iter([abs(x) for x in flow_sig] if ignore_sign else flow_sig)
        targets = [abs(x) for x in target_pkts] if ignore_sign else target_pkts
        return all(any(abs(m - s) <= margin for m in it) for s in targets)

    def _purify_flow_signature(self, sig: List[int], noise_patterns: Set[Tuple[int, ...]]) -> List[int]:
        purified = list(sig)
        for noise in noise_patterns:
            noise_list = list(noise)
            if all(purified.count(p) >= noise_list.count(p) for p in set(noise_list)):
                for p in noise_list: purified.remove(p)
        return purified

    def _extract_net_events(self):
        logger.info("[*] Generating Atomic Flows, performing Dehydration and Pattern Lock...")
        
        fg = ForensicFlowGenerator(self.pcap_path, silence_threshold=0.5)
        raw_flows = fg.get_flows_all(gateway_ip=self.gateway_ip)
        print(raw_flows[0])
        
        sig_counter = collections.Counter((f.initiator, tuple(f.signature)) for f in raw_flows)
        noise_patterns = {sig for (ip, sig), count in sig_counter.items() if count > 5}
        
        continuous_sensors = collections.defaultdict(list)
        self.active_pattern_locks = {} 

        for flow in sorted(raw_flows, key=lambda x: x.start_ts):
            #print(f"DEBUG: Flow {flow.start_ts} | Init: {flow.initiator} | Target: {flow.target_ip}")
            orig_sig = flow.signature
            sig_tuple = tuple(orig_sig)
            
            if sig_tuple in noise_patterns: continue
            
            purified_sig = self._purify_flow_signature(orig_sig, noise_patterns)
            if not purified_sig: continue
            
            sig = purified_sig
            sig_tuple_purified = tuple(sig)
            flow_ips = {flow.initiator, flow.target_ip}

            # --- 提取 MAC 地址 (从 flow 对象中获取) ---
            # 假设你已经按照之前的建议修改了 netaudit.py 
            s_mac = getattr(flow, 'src_mac', "00:00:00:00:00:00")
            d_mac = getattr(flow, 'dst_mac', "00:00:00:00:00:00")

            match_found = False
            label_suffix, caps = "", set()

            for ent_id, target_ip in self.ENTITY_CONFIG.items():
                if target_ip != "Null" and target_ip not in flow_ips: continue
                
                # 1. 模式锁优先
                locked_pat = self.active_pattern_locks.get(ent_id)
                if locked_pat:
                    # 如果有锁，必须严格符合锁定的指纹
                    if self._is_strict_subset(list(locked_pat), sig):
                        match_found = True
                        label_suffix = "has one" if "presence" in ent_id else "on" if "motion" in ent_id else "off"
                        caps = {'STATE'}
                    else:
                        continue

                if not match_found:
                    # 2. Actuator 匹配 (margin=3)
                    for db_key, profile in self.actuator_db.items():
                        if not db_key.startswith(ent_id): continue
                        is_c = self._is_subsequence(profile.get('cmd', []), sig, margin=0)
                        #print(profile.get('ent',[]))
                        is_e = self._is_subsequence(profile.get('ent', []), sig, margin=3)
                        if is_c: caps.add('CMD')
                        if is_e: caps.add('STATE')
                        
                        if (is_c or is_e) and ent_id in self.INTEGRATED_DEVICES:
                            caps.update(['CMD', 'STATE'])

                        if is_c or is_e:
                            match_found, label_suffix = True, db_key.split('|')[-1].strip()
                            #print(db_key)
                            #print(label_suffix)
                            if label_suffix in ["on", "off", "has one"]: 
                                self.active_pattern_locks[ent_id] = sig_tuple_purified
                            break
                        
                        # Manual On/Off
                        for s in ['on', 'off']:
                            pats = profile.get(s, [])
                            if pats:
                                target = pats[0] if isinstance(pats[0], list) else pats
                                if self._is_subsequence(target, sig, margin=2):
                                    match_found, label_suffix = True, s
                                    caps.update(['CMD', 'STATE'])
                                    self.active_pattern_locks[ent_id] = sig_tuple_purified
                                    break
                        if match_found: break

                    # 3. Sensor 匹配
                    if not match_found:
                        gen_lbl = self.ENTITY_MAP.get(ent_id)
                        if gen_lbl in self.sensor_db:
                            for pat in self.sensor_db[gen_lbl]:
                                # --- 关键修改点 1: 降低模糊匹配的容忍度，或者分两步走 ---
                                # 只有当指纹匹配非常接近时（例如 margin=0 或 1），才允许“建锁”
                                is_weak_match = self._is_subsequence(pat, sig, ignore_sign=True, margin=2)
                                is_strong_match = self._is_subsequence(pat, sig, ignore_sign=True, margin=0) # 要求完全一致

                                if is_weak_match:
                                    match_found = True
                                    label_suffix = "has one" if "presence" in gen_lbl else "on" if "motion" in gen_lbl else "off"
                                    caps = {'STATE'}
                                    
                                    # --- 关键修改点 2: 只有强匹配才准许建立“模式锁” ---
                                    if is_strong_match:
                                        self.active_pattern_locks[ent_id] = sig_tuple_purified
                                        # logger.info(f"[*] 建立了高置信度锁定: {ent_id} -> {sig_tuple_purified}")
                                    
                                    break

                
                if match_found:
                    full_label = f"{ent_id} | {label_suffix}"
                    anchor = FlowAnchor(
                        flow_key=f"{flow.start_ts}_{flow.initiator}", 
                        src_ip=flow.initiator,
                        dst_ip=flow.target_ip, 
                        src_mac=s_mac, # 注入 MAC
                        dst_mac=d_mac, # 注入 MAC
                        start_time=flow.start_ts, 
                        end_time=flow.end_ts, 
                        packet_count=len(sig), 
                        payload_digest=str(sig)
                    )
                    # 必须把这些带入 net_events，因为后续的 ContextualGraph 是基于 net_events 构建的
                    self.net_events.append({
                        "ts": flow.start_ts, 
                        "label": full_label, 
                        "anchor": anchor, 
                        "type": "Matched_Flow", 
                        "caps": list(caps)
                    })
                    if label_suffix in ["on", "off", "has one"]: continuous_sensors[full_label].append(flow.start_ts)
                    break

            if not match_found:
                anchor = FlowAnchor(
                flow_key=f"{flow.start_ts}_{flow.initiator}", 
                src_ip=flow.initiator,
                dst_ip=flow.target_ip,
                src_mac=s_mac,
                dst_mac=d_mac,
                start_time=flow.start_ts, 
                end_time=flow.end_ts, 
                packet_count=len(sig), 
                payload_digest=str(sig)
                )
                self.net_events.append({
                    "ts": flow.start_ts, 
                    "label": "Unknown", 
                    "anchor": anchor, 
                    "type": "Unknown_Flow", 
                    "caps": []
                })

        self._build_virtual_state_machine(continuous_sensors)
        self.net_events.sort(key=lambda x: x['ts'])

         # --- 新增逻辑：赋予全局唯一的 net_id ---
        for idx, ev in enumerate(self.net_events):
            ev['net_id'] = f"N{idx+1:04d}"



    def _build_virtual_state_machine(self, continuous_sensors):
        RULES = {"has one": "no one", "on": "off", "off": "on"}
        for active_label, timestamps in continuous_sensors.items():
            parts = active_label.split('|')
            ent_id, state = parts[0].strip(), parts[1].strip()
            if state not in RULES: continue
            timestamps.sort()
            for i in range(len(timestamps)):
                if i == len(timestamps) - 1 or (timestamps[i+1] - timestamps[i] > self.sensor_timeout):
                    if ent_id in self.active_pattern_locks: del self.active_pattern_locks[ent_id]
                    self.net_events.append({"ts": timestamps[i] + self.sensor_timeout, "label": f"{ent_id} | {RULES[state]}", "anchor": None, "type": "VIRTUAL_TIMEOUT", "caps": ['STATE']})

    def _parse_app_logs_with_date(self, target_date: date):
        if not os.path.exists(self.app_log_path): return
        with open(self.app_log_path, 'r', encoding='utf-8') as f: raw_data = json.load(f)
        nodes = raw_data.get("nodes", []) if isinstance(raw_data, dict) else raw_data
        self.app_events = []
        for log in nodes:
            ts_str = log.get('timestamp')
            if not ts_str: continue
            dt = datetime.strptime(ts_str, "%H:%M:%S.%f") if '.' in ts_str else datetime.strptime(ts_str, "%H:%M:%S")
            log_ts = datetime.combine(target_date, dt.time()).timestamp()
            if log.get('kind') == 'Entity':
                self.app_events.append({"ts": log_ts, "label": f"{log['entity_id']} | {log.get('new_state', 'active')}", "node_id": f"State_{log.get('id')}", "category": "STATE"})
            elif log.get('event_type') == 'Command' or log.get('kind') == 'Activity':
                target = log.get('target_device') or log.get('device')
                if target: self.app_events.append({"ts": log_ts, "label": f"{target} | {log.get('command')}", "node_id": f"Cmd_{log.get('id')}", "category": "CMD"})
        self.app_events.sort(key=lambda x: x['ts'])

    def run_alignment(self) -> List[DSAPrimitive]:
        self._extract_net_events()
        if not self.net_events: return []
        pcap_date = datetime.fromtimestamp(self.net_events[0]['ts']).date()
        self._parse_app_logs_with_date(pcap_date)
        
        results, self.consumed_slots = [], collections.defaultdict(set)
        
        matched_cmds = {}
        for app_ev in self.app_events:
            app_ent, app_cat = app_ev['label'].split('|')[0].strip(), app_ev['category']
            app_action = app_ev['label'].split('|')[1].strip()
            
            pref_id, best_net, min_score = None, None, 60.0 # 使用 score 代替纯 dt
            
            # 1. 寻找关联上下文 (Contextual Search)
            if app_cat == 'STATE':
                for prev in results[::-1]:
                    # 寻找同实体、近期（2s内）已匹配成功的 CMD
                    if prev['metadata']['label'].startswith(app_ent) and \
                    prev['metadata'].get('slot') == 'CMD' and \
                    abs(app_ev['ts'] - prev['metadata']['app_ts_raw']) < 5.0:
                        pref_id = prev['physical_id']
                        break

            for net_ev in self.net_events:
                if net_ev['type'] == "Unknown_Flow": continue
                if '|' not in net_ev['label']: continue
                
                net_ent, net_action = net_ev['label'].split('|')[0].strip(), net_ev['label'].split('|')[1].strip()
                uid = net_ev['anchor']['flow_key'] if net_ev['anchor'] else "VIRTUAL"
                
                if app_ent == net_ent:
                    # 检查动作兼容性
                    if not (app_action in net_action or net_action in app_action or app_ent in self.AMBIGUOUS_DEVICES):
                        continue
                    # 检查能力集
                    if not (app_cat in net_ev['caps'] or net_ev['type'] == "VIRTUAL_TIMEOUT"):
                        continue
                    # 检查 Slot 是否被占用（同流同类型不可复用）
                    if uid != "VIRTUAL" and app_cat in self.consumed_slots[uid]:
                        continue
                    
                    dt = abs(net_ev['ts'] - app_ev['ts'])
                    
                    # --- 关键改进：打分机制 ---
                    score = dt
                    if uid == pref_id:
                        score -= 0.5  # 即使是同一个流，也只给一定的“亲和度”加分，而不是强制强制
                    
                    # 如果是紧随其后的另一个流（假设 Flow B 在 Flow A 之后 1s 内）
                    # 这种情况下 score 会因为 dt 很小而胜出
                    if score < min_score:
                        min_score, best_net = score, net_ev


            if best_net:
                uid = best_net['net_id'] 
                
                self.consumed_slots[uid].add(app_cat)

                # --- 修改：把 best_net['net_id'] 加入 metadata ---
                results.append(DSAPrimitive(
                    type=AlignmentType.MATCHED.value, 
                    node_id=app_ev['node_id'], 
                    physical_id=uid, 
                    timestamp=best_net['ts'], 
                    metadata={
                        "app_ts_raw": app_ev['ts'], 
                        "raw_diff_sec": round(best_net['ts'] - app_ev['ts'], 3), 
                        "label": app_ev['label'], 
                        "net_label": best_net['label'], 
                        "slot": app_cat, 
                        "sig": best_net['anchor']['payload_digest'] if best_net['anchor'] else "VIRTUAL",
                        "src_mac": best_net['anchor']['src_mac'] if best_net['anchor'] else None,
                        "dst_mac": best_net['anchor']['dst_mac'] if best_net['anchor'] else None,
                        "net_id": best_net['net_id'] # 增加这里
                    }, 
                    anchor=best_net.get('anchor')))
            else:
                # App Atomic 没有匹配到 Net Atomic (UNSUPPORTED)，所以 net_id 为 None
                results.append(DSAPrimitive(
                    type=AlignmentType.UNSUPPORTED.value, 
                    node_id=app_ev['node_id'], 
                    physical_id=None, 
                    timestamp=app_ev['ts'], 
                    metadata={"app_ts_raw": app_ev['ts'], "label": app_ev['label'], "net_id": "-"}, # 增加这里
                    anchor=None))

        # 处理 Heartbeat
        for net_ev in self.net_events:
            if not net_ev.get('anchor'): continue
            uid = net_ev['net_id'] 

            if not self.consumed_slots[uid]:
                method = "Heartbeat" if 'STATE' in net_ev['caps'] else "Ghost"
                # --- 修改：把 net_ev['net_id'] 加入 metadata ---
                results.append(DSAPrimitive(
                    type=AlignmentType.MATCHED.value if method=="Heartbeat" else AlignmentType.UNCLAIMED.value, 
                    node_id=None, 
                    physical_id=uid, 
                    timestamp=net_ev['ts'], 
                    metadata={
                        "net_ts_raw": net_ev['ts'], 
                        "label": net_ev['label'], 
                        "method": method, 
                        "sig": net_ev['anchor']['payload_digest'],
                        "net_id": net_ev['net_id'] # 增加这里
                    }, 
                    anchor=net_ev.get('anchor')))
        return results

if __name__ == "__main__":
    PCAP_FILE = "/Users/myf/shadowprov/RawLogs/A1/S2/delay/capture_br-lan.pcap" 
    APP_LOG_FILE = "./data/app_atomics_A1S2Delay.json" 
    PROFILES_DIR = "profiles"
    engine = DeviationSearchEngine(PCAP_FILE, APP_LOG_FILE, PROFILES_DIR, "192.168.0.1")
    primitives = engine.run_alignment()
    
    print("\n" + "="*240)
    # --- 修改表头，增加 NET_ID 列 ---
    print(f"{'NET_ID':<8} | {'APP TIME':<15} | {'NET TIME':<15} | {'DIFF':<10} | {'TYPE':<12} | {'SLOT':<6} | {'LABEL':<60} | {'EVIDENCE'}")
    print("-" * 240)
    
    for p in sorted(primitives, key=lambda x: x['metadata'].get('app_ts_raw', 0) or x['timestamp']):
        m = p['metadata']
        
        # --- 获取 net_id ---
        net_id = m.get('net_id', '-') 
        
        a_t = datetime.fromtimestamp(m.get('app_ts_raw', 0)).strftime('%H:%M:%S.%f')[:-3] if m.get('app_ts_raw') else "-"
        n_t = datetime.fromtimestamp(p['timestamp']).strftime('%H:%M:%S.%f')[:-3]
        diff = f"{m.get('raw_diff_sec', 0):>+8.2f}s" if 'raw_diff_sec' in m else "    -    "
        label = m.get('label') or m.get('inferred_label')
        
        c = "\033[92m" if p['type'] == "MATCHED" else ("\033[91m" if p['type'] == "UNSUPPORTED" else "\033[93m")
        if m.get('method') == "Heartbeat": c = "\033[36m"
        
        if label =="Unknown":
            continue
            
        # --- 打印时增加 net_id ---
        print(f"{net_id:<8} | {a_t:<15} | {n_t:<15} | {diff:<10} | {c}{p['type']:<12}\033[0m | {m.get('slot','-'):<6} | {label:<60} | {m.get('sig','-')[:60]}")