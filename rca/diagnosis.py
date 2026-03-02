import logging
from typing import List, Dict, Any, Tuple, Optional
from collections import defaultdict

logger = logging.getLogger("RCA_DIAGNOSER")

class RCADiagnoser:
    """
    基于攻击原子矩阵的确定性诊断器。
    使用硬性规则（无加权评分）进行根因推断。
    """
    def __init__(self, entity_config: Dict, time_window: float = 120.0):
        self.entity_config = entity_config               # 实体 IP 映射
        self.time_window = time_window                   # 最大允许延迟/提前时间（秒）
        self.cmd_intent_pool = defaultdict(list)         # 挂起的 CMD 事件 (UNSUPPORTED CMD)
        self.orphan_state_pool = defaultdict(list)       # 挂起的物理状态 (UNCLAIMED)
        self.recent_cmd_cache = defaultdict(list)        # 最近发生的 CMD 事件 {ent_id: [(ts, semantic)]} 用于排除用户手动触发

        # 语义同义词映射（可根据实际扩展）
        self.semantic_synonyms = {
            "on": ["on", "turn_on", "open"],
            "off": ["off", "turn_off", "close"],
            "has one": ["has one", "presence", "occupied"],
            "no one": ["no one", "absence", "unoccupied"],
            "armed_home": ["armed_home", "arm_home"],
            "armed_away": ["armed_away", "arm_away"],
        }
    
    
    
    def _simple_semantic_match(self, sem1: str, sem2: str) -> bool:
        # 提取动作部分：去除实体前缀（如果有）
        def extract_action(s):
            # 如果包含 '|'，取后半部分
            if '|' in s:
                s = s.split('|')[1].strip()
            # 去除常见的点分隔前缀，例如 'alarm_control_panel.alarm_arm_home' -> 'alarm_arm_home'
            parts = s.split('.')
            return parts[-1] if parts else s

        act1 = extract_action(sem1).lower()
        act2 = extract_action(sem2).lower()
        # 允许包含关系：例如 'arm_home' 和 'armed_home'
        return act1 in act2 or act2 in act1




    def _get_entity_type(self, ent_id: str) -> str:
        """提取实体类型（如 binary_sensor, light）"""
        return ent_id.split('.')[0] if '.' in ent_id else "unknown"

    def _normalize_semantic(self, sem: str) -> str:
        """将同义词归一化为标准形式"""
        sem_low = sem.lower()
        for std, syns in self.semantic_synonyms.items():
            if sem_low in syns or any(s in sem_low for s in syns):
                return std
        return sem_low

    def _semantic_match(self, sem1: str, sem2: str) -> bool:
        """判断两个语义是否匹配（如同为 'on'）"""
        return self._normalize_semantic(sem1) == self._normalize_semantic(sem2)

    def _has_fact(self, facts: List[Tuple], fact_type: str, target: Optional[str] = None) -> bool:
        """检查事实列表中是否存在指定类型（可选地限定 subject/object）"""
        for fact in facts:
            if fact[0] != fact_type:
                continue
            if target is not None:
                if fact[1] == target or fact[2] == target:
                    return True
            else:
                return True
        return False

    def _find_matching_debt(self, pool: List[Dict], semantic: str, ts: float, ent_type: str) -> Optional[Dict]:
        """在债务池中查找匹配项（类型相同、语义匹配、时间差在窗口内）"""
        for debt in pool:
            if debt['ent_type'] != ent_type:
                continue
            if not self._semantic_match(debt['semantic'], semantic):
                continue
            dt = ts - debt['ts']
            if 0 < dt <= self.time_window:
                return debt
        return None

    def _clean_recent_cache(self, ent_id: str, before_ts: float):
        """清理指定实体早于 before_ts 的最近 CMD 缓存"""
        self.recent_cmd_cache[ent_id] = [
            (t, s) for t, s in self.recent_cmd_cache[ent_id] if t >= before_ts
        ]

    def diagnose(self, primitive: Dict, facts: List[Tuple]) -> Dict:
        """
        返回诊断结果，包含：
          - root_cause: 根本原因描述
          - attack_atomic: 攻击原子名称（与矩阵一致）
          - confidence: 离散置信度 (1.0, 0.9, 0.8, 0.6, 0.5)
          - explanation: 简要解释
        """
        print("------------------------------")
        p_type = primitive['type']                     # MATCHED / UNSUPPORTED / UNCLAIMED
        meta = primitive.get('metadata', {})
        label = meta.get('label', '')
        ent_id = label.split('|')[0].strip() if '|' in label else label
        semantic = label.split('|')[1].strip() if '|' in label else ''
        ts = primitive['timestamp']
        ent_type = self._get_entity_type(ent_id)
        physical_id = primitive.get('physical_id')     # 对于 MATCHED/UNCLAIMED 有效
        print(meta)
        slot = meta.get('slot', '')                     # CMD / STATE
        print(slot)
        device_ip = self.entity_config.get(ent_id)   # 可能为 None
        # 获取状态事件的源 IP（如果有）
        src_ip = None
        if primitive.get('anchor'):
            src_ip = primitive['anchor'].get('src_ip')

        # 默认结果
        result = {
            "root_cause": "Unknown",
            "attack_atomic": "UNKNOWN",
            "confidence": 0.0,
            "explanation": ""
        }

        # --------------------------------------------------------------
        # 1. UNSUPPORTED (App有，Net无)
        # --------------------------------------------------------------
        if p_type == "UNSUPPORTED":
            if slot == "CMD":
                has_missing_response = self._has_fact(facts, 'missing_response')
                debt_record = {
                    "ts": ts,
                    "semantic": semantic,
                    "ent_type": ent_type,
                    "has_missing_response": has_missing_response,
                    "ent_id": ent_id,
                    "device_ip": device_ip,
                    "primitive_id": primitive.get('node_id')
                }
                self.cmd_intent_pool[ent_id].append(debt_record)
                self.recent_cmd_cache[ent_id].append((ts, semantic))
                self._clean_recent_cache(ent_id, ts - self.time_window)

                # 挂起，等待后续匹配（不再立即诊断为 DROP）
                # 根据是否观察到网络痕迹，给出不同的初步诊断
                if has_missing_response:
                    result.update({
                        "root_cause": "Potential CMD Delay (pending)",
                        "attack_atomic": "CMD_UNMATCHED_PENDING",
                        "confidence": 0.6,
                        "explanation": "CMD packet observed in network but no matching App flow yet, waiting for future state"
                    })
                else:
                    result.update({
                        "root_cause": "Malicious App or Internal Failure",
                        "attack_atomic": "CMD_FAILED",
                        "confidence": 0.5,
                        "explanation": "No network trace of CMD, possible malicious app injection or internal error"
                    })            
            else:  # slot == "STATE"
                # 先尝试匹配孤儿池（状态延迟）
                debt = self._find_matching_debt(self.orphan_state_pool.get(ent_id, []), semantic, ts, ent_type)
                if debt:
                    self.orphan_state_pool[ent_id].remove(debt)
                    result.update({
                        "root_cause": "MITM/Delay",
                        "attack_atomic": "STATE_DELAY",
                        "confidence": 1.0,
                        "explanation": f"Physical state at -{ts-debt['ts']:.2f}s finally logged by App"
                    })
                else:
                    # 检查是否存在发往 HA 的未知流（网络攻击者伪造状态）
                    cyber_inject = False
                    for fact in facts:
                        if fact[0] == 'unauth_inject':
                            # fact[2] 是 node_id, fact[3] 包含 ts 和 src
                            flow_ts = fact[3].get('ts')
                            if flow_ts and abs(flow_ts - ts) <= self.time_window:
                                cyber_inject = True
                                break
                    if cyber_inject:
                        result.update({
                            "root_cause": "Cyber Attacker (State Injection)",
                            "attack_atomic": "CYBER_STATE_INJECTION",
                            "confidence": 0.9,
                            "explanation": "App state event preceded by unknown flow to HA"
                        })
                    else:
                        # 无任何网络痕迹 -> 内部恶意应用
                        result.update({
                            "root_cause": "Malicious App (Internal Attacker)",
                            "attack_atomic": "MALICIOUS_APP_STATE_INJECTION",
                            "confidence": 1.0,
                            "explanation": "App state event with no matching physical trace"
                        })

        # --------------------------------------------------------------
        # 2. UNCLAIMED (Net有，App无)
        # --------------------------------------------------------------
        elif p_type == "UNCLAIMED":
            # 先入孤儿池（供未来 STATE_DELAY 匹配）
            self.orphan_state_pool[ent_id].append({
                "ts": ts,
                "semantic": semantic,
                "ent_type": ent_type
            })


            # 尝试匹配挂起的 CMD 债务（命令延迟的执行）
            matched_debt = None
            for debt in self.cmd_intent_pool.get(ent_id, []):
                dt = ts - debt['ts']
                if 0 < dt <= self.time_window:
                    # IP 匹配优先（如果都有 IP）
                    if src_ip and debt.get('device_ip') and src_ip == debt['device_ip']:
                        matched_debt = debt
                        break
                    # 否则尝试简单语义匹配
                    if self._simple_semantic_match(debt['semantic'], semantic):
                        matched_debt = debt
                        break

            if matched_debt:
                recent_cmds = [(t, s) for t, s in self.recent_cmd_cache.get(ent_id, [])
                            if matched_debt['ts'] < t < ts and self._simple_semantic_match(s, semantic)]
                if not recent_cmds:
                    self.cmd_intent_pool[ent_id].remove(matched_debt)
                    conf = 1.0 if matched_debt.get('has_missing_response') else 0.8
                    result.update({
                        "root_cause": "MITM/Replay",
                        "attack_atomic": "COMMAND_DELAY",
                        "confidence": conf,
                        "explanation": f"Delayed CMD from {ts-matched_debt['ts']:.2f}s ago (missing_response={matched_debt.get('has_missing_response')})",
                        "matched_cmd_id": matched_debt.get('primitive_id')  # 新增：记录匹配的命令原语ID
                    })
                    
            # 若未匹配债务，检查是否为固件劫持特征
            if result["attack_atomic"] == "UNKNOWN":
                has_unauth = self._has_fact(facts, 'unauth_inject', target=physical_id)
                has_spoof = self._has_fact(facts, 'mac_spoof')
                cause_from_unknown = False
                for fact in facts:
                    if fact[0] == 'cause' and fact[2] == physical_id:
                        src_flow = fact[1]
                        for f2 in facts:
                            if f2[0] == 'unauth_inject' and f2[2] == src_flow:
                                cause_from_unknown = True
                                break
                if has_unauth or has_spoof or cause_from_unknown:
                    result.update({
                        "root_cause": "Firmware Compromise / Unauthorized Control",
                        "attack_atomic": "FIRMWARE_UNAUTHORIZED_CONTROL",
                        "confidence": 0.9,
                        "explanation": "Physical state with no App record, possible direct device control"
                    })
                else:
                    result.update({
                        "root_cause": "Network Issue (Normal State Report)",
                        "attack_atomic": "ORPHAN_PHYSICAL",
                        "confidence": 0.6,
                        "explanation": "Physical state change without App record (possible packet loss)"
                    })

        # --------------------------------------------------------------
        # 3. MATCHED (完美对齐)
        # --------------------------------------------------------------
        elif p_type == "MATCHED":
            # 尝试匹配挂起的 CMD 债务（命令延迟的执行）
            matched_debt = None
            for debt in self.cmd_intent_pool.get(ent_id, []):
                dt = ts - debt['ts']
                if 0 < dt <= self.time_window:
                    if src_ip and debt.get('device_ip') and src_ip == debt['device_ip']:
                        matched_debt = debt
                        break
                    if self._simple_semantic_match(debt['semantic'], semantic):
                        matched_debt = debt
                        break

            if matched_debt:
                recent_cmds = [(t, s) for t, s in self.recent_cmd_cache.get(ent_id, [])
                            if matched_debt['ts'] < t < ts and self._simple_semantic_match(s, semantic)]
                if not recent_cmds:
                    self.cmd_intent_pool[ent_id].remove(matched_debt)
                    conf = 1.0 if matched_debt.get('has_missing_response') else 0.8
                    result.update({
                        "root_cause": "MITM/Buffer",
                        "attack_atomic": "COMMAND_DELAY",
                        "confidence": conf,
                        "explanation": f"Delayed CMD from {ts-matched_debt['ts']:.2f}s ago (missing_response={matched_debt.get('has_missing_response')})"
                    })

            # 若未匹配债务，检查是否为固件注入（被未知流 cause）
            if result["attack_atomic"] == "UNKNOWN":
                cause_from_unknown = False
                for fact in facts:
                    if fact[0] == 'cause' and fact[2] == physical_id:
                        src_flow = fact[1]
                        for f2 in facts:
                            if f2[0] == 'unauth_inject' and f2[2] == src_flow:
                                cause_from_unknown = True
                                break
                if cause_from_unknown:
                    result.update({
                        "root_cause": "Firmware Injection",
                        "attack_atomic": "FIRMWARE_INJECTION_MATCHED",
                        "confidence": 0.9,
                        "explanation": "Matched flow caused by an unknown/unauthorized flow"
                    })
                else:
                    result.update({
                        "root_cause": "BENIGN",
                        "attack_atomic": "NORMAL",
                        "confidence": 1.0,
                        "explanation": "Normal operation"
                    })

        # 清理过期债务（避免无限增长）
        current_ts = ts
        for ent, debts in list(self.cmd_intent_pool.items()):
            expired = [d for d in debts if current_ts - d['ts'] > self.time_window]
            for d in expired:
                logger.info(f"CMD debt expired for {ent}: ts={d['ts']}, semantic={d['semantic']}, has_missing_response={d.get('has_missing_response')}")
                debts.remove(d)
            if not debts:
                del self.cmd_intent_pool[ent]

        logger.debug(f"Diagnosed {p_type}/{slot} for {ent_id}: {result['attack_atomic']} (conf={result['confidence']})")
        return result