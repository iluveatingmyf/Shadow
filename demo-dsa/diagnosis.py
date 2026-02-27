import numpy as np
import logging
from typing import List, Dict, Any, Tuple
logger = logging.getLogger("RCA_DIAGNOSER")

class RCADiagnoser:
    def __init__(self, entity_config: Dict):
        # 实体 IP 配置映射：{ "switch.chuangmi_xxx": "192.168.0.61" }
        self.entity_config = entity_config
        # 债务池 1: 挂起的 App 指令 (UNSUPPORTED CMD)
        # 等待未来的 MATCHED (Entity) 来偿还 -> 判定为 Command Delay
        self.cmd_intent_pool = {} # { entity_id: [records...] }

        # 债务池 2: 孤儿的物理状态 (UNCLAIMED Entity)
        # 等待未来的 UNSUPPORTED (State) 来认领 -> 判定为 State Delay
        self.orphan_state_pool = {} # { entity_id: [records...] }

    def _get_ent_type(self, ent_id: str) -> str:
        return ent_id.split('.')[0] if '.' in ent_id else "unknown"


    def _calculate_stitch_score(self, debt, current_sem, current_ts, current_ent_type):
        """因果缝合核心算法"""
        # 硬过滤 1: 类型必须一致
        if debt['ent_type'] != current_ent_type: return 0.0
        
        dt = current_ts - debt['ts']
        # 硬过滤 2: 时间必须是正向的，且在合理延迟范围内 (30s)
        if dt <= 0 or dt > 120: return 0.0
        
        # 评分项 1: 时间衰减
        score_time = np.exp(-0.1 * dt)
        
        # 评分项 2: 语义映射 (例如 turn_on 映射为 on/armed_home 等)
        # 这里建议根据你的 Profile 扩展映射表
        score_sem = 1.0 if debt['semantic'] in current_sem or current_sem in debt['semantic'] else 0.1
        
        return score_time * 0.4 + score_sem * 0.6



    def diagnose(self, features: Dict, primitive: Dict) -> Dict:
        p_type = features['p_type']
        meta = primitive['metadata']
        ent_id = meta.get('label', '').split('|')[0].strip()
        semantic = meta.get('label', '').split('|')[1].strip()
        ts = primitive['timestamp']
        ent_type = self._get_ent_type(ent_id)


        current_slot = meta.get('slot') 
        
        # 兼容性处理：如果是从原始 app_events 生成的 Primitive
        if not current_slot:
            # 这里的逻辑对应你之前 dsa_engine 里的 category 分类
            current_slot = "STATE" if "State_" in primitive.get('node_id', '') else "CMD"

        result = {"root_cause": "Unknown", "attack_atomic": "None", "explanation": "", "confidence": 0.0}

        # ==============================================================================
        # Case 1: UNSUPPORTED (App 有，Net 无) -> 可能是 State Delay 的结束 或 Cmd Delay 的开始
        #==============================================================================
        if p_type == "UNSUPPORTED":
            if current_slot == "CMD":
                # [Command Delay 路径 A-1]: 入债务池
                if ent_id not in self.cmd_intent_pool: self.cmd_intent_pool[ent_id] = []
                self.cmd_intent_pool[ent_id].append({
                    "ts": ts, "semantic": semantic, "ent_type": ent_type, "features": features
                })
                # 初始判定
                result.update(root_cause="Network/Attacker", attack_atomic="CMD_INTERCEPTED_PENDING", confidence=0.5)

            else: # Slot is STATE
                # [State Delay 路径 B-2]: 尝试找“孤儿”缝合
                candidates = self.orphan_state_pool.get(ent_id, [])
                best_idx, max_conf = self._find_best(candidates, semantic, ts, ent_type)
                if best_idx is not None and max_conf > 0.6:
                    debt = self.orphan_state_pool[ent_id].pop(best_idx)
                    result.update(root_cause="MITM/Delay", attack_atomic="STATE_DELAY", 
                                explanation=f"Physical event at -{ts-debt['ts']:.2f}s finally logged by App.", confidence=max_conf)
                else:
                    result.update(root_cause="App Logic", attack_atomic="FABRICATED_LOG", confidence=1.0)
                    
        # # ==============================================================================
        # Case 2: UNCLAIMED (App 无，Net 有) -> 可能是 State Delay 的开始 或 Cmd Delay 的结束
        # ==============================================================================
        elif p_type == "UNCLAIMED":
            # [State Delay 路径 B-1]: 入孤儿池
            if ent_id not in self.orphan_state_pool: self.orphan_state_pool[ent_id] = []
            self.orphan_state_pool[ent_id].append({
                "ts": ts, "semantic": semantic, "ent_type": ent_type, "features": features
            })
            
            # [Command Delay 路径 A-2 (Option)]: 尝试缝合债务
            candidates = self.cmd_intent_pool.get(ent_id, [])
            best_idx, max_conf = self._find_best(candidates, semantic, ts, ent_type)
            if best_idx is not None and max_conf > 0.6:
                debt = self.cmd_intent_pool[ent_id].pop(best_idx)
                self.orphan_state_pool[ent_id].pop() # 平账，不需要留在孤儿池
                result.update(root_cause="MITM/Replay", attack_atomic="COMMAND_DELAY", confidence=max_conf)
            else:
                # 真正的孤儿：检查是否为固件劫持
                if features['is_unknown_protocol'] and features['has_bypass']:
                    result.update(root_cause=features['bypass_ip'], attack_atomic="FIRMWARE_UNAUTHORIZED_CONTROL", confidence=1.0)
                else:
                    result.update(root_cause="Physical", attack_atomic="ORPHAN_PHYSICAL", confidence=0.8)

        # ==============================================================================
        # Case 3: MATCHED (完美对齐) -> 检查是否为延迟后达成 或 固件注入
        # ==============================================================================
        elif p_type == "MATCHED":
            # 检查是否有挂起的 CMD 债务
            candidates = self.cmd_intent_pool.get(ent_id, [])
            best_idx, max_conf = self._find_best(candidates, semantic, ts, ent_type)
            
            if best_idx is not None and max_conf > 0.6:
                debt = self.cmd_intent_pool[ent_id].pop(best_idx)
                result.update(root_cause="MITM/Buffer", attack_atomic="COMMAND_DELAY", 
                              explanation=f"Delayed execution. Intent matched with past block (-{ts-debt['ts']:.2f}s)", confidence=max_conf)
            elif features['is_unknown_protocol']:
                # 状态对齐了，但包是 Unknown 的 -> 固件注入攻击
                result.update(root_cause=features.get('bypass_ip', "Unknown"), attack_atomic="FIRMWARE_INJECTION_MATCHED", confidence=1.0)
            else:
                result.update(root_cause="BENIGN", attack_atomic="NORMAL", confidence=1.0)

        return result

    def _find_best(self, pool, semantic, ts, ent_type):
        best_idx, max_conf = None, 0.0
        for i, debt in enumerate(pool):
            score = self._calculate_stitch_score(debt, semantic, ts, ent_type)
            if score > max_conf:
                max_conf, best_idx = score, i
        return best_idx, max_conf