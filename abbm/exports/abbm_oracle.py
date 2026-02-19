# exports/abbm_oracle.py
import json
import os

class ABBMOracle:
    def __init__(self, graph_path='data/logic_graph.json', profile_path='data/abbm_model_final.json'):
        # 加载静态逻辑图
        with open(graph_path, 'r') as f: 
            self.logic_db = json.load(f)
        
        # 加载动态统计特征 (由 analysis_suite.py 生成)
        if os.path.exists(profile_path):
            with open(profile_path, 'r') as f: 
                self.profile_db = json.load(f)
        else:
            self.profile_db = {}
            print("[WARN] Profile DB not found. Predictions will use default values.")

    # 1. 语义映射 (保持不变)
    def tau_map(self, service_name):
        mapping = {
            'light.turn_on': 'on', 'light.turn_off': 'off',
            'switch.turn_on': 'on', 'switch.turn_off': 'off',
            'lock.lock': 'locked', 'lock.unlock': 'unlocked',
            'alarm_control_panel.alarm_arm_away': 'armed_away',
            'alarm_control_panel.alarm_arm_home': 'armed_home',
            'alarm_control_panel.alarm_arm_night': 'armed_night',
            'alarm_control_panel.alarm_disarm': 'disarmed'
        }
        return mapping.get(service_name, 'unknown')


    
    
    # 2. Match(event, rule): 匹配接口
    def match(self, event, rule_id):
        """检查某个事件是否是特定规则的触发器"""
        rule = self.logic_db.get(rule_id)
        if not rule: return False
        for trigger in rule['triggers']:
            if trigger['entity'] == event['entity'] and trigger['state'] == event['state']:
                return True
        return False

    # 3. Satisfy(global_state, rule_id): 状态验证接口
    def satisfy(self, global_state, rule_id):
        """验证当前物理状态快照是否满足规则的前提条件"""
        rule = self.logic_db.get(rule_id)
        if not rule: return False
        for cond in rule['conditions']:
            # global_state 应该是一个字典 {entity_id: current_physical_state}
            if global_state.get(cond['entity']) != cond['state']:
                return False
        return True


    # 2. [核心新增] 预测执行结果与时间戳
    # 生成Ghost type - II 节点的图节点属性
    def predict_consequences(self, rule_id, trigger_timestamp):
        """
        核心功能：基于统计模型，预测规则执行的具体后果和时间。
        用于：
        1. 显化 Ghost Node (如果日志丢失，补全后续节点)
        2. 验证 Zombie Node (如果日志时间偏差过大，判定为伪造)
        
        Args:
            rule_id: 触发的规则 ID
            trigger_timestamp: 物理触发事件发生的时间 (float timestamp)
            
        Returns:
            List[Dict]: 预测的动作列表，包含预期状态、预测时间窗、流量指纹
        """
        rule_logic = self.logic_db.get(rule_id)
        if not rule_logic:
            return []

        # 获取统计画像 (如果不存在则使用默认值)
        profile = self.profile_db.get(rule_id, {})
        
        # 提取时间统计特征 (Cyber Norm & Physical Norm)
        # 默认值: 逻辑延迟 50ms, 网络延迟 500ms
        logic_stats = profile.get('cyber_norm', {}).get('logic_delay', {'mu': 0.05, 'limit': 0.1})
        phys_stats = profile.get('physical_norm', {}).get('network_delay', {'mu': 0.5, 'limit': 1.0})
        
        # 提取流量指纹 (用于后续匹配)
        net_fingerprint = profile.get('physical_norm', {}).get('fingerprint', {})

        predictions = []

        for action in rule_logic['actions']:
            target_entity = action['entity']
            target_service = action['service']
            expected_state = self.tau_map(target_service)

            # --- 关键时间计算 ---
            # 1. 预测指令下发时间 (Predicted Call Service Time)
            pred_call_time = trigger_timestamp + logic_stats['mu']
            
            # 2. 预测状态生效时间 (Predicted State Change Time)
            # T_state = T_trigger + Logic_Delay + Net_Delay
            pred_state_time = pred_call_time + phys_stats['mu']
            
            # 3. 计算容忍窗口 (Max Tolerance Window)
            # 最晚允许的时间 = 触发时间 + 逻辑上限 + 网络上限
            max_valid_time = trigger_timestamp + logic_stats['limit'] + phys_stats['limit']

            predictions.append({
                "type": "Predicted_Effect",
                "entity": target_entity,
                "service": target_service,
                "expected_state": expected_state,
                
                # 时间预测 (Point Estimate)
                "predicted_call_ts": round(pred_call_time, 4),
                "predicted_state_ts": round(pred_state_time, 4),
                
                # 时间窗口 (Interval Estimate) - 用于 Logic Engine 的 Range Query
                "valid_window": {
                    "start": trigger_timestamp,
                    "end": round(max_valid_time, 4)
                },
                
                # 网络指纹期望 (用于去 Shadow View 搜索证据)
                "expected_fingerprint": net_fingerprint
            })

        return predictions
