import networkx as nx
import logging
from typing import List, Dict, Any, Tuple
from collections import defaultdict
from datetime import datetime

# 配置细粒度 Debug 信息
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("ForensicEngine")

class VersionedForensicGraphBuilder:
    def __init__(self, aggr_thresh: float = 0.8):
        self.G = nx.DiGraph()
        self.aggr_thresh = aggr_thresh
        # 跟踪每个实体的版本状态: { entity_id: { "last_ver": 0, "last_ts": 0.0, "node_id": "..." } }
        self.entity_states = {}
        # 预定义的可信实体集合 (用于诊断)
        self.trusted_entities = {"192.168.5.159", "192.168.0.1", "HomeAssistant", "Cloud"}

    def _get_or_create_version_node(self, entity_id: str, ts: float) -> str:
        """
        [逻辑：纵向版本演化]
        决定是【聚合】到旧节点，还是【分裂】出新版本。
        物理意义：Version Edge 的 Duration 代表了设备维持在该物理状态的‘惯性’。
        """
        if entity_id not in self.entity_states:
            node_id = f"{entity_id}_v0"
            self.G.add_node(node_id, entity=entity_id, version=0, ts=ts, kind="PhysicalState")
            self.entity_states[entity_id] = {"last_ver": 0, "last_ts": ts, "node_id": node_id}
            return node_id

        state = self.entity_states[entity_id]
        if ts - state['last_ts'] <= self.aggr_thresh:
            # 聚合逻辑：极短时间内连续交互，不引起宏观状态分裂
            state['last_ts'] = ts
            return state['node_id']
        else:
            # 分裂逻辑：产生新版本，记录 Stagnation (停滞)
            old_node_id = state['node_id']
            new_ver = state['last_ver'] + 1
            new_node_id = f"{entity_id}_v{new_ver}"
            self.G.add_node(new_node_id, entity=entity_id, version=new_ver, ts=ts, kind="PhysicalState")
            
            duration = ts - state['last_ts']
            self.G.add_edge(old_node_id, new_node_id, type="Version", duration=round(duration, 3))
            
            state.update({"last_ver": new_ver, "last_ts": ts, "node_id": new_node_id})
            return new_node_id

    def build_graph(self, causal_context: Dict[str, Any]):
        self.G.clear()
        self.entity_states.clear()
        
        primitive = causal_context['primitive']
        flows = causal_context['context_flows']
        target_device = causal_context['entity_id']

        # 1. 注入 App 逻辑锚点 (预期行为)
        app_node = f"AppLog_{primitive.get('dsa_idx', 'root')}"
        self.G.add_node(app_node, kind="AppLogic", type=primitive['type'], ts=primitive['timestamp'])

        # 2. 注入网络原子 (物理证据)
        for flow in flows:
            ts = flow['ts']
            sig = str(flow.get('anchor', {}).get('payload_digest', ""))
            net_id = flow['net_id']
            
            # --- 核心改进：语义重定向 (Semantic Redirection) ---
            # 不论 Packet 的 IP 方向，只看签名指纹的物理意义
            # CMD指纹 (如 203, 154) 代表‘因’，STATE指纹代表‘果’
            
            if "203" in sig or "138" in sig: # 假设这些是下行指令
                # 语义：External -> Device (Action)
                u_node = self._get_or_create_version_node("External_Source", ts)
                v_node = self._get_or_create_version_node(target_device, ts)
                self.G.add_edge(u_node, v_node, type="SemanticAction", net_id=net_id, sig=sig, ts=ts)
                logger.debug(f"[Redirection] Flow {net_id} mapped as SemanticAction to {v_node}")
            
            elif "273" in sig or "274" in sig: # 假设这些是设备上报
                # 语义：Device -> Cloud (Response)
                u_node = self._get_or_create_version_node(target_device, ts)
                v_node = self._get_or_create_version_node("Cloud_Sink", ts)
                self.G.add_edge(u_node, v_node, type="SemanticResponse", net_id=net_id, sig=sig, ts=ts)
                logger.debug(f"[Redirection] Flow {net_id} mapped as SemanticResponse from {u_node}")

        # 3. 跨层链接：将 App 逻辑节点指向它实际触发的那个物理版本
        # 查找在物理层第一个包含指令指纹的 Version Node
        for u, v, d in self.G.edges(data=True):
            if d.get('type') == "SemanticAction" and "203" in str(d.get('sig')):
                self.G.add_edge(app_node, v, type="Manifestation", label="ExpectedTrigger")
                break

        return self.G

class ForensicReasoner:
    """
    推理引擎：通过查询图结构完成根因归因
    """
    def __init__(self, G: nx.DiGraph, primitive: Dict):
        self.G = G
        self.primitive = primitive
        self.victim = primitive['metadata'].get('label', '').split('|')[0].strip()

    def diagnose(self) -> Dict[str, Any]:
        logger.info(f"\n" + "="*20 + " [ROOT CAUSE ANALYSIS] " + "="*20)
        
        preds = self._extract_structural_predicates()
        
        # --- 归因逻辑矩阵 ---
        attack_entity = "Unknown"
        attack_effect = "None"
        root_cause = "Benign"

        # 1. 判定延迟攻击 (Stale State)
        if preds['long_version_stall'] and preds['delayed_semantic_action']:
            attack_entity = "On-path Adversary (MitM)"
            attack_effect = f"State Stagnation ({preds['max_stall']}s) leading to Stale Context"
            root_cause = "Time-Delay Attack via Packet Interception/Late Release"

        # 2. 判定非法注入 (Injection)
        elif preds['unauthorized_trigger'] and self.primitive['type'] == "UNCLAIMED":
            attack_entity = preds['rogue_source']
            attack_effect = "Unauthorized Physical Actuation"
            root_cause = "Device Compromise / Local Command Injection"

        # 3. 判定逻辑篡改 (Log Injection)
        elif self.primitive['type'] == "UNSUPPORTED" and not preds['any_physical_action']:
            attack_entity = "Cyber Platform / Malicious App"
            attack_effect = "Semantic Forgery (Fake Log)"
            root_cause = "Cyber-Plane Log Injection (No Physical Basis)"

        result = {
            "Diagnosis": root_cause,
            "Attacker": attack_entity,
            "Effect": attack_effect,
            "Structural_Evidence": preds
        }
        
        self._print_report(result)
        return result

    def _extract_structural_predicates(self) -> Dict[str, Any]:
        """
        [物理语义提取]
        通过图遍历寻找拓扑畸变特征。
        """
        # P1: 查找长持续时间的版本边 (停滞期)
        version_edges = [(u,v,d) for u,v,d in self.G.edges(data=True) if d['type'] == "Version"]
        max_stall = max([d['duration'] for u,v,d in version_edges]) if version_edges else 0
        
        # P2: 查找延迟的语义动作 (App发出到物理到达的差值)
        app_ts = self.primitive['timestamp']
        semantic_actions = [d['ts'] for u,v,d in self.G.edges(data=True) if d['type'] == "SemanticAction"]
        min_phys_ts = min(semantic_actions) if semantic_actions else 0
        delay_gap = min_phys_ts - app_ts if min_phys_ts > 0 else 0

        # P3: 身份核查
        # 实际代码中应从 Interaction 边的 net_id 回溯到原始包的 Source IP
        # 这里模拟：是否存在来自非 Trust 列表的 Action
        unauthorized = False # 逻辑点

        return {
            "long_version_stall": max_stall > 10.0,
            "max_stall": max_stall,
            "delayed_semantic_action": delay_gap > 5.0,
            "any_physical_action": len(semantic_actions) > 0,
            "unauthorized_trigger": unauthorized
        }

    def _print_report(self, res: Dict):
        print(f"\033[1;31m[FINAL EXPLANATION]\033[0m")
        print(f"  ● 根本原因: {res['Diagnosis']}")
        print(f"  ● 攻击实体: {res['Attacker']}")
        print(f"  ● 物理效果: {res['Effect']}")
        print(f"  ● 图结构证据: Stall={res['Structural_Evidence']['max_stall']}s")

# --- 集成运行示例 ---
if __name__ == "__main__":
    # 假设来自 InteractionCausalSelector 的输出
    # 模拟一个延迟场景：App在 100s 发指令，物理包在 118s 到达
    mock_context = {
        "entity_id": "lumi_mgl03_4e93_arming",
        "primitive": {
            "type": "UNSUPPORTED", 
            "timestamp": 1771817045.0,
            "dsa_idx": "001",
            "metadata": {"label": "lumi_mgl03_4e93_arming | armed_away"}
        },
        "context_flows": [
            {"net_id": "N0014", "ts": 1771817052.0, "anchor": {"payload_digest": "[203, 203]"}}, # 拦截中的重传包
            {"net_id": "N0027", "ts": 1771817062.0, "anchor": {"payload_digest": "[203]"}},      # 最终释放包
            {"net_id": "N0062", "ts": 1771817103.0, "anchor": {"payload_digest": "[273]"}}       # 状态改变上报
        ]
    }

    builder = VersionedForensicGraphBuilder(aggr_thresh=0.8)
    G = builder.build_graph(mock_context)
    
    reasoner = ForensicReasoner(G, mock_context['primitive'])
    reasoner.diagnose()