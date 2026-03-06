# -*- coding: utf-8 -*-
import json
import networkx as nx
import os
import time
import re

class GEDEvaluator:
    def __init__(self, timeout=20):
        self.timeout = timeout
        # 此时 ID 已经是指纹了，node_match 主要是为了双重保险
        self.node_match = lambda n1, n2: n1.get('kind') == n2.get('kind')
        self.edge_match = lambda e1, e2: e1.get('type') == e2.get('type')

    def _generate_fingerprint(self, n):
        kind = n.get('kind', 'Entity')
        # 1. 提取设备 ID (标准化：去掉 sensor./automation. 前缀，统一用下划线)
        raw_device = n.get('raw_device_id') or n.get('device') or ""
        # 某些字段可能包含完整的 entity_id，统一只取最后一部分
        device = str(raw_device).lower().split('.')[-1]
        device = device.replace(" ", "_")

        # 2. 核心分类逻辑
        state_info = "any"

        if kind == 'Agent' or 'agent' in kind.lower():
            # Agent 统一指纹
            state_info = "trigger"
            
        elif kind == 'Activity':
            # 动作：优先取 command 字段，避开 label 里的 "Command_17"
            cmd = n.get('command')
            if not cmd or "command_" in str(cmd).lower():
                # 如果 command 字段不存在或只是 ID，尝试从 label 提取有意义的动作
                label_parts = str(n.get('label', '')).split('\n')
                # 排除掉类似 Command_17 的 label
                meaningful_parts = [p for p in label_parts if "command_" not in p.lower() and "activity" not in p.lower()]
                state_info = meaningful_parts[0] if meaningful_parts else "execute"
            else:
                # 处理类似 "alarm_control_panel.alarm_arm_home" -> "alarm_arm_home"
                state_info = str(cmd).split('.')[-1]
            
        else:
            # Entity：优先取 new_state
            ns = n.get('new_state')
            if ns:
                state_info = str(ns)
            else:
                # 从 label 提取状态 (例如 "no one → has one" 取 "has one")
                label_parts = str(n.get('label', '')).split('\n')
                last_line = label_parts[-1].lower()
                state_info = last_line.split('→')[-1].strip() if '→' in last_line else last_line

        # 3. 清洗最终状态字符串
        state_info = state_info.lower().replace("[forbidden]", "").strip()

        # --- 新增：处理时间戳和干扰项 ---
        # 匹配 ISO 8601 格式或类似 2026-02-23 的日期模式
        iso_date_pattern = r'\d{4}-\d{2}-\d{2}([t ]\d{2}:\d{2}:\d{2})?'
        
        if re.search(iso_date_pattern, state_info):
            state_info = "any"
        # 处理 "status: ok" 或自动生成的 ID 干扰
        elif "status:" in state_info or "command_" in state_info:
            state_info = "executed"

        return f"{kind}|{device}|{state_info}".lower()


    def load_normalized_graph(self, path, target_device_id=None, base_filter=None):
        if not os.path.exists(path): return None
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        G = nx.DiGraph()
        old_id_to_fp = {}
        
        for n in data['nodes']:
            fp = self._generate_fingerprint(n)
            # 先不开启 base_filter，看看原始加载了多少
            old_id_to_fp[n['id']] = fp
            G.add_node(fp, kind=n.get('kind'))

        for e in data.get('links', []) or data.get('edges', []):
            u_fp, v_fp = old_id_to_fp.get(e['source']), old_id_to_fp.get(e['target'])
            if u_fp and v_fp:
                etype = e.get('type', '')
                G.add_edge(u_fp, v_fp, type=etype)

        if target_device_id:
            target_key = target_device_id.split('.')[-1].lower()
            seeds = [n for n in G.nodes() if target_key in n]
            if seeds:
                # 暂时改回无向图 3-hop，确保能把“邻居”都抓进来，看看是不是边断了
                UG = G.to_undirected()
                nodes_to_keep = set()
                for s in seeds:
                    nodes_to_keep.update(nx.single_source_shortest_path_length(UG, s, cutoff=3).keys())
                G = G.subgraph(nodes_to_keep).copy()
        
        # 暂时注释掉这行，看看有没有孤立节点
        # G.remove_nodes_from(list(nx.isolates(G)))
        return G
    def calculate_ged(self, g1, g2, desc=""):
        if g1 is None or g2 is None: return 99.0
        
        # 调试：查看 ID（即指纹）的匹配情况
        nodes1, nodes2 = set(g1.nodes()), set(g2.nodes())
        print(f"\n  [DEBUG: {desc}]")
        print(f"    - Base 节点(指纹)数: {len(nodes1)} | 对比图节点数: {len(nodes2)}")
        print(f"    - 完美匹配的节点数: {len(nodes1 & nodes2)}")
        
        if len(nodes1 - nodes2) > 0:
            print(f"    - Base 有但对方没有的指纹: {list(nodes1 - nodes2)[:2]}")
        if len(nodes2 - nodes1) > 0:
            print(f"    - 对方多出来的指纹: {list(nodes2 - nodes1)[:2]}")
        
        start = time.time()
        # 由于 ID 已对齐，GED 只需要计算边的增减和少量不匹配节点的开销
        dist = nx.graph_edit_distance(
            g1, g2, 
            node_match=self.node_match, 
            edge_match=self.edge_match,
            timeout=self.timeout
        )
        duration = time.time() - start
        res = dist if dist is not None else 99.0
        print(f"    >> GED 结果: {res} (耗时: {duration:.2f}s)")
        return res

    def run_suite(self, scene, target_id, base_p, attack_p, trans_p):
        print(f"\n" + "="*60)
        print(f"EVALUATING: {scene.upper()} (Target: {target_id})")
        gb = self.load_normalized_graph(base_p, target_id)
        ga = self.load_normalized_graph(attack_p, target_id)
        gt = self.load_normalized_graph(trans_p, target_id)

        dist_a = self.calculate_ged(gb, ga, "Base vs Attack")
        dist_t = self.calculate_ged(gb, gt, "Base vs Transformed")

        if dist_a > 0:
            improvement = (dist_a - dist_t) / dist_a * 100
            print(f"RESULT: 提升了 {improvement:.2f}%")
        else:
            print("RESULT: Base 图可能由于过滤过狠变为空，或者 Attack 已是完美状态")

if __name__ == "__main__":
    evaluator = GEDEvaluator()
    scenarios = {
        "camera": "switch.chuangmi_ipc009_b918_switch_status",
        "floor_lamp": "light.yeelink_bslamp1_b745_light",
        "bedside_lamp": "light.yeelink_bslamp1_b745_light",
        "speaker": "media_player.xiaomi_lx06_079d_play_control"
    }
    for scene, target_id in scenarios.items():
        evaluator.run_suite(scene, target_id,
            f"./test_data/{scene}/base.json",
            f"./test_data/{scene}/attack.json",
            f"./test_data/{scene}/transformed.json")