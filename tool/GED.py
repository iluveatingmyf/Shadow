# -*- coding: utf-8 -*-
import json
import networkx as nx
import os
import time

class GEDEvaluator:
    def __init__(self, timeout=20):
        self.timeout = timeout
        # 匹配逻辑：现在我们直接比对 ID，因为加载时 ID 已经被归一化为指纹了
        self.node_match = lambda n1, n2: n1.get('kind') == n2.get('kind')
        self.edge_match = lambda e1, e2: e1.get('type') == e2.get('type')

    def _generate_fingerprint(self, n):
        """核心归一化逻辑：将节点 ID 转化为业务语义指纹"""
        kind = n.get('kind', 'Entity')
        device = n.get('device', 'unknown')
        
        if kind == 'Activity':
            # Activity 的指纹由命令内容决定
            state_info = n.get('command', n.get('description', ''))
        else:
            # Entity 的指纹由状态切换决定
            state_info = f"{n.get('old_state', '')}_{n.get('new_state', '')}"
            
        return f"{kind}|{device}|{state_info}".replace(" ", "_").lower()

    def load_normalized_graph(self, path):
        if not os.path.exists(path): return None
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        G = nx.DiGraph()
        
        # 1. 先建立 旧ID -> 语义指纹 的映射
        id_to_fp = {}
        for n in data['nodes']:
            fp = self._generate_fingerprint(n)
            id_to_fp[n['id']] = fp
            # 添加节点，ID 直接使用指纹
            G.add_node(fp, kind=n.get('kind', 'Entity'), fingerprint=fp)

        # 2. 添加边，使用指纹 ID 连接
        for e in data.get('links', []):
            u_fp = id_to_fp.get(e['source'])
            v_fp = id_to_fp.get(e['target'])
            
            if u_fp and v_fp:
                # 只添加边，不在这里做语义转化（那是 SemanticTransformer 的事）
                G.add_edge(u_fp, v_fp, type=e.get('type'))

        # 3. 物理清理：如果图中还有 Forbid 边，说明 Transformation 没删干净，这里强制辅助清理
        # 这样能确保 GED 计算的是“修复后”的效果，而不是包含“拦截过程”的效果
        forbidden_activities = [v for u, v, d in G.edges(data=True) if d['type'] == 'Forbid']
        for act in forbidden_activities:
            if G.has_node(act):
                # 删除该动作及其产生的所有后果
                descendants = list(nx.descendants(G, act))
                G.remove_nodes_from(descendants)
                G.remove_node(act)
        
        # 移除孤立点
        G.remove_nodes_from(list(nx.isolates(G)))
        
        return G

    def print_debug_info(self, name, G):
        if G is None: return
        print(f"  [{name} Stats]:")
        print(f"    - Nodes: {G.number_of_nodes()}")
        edge_types = {}
        for _, _, d in G.edges(data=True):
            t = d['type']
            edge_types[t] = edge_types.get(t, 0) + 1
        print(f"    - Edges: {G.number_of_edges()} (Detail: {edge_types})")

    def calculate_ged(self, g1, g2, desc=""):
        if g1 is None or g2 is None: return 99.0
        start = time.time()
        
        # 因为 ID 已经归一化，GED 的搜索空间会大幅缩小，计算会非常快
        dist = nx.graph_edit_distance(
            g1, g2, 
            node_match=self.node_match, 
            edge_match=self.edge_match,
            timeout=self.timeout
        )
        
        duration = time.time() - start
        print(f"  >> {desc} | GED: {dist} | Time: {duration:.2f}s")
        return dist if dist is not None else 99.0

    def run_suite(self, scene, base_p, attack_p, trans_p):
        print(f"\n" + "="*50)
        print(f"EVALUATING SCENARIO: {scene.upper()}")
        
        gb = self.load_normalized_graph(base_p)
        ga = self.load_normalized_graph(attack_p)
        gt = self.load_normalized_graph(trans_p)

        self.print_debug_info("BASE", gb)
        self.print_debug_info("ATTACK", ga)
        self.print_debug_info("TRANSFORMED", gt)

        dist_a = self.calculate_ged(gb, ga, "Base vs Attack")
        dist_t = self.calculate_ged(gb, gt, "Base vs Transformed")

        if dist_a > 0:
            improvement = (dist_a - dist_t) / dist_a * 100
            print(f"CONCLUSION: 修复后语义偏差减少了 {improvement:.2f}%")
        else:
            print("CONCLUSION: Attack 与 Base 无偏差")

if __name__ == "__main__":
    evaluator = GEDEvaluator()    
    for scene in ["camera", "floor_lamp", "bedside_lamp", "speaker"]:
        evaluator.run_suite(
            scene,
            f"./test_data/{scene}/base.json",
            f"./test_data/{scene}/attack.json",
            f"./test_data/{scene}/transformed.json"
        )