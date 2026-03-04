# -*- coding: utf-8 -*-
import json
import networkx as nx
import os

class SemanticTransformer:
    def __init__(self):
        self.stats = {"nodes_pruned": 0, "nodes_replaced": 0, "ghosts_restored": 0}

    def _prune_forbidden_zone(self, G, forbidden_commands):
        """
        彻底清理禁区，但保护 Ghost 节点及其发出的边。
        """
        nodes_to_remove = set()
        for cmd in forbidden_commands:
            if not G.has_node(cmd): continue
            
            # 1. 清理孤立条件
            pre_nodes = list(G.predecessors(cmd))
            for pre in pre_nodes:
                if G.get_edge_data(pre, cmd).get('type') in ['isConditionOf', 'scondition']:
                    if G.out_degree(pre) <= 1: nodes_to_remove.add(pre)
            
            # 2. 递归查找下游，但排除 Ghost/Restored 节点
            search_queue = [cmd]
            while search_queue:
                curr = search_queue.pop(0)
                for _, target, data in list(G.out_edges(curr, data=True)):
                    # 如果目标是还原节点或 Ghost，绝对不删
                    if str(target).startswith("Ghost_") or "Restored" in str(target):
                        continue
                    if data.get('type') in ['Generate', 'Derive', 'sgen', 'sderive', 'shouldDerive']:
                        nodes_to_remove.add(target)
                        search_queue.append(target)
        
        self.stats["nodes_pruned"] += len(nodes_to_remove)
        G.remove_nodes_from(nodes_to_remove)

    def transform(self, corrective_path, output_path):
        if not os.path.exists(corrective_path): return
        with open(corrective_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        G = nx.DiGraph()
        for n in data.get("nodes", []): G.add_node(n['id'], **n)
        for e in data.get("links", []): G.add_edge(e['source'], e['target'], **e)

        # --- 1. 预处理：识别 Ghost 并建立映射 ---
        mapping = {}
        restored_ids = set()
        for nid, nattr in G.nodes(data=True):
            if nid.startswith("Ghost_") or "Restored" in nid:
                new_id = nid.replace("Ghost_", "Entity_")
                mapping[nid] = new_id
                restored_ids.add(new_id)
                nattr['kind'] = "Entity" # 强制转化为 Entity
                self.stats["ghosts_restored"] += 1

        # --- 2. 识别 Forbidden 目标 ---
        forbidden_cmds = [n for n, d in G.nodes(data=True) 
                         if d.get("in_forbidden_zone") in ["True", True] and d.get("kind") == "Activity"]
        
        # --- 3. 执行剪枝 (保护已映射的 Ghost) ---
        self._prune_forbidden_zone(G, forbidden_cmds)

        # --- 4. 节点 ID 替换 ---
        if mapping:
            G = nx.relabel_nodes(G, mapping)

        # --- 5. 边类型最终标准化 ---
        ops_replace = []
        for u, v, d in G.edges(data=True):
            etype = d.get("type")
            # 核心：将所有演化边转化为基线可识别的类型
            if etype in ["shouldDerive", "sderive"]:
                d.update({"type": "Derive", "label": "Derive", "color": "#2ca02c"})
            elif etype == "sgen":
                d.update({"type": "Generate", "label": "Generate", "color": None})
            elif etype == "sforbid":
                d.update({"type": "Forbid", "label": "Forbid", "color": "red"})
            elif etype == "strigger":
                d.update({"type": "wasUsedBy", "label": "wasUsedBy"})
            elif etype in ["sreplace", "sreplacedBy"]:
                ops_replace.append((u, v))
                d.update({"type": "Derive", "label": "Corrects", "color": "#9467bd"})

        # --- 6. 处理残留的替换入边迁移 ---
        for stale, ghost in ops_replace:
            if G.has_node(stale) and G.has_node(ghost):
                for src, _, d_in in list(G.in_edges(stale, data=True)):
                    if src != ghost: G.add_edge(src, ghost, **d_in)
                G.remove_node(stale)

        # --- 7. 导出 ---
        final_nodes = []
        for n, d in G.nodes(data=True):
            final_nodes.append({
                "id": str(n),
                "kind": d.get("kind"),
                "label": d.get("label", str(n)).replace("[FORBIDDEN]", "").strip(),
                "device": d.get("device"),
                "raw_device_id": d.get("raw_device_id") or d.get("device"),
                "in_forbidden_zone": n in forbidden_cmds or d.get("in_forbidden_zone") in ["True", True],
                "is_ghost": n in restored_ids
            })

        links = [{"source": str(u), "target": str(v), "type": d.get("type"), 
                  "label": d.get("label", d.get("type")), "color": d.get("color")} 
                 for u, v, d in G.edges(data=True)]

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump({"nodes": final_nodes, "links": links}, f, indent=4, ensure_ascii=False)

        print(f"[✔] 转化完成: Ghost还原={self.stats['ghosts_restored']}, 剪枝={self.stats['nodes_pruned']}")

if __name__ == "__main__":
    st = SemanticTransformer()
    scenes = ["camera", "floor_lamp", "bedside_lamp", "speaker"]
    for scene in scenes:
        st.transform(f"./test_data/{scene}/corrective.json", f"./test_data/{scene}/transformed.json")