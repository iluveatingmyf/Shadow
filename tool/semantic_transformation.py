# -*- coding: utf-8 -*-
import json
import networkx as nx
import os

class SemanticTransformer:
    def __init__(self):
        self.stats = {"nodes_pruned": 0, "nodes_replaced": 0, "ghosts_restored": 0}

    def prune_to_device_subgraph(self, G, target_device_keyword):
        target = target_device_keyword.lower()
        seeds = []
        for n, d in G.nodes(data=True):
            # ... (种子匹配逻辑保持不变) ...
            search_fields = [str(n), str(d.get('device', '')), str(d.get('raw_device_id', '')),
                             str(d.get('target_device', '')), str(d.get('entity_id', '')),
                             str(d.get('command', '')), str(d.get('label', ''))]
            if any(target in field.lower() for field in search_fields):
                seeds.append(n)

        if not seeds: return G

        # --- 修改后的核心逻辑 ---
        keep_nodes = set(seeds)
        
        for s in seeds:
            # 1. 向上保住：所有导致 Seed 发生的路径（必须留着，否则语义不全）
            keep_nodes.update(nx.ancestors(G, s))
            
            # 2. 向下保住：Seed 产生的所有直接和间接结果
            #keep_nodes.update(nx.descendants(G, s))

        # --- [重点] 删除原来的“深度补偿”步骤 3 ---
        # 不要再对 keep_nodes 里的非 seed 节点跑 ancestors 了
        # 否则会引发“逻辑扩散”，把无关分支带进来

        nodes_to_remove = [n for n in G.nodes() if n not in keep_nodes]
        G.remove_nodes_from(nodes_to_remove)
        return G

    def _prune_forbidden_zone(self, G, forbidden_commands):
        nodes_to_remove = set()
        for cmd in forbidden_commands:
            if not G.has_node(cmd): continue
            
            # 断开驱动边 (isConditionOf 等)
            pre_edges = list(G.in_edges(cmd, data=True))
            for u, v, d in pre_edges:
                etype = d.get('type', d.get('label', ''))
                if etype in ['isConditionOf', 'scondition']:
                    G.remove_edge(u, v)
                    if G.degree(u) == 0: nodes_to_remove.add(u)
            
            # 清理下游产生的虚假状态
            search_queue = [cmd]
            visited = {cmd}
            while search_queue:
                curr = search_queue.pop(0)
                for _, target, data in list(G.out_edges(curr, data=True)):
                    if target in visited: continue
                    if str(target).startswith("Ghost_") or "Restored" in str(target): continue
                    if data.get('type') in ['Generate', 'Derive', 'sgen', 'sderive']:
                        nodes_to_remove.add(target)
                        visited.add(target)
                        search_queue.append(target)
        
        G.remove_nodes_from(nodes_to_remove)

    def transform(self, corrective_path, output_path, target_key):
        if not os.path.exists(corrective_path): return
        with open(corrective_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        G = nx.DiGraph()
        for n in data.get("nodes", []): G.add_node(n['id'], **n)
        for e in data.get("links", []): 
            G.add_edge(e['source'], e['target'], **e)

        # --- [第一步] 递归连坐删除：清理被替换节点的所有“专有前因” ---
        nodes_to_purge = set()
        # 识别所有的替换关系 (u 被 v 替换)
        replace_pairs = [(u, v) for u, v, d in G.edges(data=True) if d.get('type') in ['sreplace', 'sreplacedBy']]
        
        # 1. 标记初始 stale 节点为删除目标
        queue = []
        for u, v in replace_pairs:
            if G.has_node(u):
                nodes_to_purge.add(u)
                queue.append(u)

        # 2. 向上递归：只要节点的所有下游都在删除名单里，该节点就一起删
        while queue:
            curr = queue.pop(0)
            for pre in list(G.predecessors(curr)):
                if pre in nodes_to_purge: continue
                # 永远不要误杀 Ghost 或 Restored 节点
                if str(pre).startswith("Ghost_") or "Restored" in str(pre): continue
                
                # 核心逻辑：检查这个前驱节点是否有任何“活着的”下游
                # 如果它所有的去向都是为了这个错误的动作，那它就得死
                remaining_succs = [s for s in G.successors(pre) if s not in nodes_to_purge]
                if not remaining_succs:
                    nodes_to_purge.add(pre)
                    queue.append(pre)

        # 3. 在物理删除前，完成“果”的继承 (让 v 接替 u 的出边)
        for u, v in replace_pairs:
            if G.has_node(u) and G.has_node(v):
                for _, target, edata in list(G.out_edges(u, data=True)):
                    if target == v: continue # 避开 sreplacedBy 边本身
                    G.add_edge(v, target, **edata)
        
        # 执行彻底删除
        G.remove_nodes_from(nodes_to_purge)
        self.stats["nodes_pruned"] += len(nodes_to_purge)
        print(f"[*] 深度连坐清理完成，共移除 {len(nodes_to_purge)} 个废弃节点（含前因关联）。")

        # --- [第二步] 处理 shouldPrecede (节点合并逻辑) ---
        nodes_to_remove_after_merge = set()
        precede_edges = [(u, v) for u, v, d in G.edges(data=True) if d.get('type') == 'shouldPrecede']
        for ghost_node, entity_node in precede_edges:
            if G.has_node(ghost_node) and G.has_node(entity_node):
                # 合并逻辑保持不变...
                in_edges = list(G.in_edges(entity_node, data=True))
                for s, t, d in in_edges:
                    if s == ghost_node: continue
                    G.add_edge(s, ghost_node, **d)
                out_edges = list(G.out_edges(entity_node, data=True))
                for s, t, d in out_edges:
                    G.add_edge(ghost_node, t, **d)
                nodes_to_remove_after_merge.add(entity_node)
        G.remove_nodes_from(nodes_to_remove_after_merge)

        # --- [第三步] Ghost 映射与标准化 ---
        mapping = {}
        restored_ids = set()
        for nid, nattr in G.nodes(data=True):
            if nid.startswith("Ghost_") or "Restored" in nid:
                parts = nattr.get('label', '').split('\n')
                nattr['raw_device_id'] = parts[1].strip() if len(parts)>1 else ""
                nattr['new_state'] = parts[2].strip() if len(parts)>2 else ""
                new_id = nid.replace("Ghost_", "Entity_")
                mapping[nid] = new_id
                restored_ids.add(new_id)
                nattr['kind'] = "Entity"
                self.stats["ghosts_restored"] += 1

        # --- [第四步] 识别常规 Forbidden 区域并剪枝 ---
        sforbid_targets = [v for u, v, d in G.edges(data=True) if d.get('type') == 'sforbid']
        forbidden_cmds = [n for n, d in G.nodes(data=True) 
                         if (d.get("in_forbidden_zone") in ["True", True] and d.get("kind") == "Activity")
                         or n in sforbid_targets]
        self._prune_forbidden_zone(G, forbidden_cmds)

        # --- [第五步] 节点 ID 替换与边标准化 ---
        if mapping:
            G = nx.relabel_nodes(G, mapping)

        for u, v, d in G.edges(data=True):
            etype = d.get("type")
            if etype in ["shouldDerive", "sderive", "suppressed"]:
                d.update({"type": "Derive", "label": "Derive"})
            elif etype == "sgen":
                d.update({"type": "Generate", "label": "Generate"})
            elif etype == "sforbid":
                d.update({"type": "Forbid", "label": "Forbid"})
            elif etype == "strigger":
                d.update({"type": "wasUsedBy", "label": "wasUsedBy"})
            elif etype in ["sreplace", "sreplacedBy"]:
                d.update({"type": "Derive", "label": "Corrects"})

        # --- [第六步] 因果子图提取与孤儿清理 ---
        G = self.prune_to_device_subgraph(G, target_key)
        
        final_cleanup = [n for n, d in G.nodes(data=True) 
                        if d.get('kind') == 'Agent' and G.out_degree(n) == 0]
        G.remove_nodes_from(final_cleanup)

        # --- [第七步] 导出 ---
        final_nodes = []
        for n, d in G.nodes(data=True):
            node_info = {
                "id": str(n),
                "kind": d.get("kind"),
                "device": d.get("device") or d.get("raw_device_id"),
                "raw_device_id": d.get("raw_device_id") or d.get("entity_id") or d.get("device"),
                "in_forbidden_zone": n in forbidden_cmds or d.get("in_forbidden_zone") in ["True", True],
                "is_ghost": n in restored_ids
            }
            if d.get("kind") == "Activity":
                node_info["command"] = d.get("command") or d.get("description") or str(n)
            else:
                node_info["new_state"] = d.get("new_state") or d.get("state") or d.get("description")
            node_info["label"] = d.get("label", str(n)).replace("[FORBIDDEN]", "").strip()
            final_nodes.append(node_info)

        links = [{"source": str(u), "target": str(v), "type": d.get("type"), 
                  "label": d.get("label", d.get("type"))} for u, v, d in G.edges(data=True)]

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump({"nodes": final_nodes, "links": links}, f, indent=4, ensure_ascii=False)
        print(f"[✔] 转化完成: {scene}")

if __name__ == "__main__":

    st = SemanticTransformer()
    device_map = {
        "camera": "chuangmi_ipc009",
        "floor_lamp": "bslamp1", # 或者用 "yeelink"
        "bedside_lamp": "bslamp1",
        "speaker": "xiaomi_s12"
    }
    
    for scene in ["camera", "floor_lamp", "bedside_lamp", "speaker"]:
        # 传入对应的关键字，而不是文件夹名
        target_key = device_map.get(scene, scene)
        st.transform(f"./test_data/{scene}/corrective.json", 
                     f"./test_data/{scene}/transformed.json",
                     target_key)