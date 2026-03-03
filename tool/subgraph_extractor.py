# -*- coding: utf-8 -*-
import json
import os
import networkx as nx

class DeviceCausalSlicer:
    def __init__(self, name, graph_path):
        self.name = name
        self.graph_path = graph_path
        self.G = self._load_graph(graph_path)
        self.device_list = self._get_all_devices()

    def _load_graph(self, path):
        if not os.path.exists(path):
            print(f"[!] 找不到文件: {path}")
            return nx.DiGraph()
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        G = nx.DiGraph()
        nodes = data.get("nodes", [])
        links = data.get("links", []) or data.get("edges", [])
        for n in nodes:
            G.add_node(n['id'], **n)
        for l in links:
            G.add_edge(l['source'], l['target'], **l)
        return G

    def _get_all_devices(self):
        devices = set()
        for n, d in self.G.nodes(data=True):
            # 兼容 entity_id 或 properties 里的定义
            props = d.get("properties", {})
            did = d.get("entity_id") or props.get("entity_id") or d.get("target_device")
            if did and did != "None":
                devices.add(did)
        return devices

    def extract_slice(self, target_device):
        """优化版：仅提取上游因果链，防止无关联动导致子图爆炸"""
        core_nodes = []
        for n, d in self.G.nodes(data=True):
            props = d.get("properties", {})
            if (d.get("entity_id") == target_device or 
                props.get("entity_id") == target_device or
                d.get("target_device") == target_device):
                core_nodes.append(n)
        
        if not core_nodes: return None

        # 重点：只找 predecessors (前驱/上游)，不找 successors (后继/下游)
        expanded_nodes = set(core_nodes)
        
        # 第一层：找到 Activity (Command)
        first_hop = set()
        for node in expanded_nodes:
            first_hop.update(self.G.predecessors(node))
        expanded_nodes.update(first_hop)

        # 第二层：找到 Agent 或 影子节点 (Corrective Logic)
        second_hop = set()
        for node in first_hop:
            second_hop.update(self.G.predecessors(node))
        expanded_nodes.update(second_hop)


        # 2. 【新增：无条件补全 Command 的 Agent】
        # 遍历当前已找到的所有节点，如果是 Activity (Command)，则强行拉入其 Agent
        supplementary_nodes = set()
        for node_id in expanded_nodes:
            node_data = self.G.nodes[node_id]
            # 判断是否为 Command 节点 (根据你的数据特征，可能是 kind='Activity')
            if node_data.get("kind") == "Activity" or node_id.startswith("Command"):
                # 寻找该 Command 的所有前驱
                for pred in self.G.predecessors(node_id):
                    edge_data = self.G.get_edge_data(pred, node_id)
                    # 如果边类型是 wasAssociateWith，或者前驱是 Agent，则加入
                    if edge_data.get("type") == "wasAssociateWith" or pred.startswith("Agent"):
                        supplementary_nodes.add(pred)
        
        expanded_nodes.update(supplementary_nodes)

        
        # 针对纠错语义的特殊保护：只包含指向当前路径的纠错边
        final_nodes = set(expanded_nodes)
        for u, v, d in self.G.edges(data=True):
            # 如果某个节点在我们的链条里，且它被 sforbid 或 sreplace 指向
            if v in expanded_nodes:
                if d.get("type") in ["sforbid", "sreplace", "shouldPrecede"]:
                    final_nodes.add(u) # 把纠错源拉进来

        return self.G.subgraph(final_nodes).copy()

    def _save_json(self, sub_g, path):
        nodes = [{"id": n, **d} for n, d in sub_g.nodes(data=True)]
        links = [{"source": u, "target": v, **d} for u, v, d in sub_g.edges(data=True)]
        with open(path, 'w', encoding='utf-8') as f:
            json.dump({"nodes": nodes, "links": links}, f, indent=4, ensure_ascii=False)

# ==========================================
# 执行脚本
# ==========================================
if __name__ == "__main__":
    # 定义三个数据源路径
    paths = {
        "base": "/Users/myf/shadowprov/RawLogs/groundtruth/S2/graph/provenance_analysis_data.json",
        "attack": "/Users/myf/shadowprov/RawLogs/A1/S2/delay/graph/provenance_analysis_data.json",
        "corrective": "/Users/myf/shadowprov/LE/core/shadow_prov_logic_graph.json"
    }

    # 1. 初始化三个切片器
    slicers = {}
    all_devices = set()
    for tag, path in paths.items():
        s = DeviceCausalSlicer(tag, path)
        slicers[tag] = s
        all_devices.update(s.device_list)

    print(f"[*] 发现总设备数: {len(all_devices)}")

    # 2. 遍历所有设备，在三个维度分别提取
    for device in sorted(list(all_devices)):
        print(f"[*] 正在切片设备: {device}")
        
        for tag in ["base", "attack", "corrective"]:
            out_dir = f"subgraphs_{tag}"
            if not os.path.exists(out_dir): os.makedirs(out_dir)
            
            sub_g = slicers[tag].extract_slice(device)
            if sub_g:
                filename = f"{device.replace('.', '_')}.json"
                slicers[tag]._save_json(sub_g, os.path.join(out_dir, filename))
                print(f"  [+] [{tag}] 已保存")
            else:
                print(f"  [-] [{tag}] 无数据")

    print("\n[✔] 三路子图提取全部完成。")