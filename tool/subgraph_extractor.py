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
        final_nodes = set()
        visited = set()
        
        print(f"\n{'='*20} DEBUG START: {target_device} {'='*20}")

        # 1. 递归溯源函数（带日志）
        def trace_recursive(node_id, depth=0):
            if node_id in visited: return
            visited.add(node_id)
            final_nodes.add(node_id)
            
            node_data = self.G.nodes[node_id]
            indent = "  " * depth
            print(f"{indent}[→] Tracing: {node_id} (Kind: {node_data.get('kind')}, Label: {node_data.get('label', 'N/A')[:30]}...)")

            # 检查所有指向该节点的前驱
            preds = list(self.G.predecessors(node_id))
            if not preds:
                print(f"{indent} [!] No predecessors for {node_id}")

            for pred in preds:
                edge_data = self.G.get_edge_data(pred, node_id)
                # 同时检查 label 和 type，打印出来看看实际拿到了什么
                e_type = str(edge_data.get("label", "")) or str(edge_data.get("type", ""))
                
                # 定义因果边白名单
                causal_list = ["Generate", "sgen", "wasAssociateWith", "wasUsedBy", "isConditionOf", "Derive", "shouldDerive"]
                
                is_causal = any(c.lower() in e_type.lower() for c in causal_list)
                
                if is_causal:
                    print(f"{indent}  |-- Found causal edge [{e_type}] from {pred}")
                    trace_recursive(pred, depth + 1)
                else:
                    # 记录被过滤掉的边，看看是不是在这里断了
                    print(f"{indent}  |xx Filtered edge [{e_type}] from {pred}")

        # 2. 初始种子扫描
        seeds = []
        for n, d in self.G.nodes(data=True):
            props = d.get("properties", {})
            node_dev = str(d.get("entity_id") or props.get("entity_id") or d.get("device") or "")
            
            # 这里的匹配逻辑：如果是目标设备，或者是 Ghost
            if (target_device in node_dev and d.get("kind") == "Entity") or "Ghost" in n:
                seeds.append(n)

        print(f"[*] Initial seeds found: {seeds}")

        for seed in seeds:
            trace_recursive(seed)

        # 3. 结果验证
        print(f"[*] Total nodes extracted: {len(final_nodes)}")
        
        # 检查有没有任何 User Panel 混进来了
        panels = [n for n in final_nodes if "panel" in str(n).lower() or "panel" in str(self.G.nodes[n].get("label","")).lower()]
        print(f"[*] Panels found in result: {panels}")
        print(f"{'='*50}\n")

        if not final_nodes: return None
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