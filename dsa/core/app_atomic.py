import json
import os

def extract_filtered_atomic_subgraph(json_data):
    nodes = {n['id']: n for n in json_data['nodes']}
    links = json_data['links']
    
    # 建立邻接表：正向索引
    adj = {}
    for link in links:
        s, t = link['source'], link['target']
        if s not in adj: adj[s] = []
        adj[s].append(link)

    # 1. 确定保留节点集合 (Kept Nodes)
    kept_nodes = {}
    for nid, node in nodes.items():
        # 判定条件 A: 必须是 Entity, PanelAgent 或 Command
        kind = node.get('kind')
        is_base_type = kind in ['Entity', 'PanelAgent', 'Activity'] or node.get('event_type') == 'Command'
        
        # 判定条件 B: 剔除 Inferred Anchor State
        is_anchor = node.get('description') == "Inferred Anchor State"
        
        # 判定条件 C: 如果是 Command，必须是 executed
        is_exec_cmd = True
        if node.get('event_type') == 'Command':
            is_exec_cmd = (node.get('status') == 'executed')

        if is_base_type and not is_anchor and is_exec_cmd:
            kept_nodes[nid] = node

    # 2. 边关系重构 (Link Reconstruction)
    new_links = []
    for start_node_id in kept_nodes:
        # 寻找从当前保留节点出发，穿过 Agent 或被剔除节点后，到达的下一个保留节点
        found_links = find_next_kept_nodes(start_node_id, adj, kept_nodes, nodes)
        new_links.extend(found_links)

    return {
        "nodes": list(kept_nodes.values()),
        "links": new_links
    }

def find_next_kept_nodes(current_id, adj, kept_nodes, all_nodes):
    discovered_links = []
    # 使用广度优先搜索探测路径
    q = []
    # 初始化：从当前节点的直接出边开始
    for link in adj.get(current_id, []):
        q.append((link['target'], link['type']))
    
    visited = {current_id}
    
    while q:
        tid, original_rel = q.pop(0)
        if tid in visited: continue
        visited.add(tid)
        
        # 情况 1: 目标是我们要保留的节点
        if tid in kept_nodes:
            discovered_links.append({
                "source": current_id,
                "target": tid,
                "relation": original_rel,
                "info": "Direct or via Agent/Anchor"
            })
            continue # 停止向该分支深挖，因为已经连接到了最近的保留节点
            
        # 情况 2: 目标是被剔除的节点 (Agent 或 Anchor)
        t_node = all_nodes.get(tid)
        if t_node:
            # 只要不是保留节点，就视为“透明层”，继续向下寻找
            for next_link in adj.get(tid, []):
                if next_link['target'] not in visited:
                    q.append((next_link['target'], original_rel))

    return discovered_links

def main(input_path='/Users/myf/shadowprov/RawLogs/A1/S2/delay/graph/provenance_analysis_data.json'):
    if not os.path.exists(input_path):
        print(f"Error: {input_path} not found.")
        return

    with open(input_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    result = extract_filtered_atomic_subgraph(data)

    # 结果回写
    output_path = 'app_atomics_final.json'
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=4, ensure_ascii=False)
    
    print(f"--- 筛选报告 ---")
    print(f"原始节点数: {len(data['nodes'])}")
    print(f"最终保留节点: {len(result['nodes'])} (已剔除 Anchor 态与 Agent)")
    print(f"重构后的有效边: {len(result['links'])}")

if __name__ == "__main__":
    main()