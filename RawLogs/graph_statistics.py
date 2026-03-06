import json
from collections import Counter

def analyze_graph(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        graph_data = json.load(f)
    
    nodes = graph_data.get('nodes', [])
    edges = graph_data.get('links', graph_data.get('edges', [])) # 适配不同的json格式名
    
    node_kinds = Counter(n.get('kind') for n in nodes)
    edge_types = Counter(e.get('type', e.get('label')) for e in edges)
    
    print("--- Provenance Graph Statistics ---")
    print(f"Nodes: {len(nodes)} (Density: {len(edges)/len(nodes):.2f} edges/node)")
    print(f"Edges: {len(edges)}")
    
    print("\nNode Composition:")
    for kind, count in node_kinds.items():
        print(f"  - {kind}: {count}")
        
    print("\nRelationship (Edge) Distribution:")
    for etype, count in edge_types.items():
        print(f"  - {etype}: {count}")

analyze_graph('provenance_analysis_data.json')