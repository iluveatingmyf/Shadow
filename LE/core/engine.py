# -*- coding: utf-8 -*-
import json
import bisect
import os
import networkx as nx
from datetime import datetime, timedelta
from collections import defaultdict

# ==========================================
# 1. 基础工具 (Utils & Loaders)
# ==========================================
def audit_correction_edges(G):
    print("\n" + "="*50)
    print("        [AUDIT] CORRECTION EDGES REPORT")
    print("="*50)
    
    correction_count = 0
    for u, v, d in G.edges(data=True):
        edge_type = d.get("type", "rel")
        if edge_type.startswith("s") or edge_type.startswith("should"):
            correction_count += 1
            u_label = G.nodes[u].get("label", u).split("\n")[0]
            v_label = G.nodes[v].get("label", v).split("\n")[0]
            print(f"[{edge_type:15}] {u} ({u_label}) \n                --> {v} ({v_label})")
            if "label" in d:
                print(f"                Details: {d['label']}")
    
    if correction_count == 0:
        print("[!] No correction edges found.")
    else:
        print(f"\n[Summary] Total Correction Edges: {correction_count}")
    print("="*50 + "\n")

def parse_dt(t_val):
    if not t_val or t_val == "None": return datetime.min
    t_str = str(t_val).replace("T", " ").replace("Z", "")
    if "@" in t_str: t_str = t_str.split("@")[-1].strip()
    try:
        return datetime.fromisoformat(t_str)
    except ValueError:
        try:
            t_part = t_str.split(" ")[-1]
            dt = datetime.strptime(t_part, "%H:%M:%S.%f")
            return dt.replace(year=2024, month=1, day=1)
        except ValueError:
            return datetime.min

def load_g6_graph(filepath):
    print(f"[*] Loading Cyber View Graph...")
    with open(filepath, 'r', encoding='utf-8') as f: data = json.load(f)
    G = nx.DiGraph()
    for node in data.get("nodes", []):
        attrs = {k: v for k, v in node.items() if k not in ['id', 'label', 'shape', 'color', 'title']}
        attrs["_dt"] = parse_dt(attrs.get("timestamp"))
        node_id = node["id"]
        if "label" not in attrs: attrs["label"] = str(node_id)
        G.add_node(node_id, **attrs)
    for edge in data.get("links", []):
        source, target = edge["source"], edge["target"]
        edge_attrs = {k: v for k, v in edge.items() if k not in ['source', 'target', 'label', 'type']}
        edge_type = edge.get("type", "rel")
        edge_label = edge.get("label", edge_type)
        G.add_edge(source, target, type=edge_type, label=edge_label, **edge_attrs)
    print(f"[*] Loaded Graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges.")
    return G

# ==========================================
# 2. 核心逻辑引擎 (ShadowProv Logic Engine)
# ==========================================
class LogicEngine:
    def __init__(self, graph, dsa_data, abbm_rules):
        self.G = graph
        self.dsa_data = dsa_data
        self.abbm = abbm_rules.get("rules", abbm_rules) if isinstance(abbm_rules, dict) else abbm_rules
        self.oracle = defaultdict(list)
        self.tainted_count = 0
        self._build_oracle()

    def debug_print_oracle(self, target_eid=None):
        print("\n" + "="*30 + "\n    [DEBUG] STATE ORACLE SNAPSHOT\n" + "="*30)
        for eid, timeline in self.oracle.items():
            if target_eid and target_eid not in eid: continue
            print(f"\n>> Entity: {eid}")
            for dt, state, nid in timeline:
                tag = "[GHOST]" if "Ghost" in str(nid) else "[REAL ]"
                print(f"   {dt.strftime('%H:%M:%S.%f')[:-3]} | {state:12} | {tag} {nid}")
        print("="*30 + "\n")

    def _get_rule_for_activity(self, nid):
        node_data = self.G.nodes[nid]
        agent_nodes = [s for s, t, d in self.G.in_edges(nid, data=True) if d.get("type") == "wasAssociateWith"]
        for agent_id in agent_nodes:
            agent_data = self.G.nodes[agent_id]
            auto_id = node_data.get("automation_id") or agent_data.get("automation_id")
            device_name = agent_data.get("device")
            rule = next((r for r in self.abbm if (auto_id and str(r.get("id")) == str(auto_id)) or (r.get("alias") == device_name)), None)
            if rule: return rule
        return next((r for r in self.abbm if r.get("action", {}).get("command") == node_data.get("command")), None)

    def _build_oracle(self):
        print("[*] Building State Oracle...")
        for n, d in self.G.nodes(data=True):
            if d.get("kind") in ["Entity", "GhostEntity"] and "entity_id" in d:
                dt = parse_dt(d.get("_dt"))
                state = d.get("new_state") or d.get("state")
                bisect.insort(self.oracle[d["entity_id"]], (dt, state, n))

    def query_oracle_timeline(self, entity_id):
        return self.oracle.get(entity_id, [])

    def _get_effect_from_rule(self, rule):
        return rule.get("effect") or rule.get("consequence") or {}

    def phase_1_manifestation(self):
        print("\n[Phase 1] Manifesting Shadow Nodes (Ghosts & Zombies)...")
        for item in self.dsa_data:
            p_type, nid, meta = item.get("type"), item.get("node_id", ""), item.get("metadata", {})
            ts = parse_dt(item.get("timestamp"))
            if p_type == "UNCLAIMED":
                ghost_id = f"Ghost_I_{item.get('physical_id', nid)}"
                eid, state = meta.get('entity_id'), meta.get('state')
                self.G.add_node(ghost_id, label=f"Ghost Entity\n{eid}\n{state}", kind="GhostEntity", sub_kind="Ghost-I", entity_id=eid, new_state=state, _dt=ts, timestamp=ts.isoformat())
                bisect.insort(self.oracle[eid], (ts, state, ghost_id))
            elif p_type == "UNSUPPORTED" and nid in self.G:
                node_data = self.G.nodes[nid]
                if node_data.get("kind") == "Entity":
                    self.G.nodes[nid]["is_zombie"] = True
                    self.G.nodes[nid]["label"] += "\n[ZOMBIE]"
                elif node_data.get("kind") in ["Activity", "Command"]:
                    rule = self._get_rule_for_activity(nid)
                    eff = self._get_effect_from_rule(rule) if rule else None
                    if eff and "entity_id" in eff:
                        ghost_ii_id = f"Ghost_II_{nid}"
                        base_dt = node_data.get("_dt") or ts
                        g2_ts = base_dt + timedelta(milliseconds=150)
                        self.G.add_node(ghost_ii_id, label=f"Ghost Entity (II)\n{eff['entity_id']}\n{eff['state']}", kind="GhostEntity", sub_kind="Ghost-II", base_kind="Entity", entity_id=eff['entity_id'], state=eff['state'], new_state=eff['state'], _dt=g2_ts, timestamp=g2_ts.isoformat())
                        self.G.add_edge(nid, ghost_ii_id, label="sgen", type="sgen")
                        bisect.insort(self.oracle[eff['entity_id']], (g2_ts, eff['state'], ghost_ii_id))
                        print(f"  [+] Ghost-II Fixed: {eff['entity_id']} recovered as {eff['state']}")

    def phase_2_control_race(self):
        print("\n[Phase 2] Causal-based Search for shouldAdvance...")
        verified_cmds = [(n, d) for n, d in self.G.nodes(data=True) 
                         if d.get("kind") in ["Command", "Activity"] and not d.get("is_zombie")]
        ghost_nodes = [n for n, d in self.G.nodes(data=True) if d.get("kind") == "GhostEntity"]
        
        for g_id in ghost_nodes:
            g_data = self.G.nodes[g_id]
            g_time = parse_dt(g_data.get("_dt"))
            eid, g_state = g_data.get("entity_id"), str(g_data.get("new_state"))
            
            # 搜索有效期边界 (逻辑保持不变)
            timeline = self.query_oracle_timeline(eid)
            idx = bisect.bisect_right(timeline, (g_time, "~~~~", "~~~~"))
            end_boundary = datetime.max
            for i in range(idx, len(timeline)):
                if str(timeline[i][1]) != g_state:
                    end_boundary = timeline[i][0]; break

            for rule in self.abbm:
                trig = rule.get("trigger", {})
                # --- 针对您的 YAML 字段进行适配 ---
                # 您的 YAML 使用 'to' 代表目标状态，但也可能在 conditions 里使用 'state'
                rule_state = str(trig.get("to") or trig.get("state") or "")
                rule_eid = trig.get("entity_id")

                # 如果 ID 匹配 且 目标状态匹配
                if rule_eid == eid and rule_state == g_state:
                    print(f"  [Match Success] Rule '{rule.get('alias')}' matched Ghost {g_id}")
                    
                    # 获取 Action 命令名
                    target_cmd = rule.get("action", {}).get("service") or rule.get("action", {}).get("command")
                    
                    for c_id, c_data in verified_cmds:
                        c_time = parse_dt(c_data.get("_dt"))
                        # 只要命令名包含在 rule 的 service 里 (如 light.turn_on 包含 turn_on)
                        if target_cmd and (target_cmd in str(c_data.get("command"))) and (g_time <= c_time < end_boundary):
                            diff = (c_time - g_time).total_seconds()
                            self.G.add_edge(g_id, c_id, label=f"shouldAdvance\n(+{diff:.1f}s)", type="shouldAdvance")
                            print(f"  [=>] Causal Match: {g_id} triggered {c_id}")
                            break

    def phase_3_temporal(self):
        print("\n[Phase 3] Checking Temporal Latency (shouldPrecede)...")
        ghost_nodes = [n for n, d in self.G.nodes(data=True) if d.get("kind") == "GhostEntity"]
        for g_id in ghost_nodes:
            g_data = self.G.nodes[g_id]
            g_time, eid, state = g_data.get("_dt"), g_data.get("entity_id"), str(g_data.get("new_state"))
            timeline = self.query_oracle_timeline(eid)
            start_idx = bisect.bisect_right(timeline, (g_time, "~~~~", "~~~~"))
            for i in range(start_idx, len(timeline)):
                l_time, l_state, l_node = timeline[i]
                if "Ghost" in str(l_node): continue
                if str(l_state) == state:
                    lag = (l_time - g_time).total_seconds()
                    if 0 <= lag < 120.0:
                        self.G.add_edge(g_id, l_node, label=f"shouldPrecede\n({lag:.2f}s)", type="shouldPrecede")
                        break
                else: break

    
    def phase_4_inference(self):
        print("\n[Phase 3] Generating Tainted Subgraphs (Counterfactual)...")
        ghost_nodes = [n for n, d in self.G.nodes(data=True) if d.get("kind") == "GhostEntity"]
        
        for g_id in ghost_nodes:
            # --- 破解重叠的关键：检查是否已经建立了 shouldAdvance 关系 ---
            # 如果这个 Ghost 已经成功“提前”了某个真实指令，说明因果链已闭环，不再生成虚拟路径
            if any(edge_attr.get('type') == 'shouldAdvance' for _, _, edge_attr in self.G.edges(g_id, data=True)):
                print(f"  - Skip Trigger: {g_id} already advanced to a real command.")
                continue
            
            # 以下原有的逻辑不变...
            g_data = self.G.nodes[g_id]
            g_time, eid, state = parse_dt(g_data.get("_dt")), g_data.get("entity_id"), g_data.get("new_state")
            for rule in self.abbm:
                if rule["trigger"]["entity_id"] == eid and rule["trigger"]["state"] == state:
                    should_run, ctx_node = True, None
                    if rule.get("condition"):
                        cond = rule["condition"]
                        timeline = self.query_oracle_timeline(cond["entity_id"])
                        idx = bisect.bisect_right(timeline, (g_time, "~~~~", "~~~~"))
                        if idx > 0:
                            act_st, _, ctx_node = timeline[idx-1]
                            if act_st != cond["state"]: should_run = False
                        else: should_run = False
                    if should_run: self._inject_tainted_subgraph(g_id, rule, g_time, ctx_node)

    def _inject_tainted_subgraph(self,          trigger_id, rule, start_time, ctx_node):
        self.tainted_count += 1
        suffix = f"_T{self.tainted_count}"
        act = rule["action"]
        eff = rule["consequence"]
        
        # --- 修复 KeyError 的关键：安全获取 timing 配置 ---
        timing = rule.get("timing", {})
        # 优先读取特定字段，如果没有，则尝试从 max_advance_window 分配，再没有就给默认值
        cmd_delay = timing.get("command_delay_seconds", 0.1)
        
        # 逻辑：如果只有 max_advance_window_seconds，我们将响应时间设为其一半
        default_res_delay = timing.get("max_advance_window_seconds", 2.0) / 2
        res_delay = timing.get("physical_response_seconds", default_res_delay)
        
        cmd_dt = start_time + timedelta(seconds=cmd_delay)
        res_dt = cmd_dt + timedelta(seconds=res_delay)
        
        # 1. 注入 Tainted Command
        cmd_id = f"TaintedCmd_{act['command']}{suffix}"
        self.G.add_node(cmd_id, 
            label=f"Tainted Cmd\n{act['command']}\n(@{cmd_dt.strftime('%H:%M:%S')})", 
            kind="TaintedCommand", 
            command=act['command'],
            _dt=cmd_dt.isoformat(),
            timestamp=cmd_dt.isoformat())
        
        self.G.add_edge(trigger_id, cmd_id, label="shouldTrigger", type="shouldTrigger")
        if ctx_node: 
            self.G.add_edge(ctx_node, cmd_id, label="inform", type="inform")
        
        # 2. 注入 Tainted Entity (Consequence)
        res_id = f"TaintedRes_{eff['entity_id']}{suffix}"
        self.G.add_node(res_id,
            label=f"Tainted Entity\n{eff['state']}\n[{eff['semantic_label']}]",
            kind="TaintedEntity", 
            entity_id=eff['entity_id'],
            new_state=eff['state'],
            _dt=res_dt.isoformat(),
            timestamp=res_dt.isoformat())
            
        self.G.add_edge(cmd_id, res_id, label="sgen", type="sgen")
        print(f"  + Injected Tainted Chain: {act['command']} -> {eff['entity_id']}({eff['state']})")


    def phase_5_validity(self):
        print("\n[Phase 5] Detecting Interjections (sforbid)...")
        for n, d in self.G.nodes(data=True):
            if d.get("kind") == "Activity" and not d.get("is_zombie"):
                rule = self._get_rule_for_activity(n)
                if not rule: continue
                cmd_time = parse_dt(d.get("_dt"))
                for cond in rule.get("conditions", []):
                    timeline = self.query_oracle_timeline(cond.get("entity_id"))
                    idx = bisect.bisect_right(timeline, (cmd_time, "~~~~", "~~~~"))
                    if idx > 0 and str(timeline[idx-1][1]) != str(cond.get("state")):
                        if "Ghost" in str(timeline[idx-1][2]):
                            self.G.add_edge(timeline[idx-1][2], n, label=f"sforbid\n(Reality:{timeline[idx-1][1]})", type="sforbid")

    def phase_6_lineage(self):
        print("\n[Phase 6] Stitching state evolution (shouldDerive/shouldSync)...")
        for eid, timeline in self.oracle.items():
            sorted_tl = sorted(timeline, key=lambda x: x[0])
            for i in range(len(sorted_tl) - 1):
                curr_dt, curr_s, curr_node = sorted_tl[i]
                next_dt, next_s, next_node = sorted_tl[i+1]
                if "Ghost" in str(curr_node) or "Ghost" in str(next_node):
                    if str(curr_s) != str(next_s):
                        self.G.add_edge(curr_node, next_node, label="shouldDerive", type="shouldDerive")
                    else:
                        # 即使状态相同也建立 Sync 边，确保因果链完整，不被 Precede 掩盖
                        self.G.add_edge(curr_node, next_node, label="shouldPrecede", type="shouldPrecede")

    def phase_7_conflict_resolution(self):
        print("\n[Phase 7] Suppressing legacy edges...")
        edges_to_remove = []
        for g_id, next_id, d in self.G.edges(data=True):
            if d.get("type") in ["shouldPrecede", "shouldPrecede"]:
                predecessors = [u for u, v, attr in self.G.in_edges(g_id, data=True) if attr.get("type") == "shouldDerive"]
                for prev_node in predecessors:
                    if self.G.has_edge(prev_node, next_id):
                        if not self.G.get_edge_data(prev_node, next_id).get("type", "").startswith("s"):
                            edges_to_remove.append((prev_node, next_id))
        for u, v in edges_to_remove:
            self.G.edges[u, v]["type"], self.G.edges[u, v]["label"] = "suppressed", "[SUPPRESSED]"

    def run(self):
        self.phase_1_manifestation()
        self.debug_print_oracle("alarm_control_panel.lumi_mgl03_4e93_arming")
        self.phase_2_control_race() 
        self.phase_3_temporal()
        self.phase_5_validity()
        self.phase_6_lineage()
        self.phase_7_conflict_resolution()
        return self.G

# ==========================================
# 3. 导出与入口
# ==========================================
def export_corrected_graph_to_g6(G, output_path="shadow_prov_final_graph.json"):
    nodes_for_g6, edges_for_g6 = [], []
    for node_id, attrs in G.nodes(data=True):
        kind = attrs.get("kind", "Entity")
        g6_type = "GhostNode" if "Ghost" in kind else ("Activity" if kind in ["Command", "Activity"] else "Entity")
        nodes_for_g6.append({"id": str(node_id), "type": g6_type, "label": attrs.get("label", str(node_id)), "properties": {k: str(v) for k,v in attrs.items()}})
    for u, v, attrs in G.edges(data=True):
        et = attrs.get("type", "rel")
        edges_for_g6.append({"source": str(u), "target": str(v), "type": et, "label": attrs.get("label", "").replace("\n", " ")})
    with open(output_path, 'w', encoding='utf-8') as f: json.dump({"nodes": nodes_for_g6, "edges": edges_for_g6}, f, indent=4)

if __name__ == "__main__":
    GRAPH_FILE = "/Users/myf/shadowprov/RawLogs/A1/S2/delay/graph/provenance_analysis_data.json"
    DSA_FILE = "/Users/myf/shadowprov/LE/data/S2A1Delaycase#1/dsa_output.json"
    ABBM_FILE = "/Users/myf/shadowprov/config/abbm.yaml"
    
    if os.path.exists(GRAPH_FILE):
        G_cyb = load_g6_graph(GRAPH_FILE)
        with open(DSA_FILE, 'r', encoding='utf-8') as f: dsa_primitives = json.load(f)
        import yaml
        with open(ABBM_FILE, 'r', encoding='utf-8') as f: abbm_rules = yaml.safe_load(f)
        engine = LogicEngine(G_cyb, dsa_primitives, abbm_rules)
        corrected_G = engine.run()
        audit_correction_edges(corrected_G)
        export_corrected_graph_to_g6(corrected_G)