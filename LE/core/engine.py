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
def audit_correction_edges(G): # 去掉 self
    print("\n" + "="*50)
    print("        [AUDIT] FINAL CORRECTION REPORT")
    print("="*50)
    
    counts = defaultdict(int)
    # 按照边类型排序，让输出更有序
    sorted_edges = sorted(G.edges(data=True), key=lambda x: x[2].get("type", ""))
    
    for u, v, d in sorted_edges:
        et = d.get("type", "rel")
        if et.startswith("s") or et.startswith("should"):
            counts[et] += 1
            u_label = G.nodes[u].get("label", u).split("\n")[0]
            v_label = G.nodes[v].get("label", v).split("\n")[0]
            print(f"[{et:15}] {u} ({u_label}) \n                --> {v} ({v_label})")
            if et == "sreplace":
                print(f"                (!) Corrected displaced state in forbidden zone.")
    
    print("\n[Summary Statistics]")
    if not counts:
        print("  - No correction edges detected.")
    for t in sorted(counts.keys()):
        print(f"  - {t:15}: {counts[t]}")
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

    # === Phase 1: Manifestation ===
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

    # === 优化后的 Phase 2: Control Race ===
    def phase_2_control_race(self):
        print("\n[Phase 2] Generating shouldAdvance (Logic-based)...")
        ghost_nodes = [n for n, d in self.G.nodes(data=True) if d.get("kind") == "GhostEntity"]

        for g_id in ghost_nodes:
            g_data = self.G.nodes[g_id]
            eid = g_data.get("entity_id")
            g_time = g_data.get("_dt")

            # 策略：寻找在 Ghost 之后发生的、且业务逻辑上依赖该 Entity 的 Activity
            # 这样即使原始图中没有 wasUsedBy 边，我们也能通过 ABBM 规则建立逻辑关联
            for act_id, act_data in self.G.nodes(data=True):
                if act_data.get("kind") not in ["Activity", "Command"] or act_data.get("is_zombie"):
                    continue
                
                # 检查该 Activity 是否在逻辑上需要这个实体 (通过 ABBM 规则)
                rule = self._get_rule_for_activity(act_id)
                if not rule: continue
                
                # 检查规则的条件是否包含当前的 entity_id
                # 有些规则叫 'condition' (dict), 有些叫 'conditions' (list)，做个兼容
                raw_conds = rule.get("conditions", [])
                if rule.get("condition"): raw_conds.append(rule["condition"])
                
                is_dependent = any(str(c.get("entity_id")) == str(eid) for c in raw_conds)
                
                if is_dependent:
                    act_time = parse_dt(act_data.get("_dt"))
                    # 如果 Activity 发生在 Ghost 之后，且在合理的控制窗口内 (如 5秒)
                    if g_time <= act_time <= g_time + timedelta(seconds=5):
                        if not self.G.has_edge(g_id, act_id):
                            self.G.add_edge(g_id, act_id, label="shouldAdvance", type="shouldAdvance")
                            print(f"  [+] shouldAdvance (Logic): {g_id} -> {act_id}")

    def phase_3_temporal(self):
        print("\n[Phase 3] Checking Temporal Latency (shouldPrecede: Ghost -> Nearest Clean Entity)...")
        ghost_nodes = [n for n, d in self.G.nodes(data=True) if d.get("kind") == "GhostEntity"]
        
        for g_id in ghost_nodes:
            g_data = self.G.nodes[g_id]
            g_time, eid, g_state = g_data.get("_dt"), g_data.get("entity_id"), str(g_data.get("new_state"))
            
            timeline = self.query_oracle_timeline(eid)
            idx = bisect.bisect_right(timeline, (g_time, "~~~~", "~~~~"))
            
            for i in range(idx, len(timeline)):
                l_time, l_state, l_node = timeline[i]
                
                # 核心互斥检查：
                # 1. 必须是真实节点
                # 2. 状态一致
                # 3. ！！！该节点不能在禁区内 (in_forbidden_zone) ！！！
                #    如果在禁区内，它将被 Phase 8 的 replacedBy 处理，而不是 shouldPrecede
                if "Ghost" not in str(l_node) and str(l_state) == g_state:
                    if not self.G.nodes[l_node].get("in_forbidden_zone", False):
                        lag = (l_time - g_time).total_seconds()
                        self.G.add_edge(g_id, l_node, label=f"shouldPrecede\n({lag:.2f}s)", type="shouldPrecede")
                        print(f"  [+] shouldPrecede (Clean): {g_id} -> {l_node}")
                        break
                    else:
                        print(f"  [-] Skipping shouldPrecede for {l_node}: Node is in Forbidden Zone (Subject to Replacement).")
                        # 注意：这里不 break，因为可能在禁区之后还有一个干净的相同状态节点（虽然概率低）


    # === Phase 4: Counterfactual Inference ===
    def phase_4_inference(self):
        print("\n[Phase 4] Generating Tainted Subgraphs (Counterfactual)...")
        ghost_nodes = [n for n, d in self.G.nodes(data=True) if d.get("kind") == "GhostEntity"]
        
        for g_id in ghost_nodes:
            # 如果 Ghost 已经重新归因给了现存的真实 Activity (Rule 2)，则不应触发 Rule 3
            if any(edge_attr.get('type') == 'shouldAdvance' for _, _, edge_attr in self.G.edges(g_id, data=True)):
                continue
            
            g_data = self.G.nodes[g_id]
            g_time = parse_dt(g_data.get("_dt"))
            eid = g_data.get("entity_id")
            state = str(g_data.get("new_state")) # 统一转字符串防止类型匹配失败
            
            for rule in self.abbm:
                # 修复 KeyError: 安全地获取 trigger 和 state
                trigger_cfg = rule.get("trigger", {})
                if trigger_cfg.get("entity_id") == eid and str(trigger_cfg.get("state")) == state:
                    
                    should_run = True
                    ctx_node = None
                    
                    # 1. 检查 Context / Preconditions 是否满足
                    if rule.get("condition"):
                        cond = rule["condition"]
                        timeline = self.query_oracle_timeline(cond.get("entity_id"))
                        idx = bisect.bisect_right(timeline, (g_time, "~~~~", "~~~~"))
                        if idx > 0:
                            act_st, _, ctx_node = timeline[idx-1]
                            if str(act_st) != str(cond.get("state")): 
                                should_run = False
                        else: 
                            should_run = False
                    
                    # 2. 核心补齐：实现论文 Formula (11) 的 ¬Exists 逻辑
                    if should_run:
                        action_cmd = rule.get("action", {}).get("command")
                        # 检查在 g_time 之后的 [0, Δt] 窗口内，系统是否已经执行了该命令？
                        delta_t = timedelta(seconds=2.0) # 假设时间窗口为2秒，可根据配置读取
                        action_exists = False
                        
                        # 遍历图中的命令节点，查找是否有真实执行记录
                        for n, d in self.G.nodes(data=True):
                            if d.get("kind") in ["Activity", "Command"] and d.get("command") == action_cmd:
                                cmd_time = parse_dt(d.get("_dt"))
                                if g_time <= cmd_time <= g_time + delta_t:
                                    # 如果在有效窗口内找到了真实的命令，说明动作发生了，不需要脑补(Counterfactual)
                                    action_exists = True
                                    break
                        
                        # 只有在条件满足，且系统实际上没有执行该动作时，才推断 Tainted Graph
                        if not action_exists:
                            self._inject_tainted_subgraph(g_id, rule, g_time, ctx_node)
                        else:
                            print(f"  [-] Skipped Rule 3 for {g_id}: Action '{action_cmd}' actually executed in reality.")

    def _inject_tainted_subgraph(self, trigger_id, rule, start_time, ctx_node):
        self.tainted_count += 1
        suffix = f"_T{self.tainted_count}"
        act = rule["action"]
        eff = rule["consequence"]
        timing = rule.get("timing", {})
        cmd_delay = timing.get("command_delay_seconds", 0.1)
        default_res_delay = timing.get("max_advance_window_seconds", 2.0) / 2
        res_delay = timing.get("physical_response_seconds", default_res_delay)
        
        cmd_dt = start_time + timedelta(seconds=cmd_delay)
        res_dt = cmd_dt + timedelta(seconds=res_delay)
        
        cmd_id = f"TaintedCmd_{act['command']}{suffix}"
        self.G.add_node(cmd_id, label=f"Tainted Cmd\n{act['command']}\n(@{cmd_dt.strftime('%H:%M:%S')})", kind="TaintedCommand", command=act['command'], _dt=cmd_dt.isoformat(), timestamp=cmd_dt.isoformat())
        self.G.add_edge(trigger_id, cmd_id, label="shouldTrigger", type="shouldTrigger")
        if ctx_node: self.G.add_edge(ctx_node, cmd_id, label="inform", type="inform")
        
        res_id = f"TaintedRes_{eff['entity_id']}{suffix}"
        self.G.add_node(res_id, label=f"Tainted Entity\n{eff['state']}\n[{eff['semantic_label']}]", kind="TaintedEntity", entity_id=eff['entity_id'], new_state=eff['state'], _dt=res_dt.isoformat(), timestamp=res_dt.isoformat())
        self.G.add_edge(cmd_id, res_id, label="sgen", type="sgen")

    # === Phase 5: Validity (sforbid) ===
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

    # === NEW: Identify Forbidden Cascade ===
    def _identify_forbidden_cascade(self):
        """递归识别受攻击污染的全路径禁区"""
        forbidden_zone = set()
        seeds = [v for u, v, d in self.G.edges(data=True) if d.get("type") == "sforbid"]
        forbidden_zone.update(seeds)

        changed = True
        while changed:
            changed = False
            current_len = len(forbidden_zone)
            for u, v, d in self.G.edges(data=True):
                if u in forbidden_zone and v not in forbidden_zone:
                    et = d.get("type")
                    if et in ["Generate", "wasUsedBy", "Derive", "Trigger", "sgen", "strigger"]:
                        print("forbidden zone")
                        print(v)
                        forbidden_zone.add(v)
            if len(forbidden_zone) > current_len: changed = True
        
        
        #染色逻辑
        for nid in forbidden_zone:
            self.G.nodes[nid]["in_forbidden_zone"] = True
            # 可选：修改 label 方便可视化调试
            if "[FORBIDDEN]" not in self.G.nodes[nid].get("label", ""):
                self.G.nodes[nid]["label"] += "\n[FORBIDDEN]"

        return forbidden_zone

    # === 修正后的 Phase 8: 状态替换逻辑 ===
    def phase_8_restorative_sgen(self):
        print("\n[Phase 8] Restoring Silenced Commands (Causal Replacement)...")
        forbidden_zone = self._identify_forbidden_cascade()
        all_cmds = [n for n, d in self.G.nodes(data=True) if d.get("kind") in ["Activity", "Command"]]
        
        for cmd_id in all_cmds:
            cmd_data = self.G.nodes[cmd_id]
            if cmd_id in forbidden_zone or cmd_data.get("is_zombie"): continue

            # 寻找被沉默的命令
            has_clean_generate = any(d.get("type") in ["Generate", "sgen"] and target not in forbidden_zone 
                                     for _, target, d in self.G.out_edges(cmd_id, data=True))
            
            if not has_clean_generate:
                rule = self._get_rule_for_activity(cmd_id)
                if not rule: continue
                eff = self._get_effect_from_rule(rule)
                target_eid, target_state = eff.get("entity_id"), str(eff.get("state"))
                
                # 在时间线上寻找被“顶替”的脏节点
                cmd_dt = parse_dt(cmd_data.get("_dt"))
                timeline = self.query_oracle_timeline(target_eid)
                idx = bisect.bisect_left(timeline, (cmd_dt, "", ""))

                # --- 1. 往前找：寻找逻辑起点 A(ON) ---
                # idx-1 是时间轴上紧挨着命令之前的节点
                prev_node = None
                if idx > 0:
                    _, _, prev_node = timeline[idx-1]

                # --- 3. 建立修复边 ---
                if prev_node:
                    ghost_id = f"Ghost_Restored_{cmd_id}"
                    g_dt = cmd_dt + timedelta(milliseconds=350)
                    
                    self.G.add_node(ghost_id, label=f"Ghost Entity\n{target_eid}\n{target_state}", 
                                    kind="GhostEntity", entity_id=target_eid, new_state=target_state, 
                                    _dt=g_dt, timestamp=g_dt.isoformat())
                    
                    self.G.add_edge(prev_node, ghost_id, label="sreplacedBy", type="sreplacedBy")
                    
                    # Command --sgen--> Ghost
                    self.G.add_edge(cmd_id, ghost_id, label="sgen", type="sgen")

                    
                    bisect.insort(self.oracle[target_eid], (g_dt, target_state, ghost_id))


    # === Phase 6: Lineage ===
    def phase_6_lineage(self):
        print("\n[Phase 6] Stitching state evolution...")
        for eid, timeline in self.oracle.items():
            sorted_tl = sorted(timeline, key=lambda x: x[0])
            for i in range(len(sorted_tl) - 1):
                curr_dt, curr_s, curr_node = sorted_tl[i]
                next_dt, next_s, next_node = sorted_tl[i+1]
                
                # 防护 A: 如果已经有 replacedBy 关系，严禁再加演化边
                if self.G.has_edge(next_node, curr_node) and self.G[next_node][curr_node].get("type") == "replacedBy":
                    continue

                if "Ghost" in str(curr_node) or "Ghost" in str(next_node):
                    if str(curr_s) != str(next_s):
                        # 只有在没有被 replacedBy 的情况下才加推演
                        if not self.G.has_edge(curr_node, next_node):
                            self.G.add_edge(curr_node, next_node, label="shouldDerive", type="shouldDerive")
                    else:
                        # 相同状态走对齐
                        if not self.G.has_edge(curr_node, next_node):
                            self.G.add_edge(curr_node, next_node, label="shouldPrecede", type="shouldPrecede")
    # === Phase 7: Conflict Resolution ===
    # === 优化后的 Phase 7: Conflict Resolution ===
    def phase_7_conflict_resolution(self):
        print("\n[Phase 7] Suppressing legacy edges (Strict Shadow Path Reduction)...")
        edges_to_suppress = []

        # 定义允许构成“影子逻辑通路”的边类型
        # 这些边代表了逻辑上的推导、替换和时间对齐
        SHADOW_EDGE_TYPES = {"shouldDerive", "shouldPrecede", "sreplacedBy", "sgen"}

        # 获取所有原始的物理推导边
        physical_derives = [(u, v) for u, v, d in self.G.edges(data=True) if d.get("type") == "Derive"]

        for u, v in physical_derives:
            # 临时移除物理边以寻找替代的逻辑路径
            edge_data = self.G.get_edge_data(u, v)
            self.G.remove_edge(u, v)
            
            try:
                # 寻找从 u 到 v 的所有简单路径
                for path in nx.all_simple_paths(self.G, source=u, target=v):
                    # 验证路径属性：
                    # 1. 路径中必须包含至少一个 Ghost 节点
                    # 2. 路径上的每一条边都必须属于 SHADOW_EDGE_TYPES
                    
                    has_ghost = any("Ghost" in str(node) or self.G.nodes[node].get("kind") == "GhostEntity" 
                                    for node in path)
                    
                    if not has_ghost:
                        continue

                    # 检查路径上的所有边是否都是逻辑边
                    all_logical_edges = True
                    for i in range(len(path) - 1):
                        curr_edge_type = self.G[path[i]][path[i+1]].get("type")
                        if curr_edge_type not in SHADOW_EDGE_TYPES:
                            all_logical_edges = False
                            break
                    
                    if all_logical_edges:
                        edges_to_suppress.append((u, v))
                        path_str = " -> ".join([str(n) for n in path])
                        print(f"  [-] Suppression: {u}->{v} replaced by Shadow Path [{path_str}]")
                        break
            except nx.NetworkXNoPath:
                pass
            finally:
                # 恢复边，后续统一标记
                self.G.add_edge(u, v, **edge_data)

        # 执行抑制标记
        for u, v in edges_to_suppress:
            self.G[u][v]["type"] = "suppressed"
            self.G[u][v]["label"] = "[SUPPRESSED] (Causal Correction)"

    
    def run(self):
        # 严格按照全生命周期流转
        self.phase_1_manifestation()
        
        self.phase_5_validity()
        self.phase_8_restorative_sgen()
        self.phase_3_temporal()
        self.phase_2_control_race() 
        self.phase_4_inference()
        self.phase_6_lineage()
        self.phase_7_conflict_resolution()
        return self.G

# ==========================================
# 3. 导出与入口
# ==========================================
def export_raw_logic_graph(G, output_path="shadow_prov_logic_graph.json"):
    """
    完全保留推理语义的导出，不进行任何 schema 转换
    """
    nodes_for_json, edges_for_json = [], []
    for node_id, attrs in G.nodes(data=True):
        # 保留所有原始属性，包括 kind, sub_kind, is_zombie 等
        node_entry = {"id": str(node_id)}
        node_entry.update({k: str(v) for k, v in attrs.items()})
        nodes_for_json.append(node_entry)
    
    for u, v, attrs in G.edges(data=True):
        # 严格保留 sreplace, shouldTrigger, sforbid 等推理语义
        edge_entry = {
            "source": str(u),
            "target": str(v),
            "type": attrs.get("type", "rel"),
            "label": attrs.get("label", "")
        }
        # 附带所有推理元数据（如 lag 时间，audit 备注等）
        edge_entry.update({k: str(v) for k, v in attrs.items() if k not in ["source", "target", "type", "label"]})
        edges_for_json.append(edge_entry)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump({"nodes": nodes_for_json, "edges": edges_for_json}, f, indent=4)
    print(f"[*] Logic Graph exported to {output_path} (Raw Inference preserved).")


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
        export_raw_logic_graph(corrected_G)