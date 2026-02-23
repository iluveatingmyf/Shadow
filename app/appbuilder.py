# -*- coding: utf-8 -*-
import json
import logging
import bisect
import os
from datetime import datetime
from collections import defaultdict
from typing import List, Dict, Any, Optional

import networkx as nx
from pyvis.network import Network

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RobustOriginalPGBuilder:
    def __init__(self, raw_events: List[Dict[str, Any]], height="800px", width="100%"):
        self.events = self._validate_and_sanitize(raw_events)
        self.ev_map = {str(e["event_ID"]): e for e in self.events}
        
        # 索引：用于查找设备最近的状态
        self.entity_timeline = defaultdict(list)
        # 上下文索引：用于基于 context_id 快速回溯
        self.context_map = defaultdict(list)
        
        for e in self.events:
            eid = str(e["event_ID"])
            if e["event_type"] == "Entity" and e.get("entity_id"):
                self.entity_timeline[e["entity_id"]].append((e["_dt"], eid))
            ctx_id = e.get("context_id")
            if ctx_id:
                self.context_map[str(ctx_id)].append(e)

        self.node_of_event: Dict[str, str] = {}
        self.agent_node_of_event: Dict[str, str] = {}
        self.trigger_to_node_map: Dict[str, str] = {}
        self.G = nx.DiGraph()
        self.height = height
        self.width = width
        self.panel_counter = 0

    def _parse_time(self, ts: Any) -> Optional[datetime]:
        if not ts: return None
        if isinstance(ts, datetime): return ts
        for fmt in ("%H:%M:%S.%f", "%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try: return datetime.strptime(str(ts), fmt)
            except ValueError: continue
        return None

    def _validate_and_sanitize(self, raw: List[Dict]) -> List[Dict]:
        clean = []
        for e in raw:
            if not e.get("event_ID"): continue
            dt = self._parse_time(e.get("timestamp"))
            if not dt: continue
            new_e = e.copy()
            new_e["_dt"] = dt
            new_e["event_ID"] = str(e["event_ID"])
            if "condition_ids" in new_e and isinstance(new_e["condition_ids"], list):
                new_e["condition_ids"] = [str(cid) for cid in new_e["condition_ids"]]
            clean.append(new_e)
        clean.sort(key=lambda x: x["_dt"])
        return clean

    def _add_node(self, node_id: str, kind: str, label: str, **attrs):
        if node_id not in self.G:
            color_map = {"Entity": "#6495ED", "Agent": "#98FB98", "Activity": "#FFA07A", "PanelAgent": "#DDA0DD"}
            safe_attrs = {k: str(v) for k, v in attrs.items() if not k.startswith("_")}
            self.G.add_node(node_id, label=label, kind=kind, color=color_map.get(kind, "#eee"), 
                            title="<br>".join([f"<b>{kind}</b>"] + [f"{k}: {v}" for k, v in safe_attrs.items()]), **safe_attrs)

    def _pass_add_nodes(self):
        for e in self.events:
            et, eid = e["event_type"], e["event_ID"]
            if et == "Entity":
                self.node_of_event[eid] = f"Entity_{eid}"
                self._add_node(self.node_of_event[eid], "Entity", f"Entity\n{e.get('entity_id')}\nEvent: {eid}", **e)
            elif et == "Agent":
                action = e.get("action")
                node_id = None
                if action == "triggered":
                    node_id = f"Agent_{eid}"
                    self._add_node(node_id, "Agent", f"Agent\nTrigger\n{e.get('device')}", role="Trigger", **e)
                    self.trigger_to_node_map[eid] = node_id
                elif action == "condition_check":
                    rel_id = str(e.get("related_trigger_id", ""))
                    if rel_id in self.trigger_to_node_map:
                        node_id = self.trigger_to_node_map[rel_id]
                        if "Condition" not in self.G.nodes[node_id]["label"]: 
                            self.G.nodes[node_id]["label"] += "\n(+Condition)"
                    else:
                        node_id = f"Agent_Orphan_{eid}"
                        self._add_node(node_id, "Agent", f"Agent\nCondition\n{eid}", role="Condition", **e)
                if node_id: self.node_of_event[eid] = self.agent_node_of_event[eid] = node_id
            elif et == "Command":
                self.node_of_event[eid] = f"Command_{eid}"
                self._add_node(self.node_of_event[eid], "Activity", f"Activity\n{e.get('command')}\nStatus: {e.get('status')}", **e)

    def _latest_entity_before(self, entity_id: str, dt: datetime) -> Optional[str]:
        if not entity_id or entity_id not in self.entity_timeline: return None
        timeline = self.entity_timeline[entity_id]
        idx = bisect.bisect_right(timeline, (dt, "~~~~"))
        return timeline[idx-1][1] if idx > 0 else None

    def _pass_add_semantic_edges(self):
        """核心逻辑：你调教好的 wasUsedBy 和 Generate 逻辑"""
        for e in self.events:
            eid, et = e["event_ID"], e["event_type"]
            if et == "Command":
                cmd_node = self.node_of_event.get(eid)
                if not cmd_node: continue
                
                # 1. wasUsedBy: 基于 parent_context_id 匹配
                p_ctx = e.get("parent_context_id")
                if p_ctx:
                    for ps in self.context_map.get(str(p_ctx), []):
                        if ps.get("event_type") == "Entity":
                            root_eid = str(ps.get("event_ID"))
                            if root_eid in self.node_of_event:
                                self.G.add_edge(self.node_of_event[root_eid], cmd_node, label="wasUsedBy", type="wasUsedBy")

                # 2. wasAssociateWith: 处理 Agent 或 Panel
                src = str(e.get("source", ""))
                if src in self.agent_node_of_event:
                    self.G.add_edge(self.agent_node_of_event[src], cmd_node, label="wasAssociateWith", type="wasAssociateWith")
                elif src == "panel":
                    self.panel_counter += 1
                    p_node = f"PanelAgent_{self.panel_counter}"
                    self._add_node(p_node, "PanelAgent", f"User Panel\n#{self.panel_counter}", device="Manual Panel")
                    self.G.add_edge(p_node, cmd_node, label="wasAssociateWith", type="wasAssociateWith")

                # 3. Condition/Forbid 逻辑
                for cid in e.get("condition_ids", []):
                    cond_ev = self.ev_map.get(str(cid))
                    if not cond_ev: continue
                    target_eid = self._latest_entity_before(cond_ev.get("condition_entity_id"), e["_dt"])
                    if target_eid and target_eid in self.node_of_event:
                        res = cond_ev.get("condition_result")
                        label = "isConditionOf" if res else "Forbid"
                        self.G.add_edge(self.node_of_event[target_eid], cmd_node, 
                                        label=f"{label}\n({cond_ev.get('condition_state')})", 
                                        type=label, color="green" if res else "red")

            elif et == "Entity":
                # 4. Generate: 基于 Context ID 判定
                curr_entity_node = self.node_of_event.get(eid)
                ctx_id = e.get("context_id")
                if ctx_id and curr_entity_node:
                    for sibling in self.context_map.get(str(ctx_id), []):
                        if sibling.get("event_type") == "Command" and e["_dt"] > sibling["_dt"]:
                            if sibling.get("target_device") == e.get("entity_id"):
                                cmd_eid = str(sibling["event_ID"])
                                if cmd_eid in self.node_of_event:
                                    self.G.add_edge(self.node_of_event[cmd_eid], curr_entity_node, 
                                                    label="Generate", type="Generate")

    def _pass_add_derive(self):
        for _, timeline in self.entity_timeline.items():
            for i in range(1, len(timeline)):
                prev, curr = self.node_of_event.get(timeline[i-1][1]), self.node_of_event.get(timeline[i][1])
                if prev and curr: self.G.add_edge(prev, curr, label="Derive", type="Derive")

    def build(self):
        self._pass_add_nodes()
        self._pass_add_semantic_edges()
        self._pass_add_derive()
        return self.G

    def export_pyvis(self, path="provenance_graph.html", mode="B"):
        """
        引入 Mode A/B/C 的导出逻辑
        A: 执行成功的路径 (Executed Only)
        B: 完整路径 (Full)
        C: 仅阻断路径 (Violations Only)
        """
        # 1. 过滤逻辑
        sub_G = self.G.copy()
        if mode == "A":
            # 移除所有被阻断的节点和 Forbid 边
            nodes_to_remove = [n for n, d in sub_G.nodes(data=True) if str(d.get('status')).lower() == 'blocked']
            sub_G.remove_nodes_from(nodes_to_remove)
            edges_to_remove = [(u, v) for u, v, d in sub_G.edges(data=True) if d.get('type') == 'Forbid']
            sub_G.remove_edges_from(edges_to_remove)
        elif mode == "C":
            # 仅保留涉及 Forbid 或 Blocked 的逻辑链
            relevant_nodes = set()
            for u, v, d in sub_G.edges(data=True):
                if d.get('type') == 'Forbid' or str(sub_G.nodes[v].get('status')).lower() == 'blocked':
                    relevant_nodes.update([u, v])
            nodes_to_remove = [n for n in sub_G.nodes() if n not in relevant_nodes]
            sub_G.remove_nodes_from(nodes_to_remove)

        # 2. 核心修复：清理 datetime 对象防止 JSON 报错
        for _, attrs in sub_G.nodes(data=True):
            for k, v in list(attrs.items()):
                if isinstance(v, datetime): attrs[k] = v.isoformat()
        for _, _, attrs in sub_G.edges(data=True):
            for k, v in list(attrs.items()):
                if isinstance(v, datetime): attrs[k] = v.isoformat()

        # 3. PyVis 配置 (BarnesHut 物理引擎，不重叠)
        net = Network(height=self.height, width=self.width, directed=True, bgcolor="#f0f0f0")
        net.from_nx(sub_G)
        net.set_options("""
        {
          "physics": {
            "barnesHut": {
              "gravitationalConstant": -20000,
              "centralGravity": 0.3,
              "springLength": 150,
              "springConstant": 0.04,
              "avoidOverlap": 1
            },
            "solver": "barnesHut"
          },
          "edges": { "smooth": { "type": "continuous" } },
          "interaction": { "dragNodes": true, "zoomView": true }
        }
        """)
        net.write_html(path)
        logger.info(f"PyVis Graph ({mode}) exported: {path}")

    def export_for_g6(self, output_path: str = "provenance_for_g6.json"):
        """保留 G6 导出以支持 Combo 泳道分析"""
        nodes, combos = [], {}
        for node_id, attrs in self.G.nodes(data=True):
            dev_id = attrs.get('entity_id') or attrs.get('device') or "System"
            if dev_id not in combos:
                combos[dev_id] = {"id": f"combo_{dev_id}", "label": dev_id}
            nodes.append({
                "id": node_id, "comboId": f"combo_{dev_id}", "type": attrs.get('kind'),
                "label": attrs.get('label'), "isKeyNode": "blocked" in str(attrs.get('status', '')).lower(),
                "properties": {k: str(v) for k, v in attrs.items() if not k.startswith('_')}
            })
        edges = [{"source": u, "target": v, "label": attrs.get("label", "")} for u, v, attrs in self.G.edges(data=True)]
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump({"nodes": nodes, "edges": edges, "combos": list(combos.values())}, f, indent=4, ensure_ascii=False)

if __name__ == "__main__":
    try:
        json_path = '../RawLogs/groundtruth/S2/filtered_logs.json'
        if os.path.exists(json_path):
            with open(json_path, 'r') as f:
                json_data = json.load(f)
            builder = RobustOriginalPGBuilder(json_data)
            builder.build()
            
            # 同时生成三个 PyVis 报告
            builder.export_pyvis("graph_executed_pyvis.html", mode="A")
            builder.export_pyvis("graph_full_pyvis.html", mode="B")
            builder.export_pyvis("graph_violations_pyvis.html", mode="C")
            
            builder.export_for_g6()
        else:
            logger.warning(f"File not found: {json_path}")
    except Exception as e:
        logger.error(f"Execution Error: {e}", exc_info=True)