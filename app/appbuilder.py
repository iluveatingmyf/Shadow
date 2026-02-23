# -*- coding: utf-8 -*-
import json
import logging
import bisect
import os
from datetime import datetime, timedelta
from collections import defaultdict
from typing import List, Dict, Any, Optional

import networkx as nx
from pyvis.network import Network

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RobustOriginalPGBuilder:
    def __init__(self, raw_events: List[Dict[str, Any]], height="900px", width="100%"):
        cleaned = self._validate_and_sanitize(raw_events)
        self.events = self._inject_anchor_states(cleaned)
        
        self.ev_map = {str(e["event_ID"]): e for e in self.events}
        self.entity_timeline = defaultdict(list)
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
        self.use_concise_labels = True # 默认启用简洁标签

    def _inject_anchor_states(self, cleaned_events: List[Dict]) -> List[Dict]:
        if not cleaned_events: return cleaned_events
        state_oracle = {}
        start_dt = cleaned_events[0]["_dt"]
        anchor_dt = start_dt - timedelta(seconds=1)
        anchor_ts = anchor_dt.strftime("%H:%M:%S.%f")[:-3]
        injected_events = []

        for e in cleaned_events:
            et = e.get("event_type")
            if et == "Entity":
                state_oracle[e.get("entity_id")] = f"Entity_{str(e.get('event_ID'))}"
            elif e.get("action") == "condition_check":
                ent_id = e.get("condition_entity_id")
                if ent_id and ent_id not in state_oracle:
                    v_eid = f"anchor_{ent_id}"
                    anchor_event = {
                        "timestamp": anchor_ts, "device": e.get("condition_entity") or ent_id,
                        "raw_device_id": ent_id, "event_type": "Entity",
                        "description": "Inferred Anchor State", "source": "System_Genesis",
                        "event_ID": v_eid, "session_id": e.get("session_id"),
                        "entity_id": ent_id, "old_state": "unknown",
                        "new_state": e.get("condition_state"), "_dt": anchor_dt
                    }
                    injected_events.append(anchor_event)
                    state_oracle[ent_id] = f"Entity_{v_eid}"
                    logger.info(f"Oracle Inference: Injected {ent_id} as '{e.get('condition_state')}'")

        return injected_events + cleaned_events

    def _parse_time(self, ts: Any) -> Optional[datetime]:
        if not ts: return None
        if isinstance(ts, datetime): return ts
        for fmt in ("%H:%M:%S.%f", "%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            if '%z' in fmt:
                ts_str = str(ts)
                if ts_str.endswith('Z'): ts_str = ts_str[:-1] + '+0000'
                elif '+' in ts_str and ts_str[-3] == ':': ts_str = ts_str[:-3] + ts_str[-2:]
                try: return datetime.strptime(ts_str, fmt)
                except ValueError: continue
            else:
                try: return datetime.strptime(str(ts), fmt)
                except ValueError: continue
        return None

    def _validate_and_sanitize(self, raw: List[Dict]) -> List[Dict]:
        clean = []
        for e in raw:
            if not e.get("event_ID"): continue
            ts_str = e.get("timestamp") or e.get("time_fired")
            dt = self._parse_time(ts_str)
            if not dt: continue
            
            new_e = e.copy(); new_e["_dt"] = dt; new_e["event_ID"] = str(e["event_ID"])
            if "condition_ids" in new_e and isinstance(new_e["condition_ids"], list):
                new_e["condition_ids"] = [str(cid) for cid in new_e["condition_ids"]]
            clean.append(new_e)
        clean.sort(key=lambda x: x["_dt"])
        return clean

    def _add_node(self, node_id: str, kind: str, label: str, **attrs):
        shape_map = {
        "Entity": "ellipse",    # 圆形表示静态实体
        "Agent": "diamond",         # 方框表示触发者
        "Activity": "box", # 或者用 diamond 表示动作
        "PanelAgent": "star"
        }
        if node_id not in self.G:
            color_map = {"Entity": "#6495ED", "Agent": "#98FB98", "Activity": "#FFA07A", "PanelAgent": "#DDA0DD"}
            title_attrs = {k: str(v) for k, v in attrs.items() if not k.startswith("_")}
            title = "<br>".join([f"<b>{kind}</b>"] + [f"{k}: {v}" for k, v in title_attrs.items()])
            self.G.add_node(node_id, label=label,shape=shape_map.get(kind, "dot"), kind=kind, color=color_map.get(kind, "#eee"), title=title, **attrs)

    def _pass_add_nodes(self):
        for e in self.events:
            et, eid = e["event_type"], e["event_ID"]
            label = ""
            if self.use_concise_labels:
                if et == "Entity":
                    ent_id = e.get('entity_id', 'N/A')
                    short_id = ent_id.split('.')[-1] if '.' in ent_id else ent_id
                    label = f"Entity\n{short_id}\n{e.get('old_state','?')} → {e.get('new_state','?')}"
                elif et == "Agent":
                    device = e.get('device', 'N/A')
                    label = f"Agent\n{device}"
                    if e.get("action") == "condition_check" or "Condition" in e.get("description", ""): label += "\n(+Cond)"
                elif et == "Command":
                    cmd = e.get('command', 'N/A').split('.')[-1]
                    status = "OK" if e.get('status') == "executed" else "Blocked"
                    label = f"Activity\n{cmd}\nStatus: {status}"
            else: # Original verbose labels
                if et == "Entity": label = f"Entity\n{e.get('entity_id')}\n{e.get('old_state','')} → {e.get('new_state','')}"
                elif et == "Agent": label = f"Agent\n{e.get('device')}" + ("\n(+Condition)" if "Condition" in e.get("description", "") else "")
                elif et == "Command": label = f"Activity\n{e.get('command')}\nStatus: {e.get('status')}"

            if et == "Entity":
                self.node_of_event[eid] = f"Entity_{eid}"; self._add_node(self.node_of_event[eid], "Entity", label, **e)
            elif et == "Agent":
                node_id = None
                if e.get("action") == "triggered":
                    node_id = f"Agent_{eid}"; self.trigger_to_node_map[eid] = node_id
                elif e.get("action") == "condition_check":
                    rel_id = str(e.get("related_trigger_id", ""))
                    if rel_id in self.trigger_to_node_map:
                        node_id = self.trigger_to_node_map[rel_id]
                        if "(+Cond)" not in self.G.nodes[node_id].get("label", ""): self.G.nodes[node_id]["label"] += "\n(+Cond)"
                    else: node_id = f"Agent_Orphan_{eid}"
                if node_id: self.node_of_event[eid] = self.agent_node_of_event[eid] = node_id; self._add_node(node_id, "Agent", label, **e)
            elif et == "Command":
                self.node_of_event[eid] = f"Command_{eid}"; self._add_node(self.node_of_event[eid], "Activity", label, **e)

    def _latest_entity_before(self, entity_id: str, dt: datetime) -> Optional[str]:
        if not entity_id or entity_id not in self.entity_timeline: return None
        timeline = self.entity_timeline[entity_id]; idx = bisect.bisect_right(timeline, (dt, "~~~~")); return timeline[idx-1][1] if idx > 0 else None

    def _pass_add_semantic_edges(self):
        for e in self.events:
            eid, et = e["event_ID"], e["event_type"]
            if et == "Command":
                cmd_node = self.node_of_event.get(eid)
                if not cmd_node: continue
                p_ctx, src = e.get("parent_context_id"), str(e.get("source", ""))
                if p_ctx:
                    for ps in self.context_map.get(str(p_ctx), []):
                        if ps.get("event_type") == "Entity" and (root_eid := str(ps.get("event_ID"))) in self.node_of_event:
                            self.G.add_edge(self.node_of_event[root_eid], cmd_node, label="wasUsedBy", type="wasUsedBy")
                if src in self.agent_node_of_event: self.G.add_edge(self.agent_node_of_event[src], cmd_node, label="wasAssociateWith", type="wasAssociateWith")
                elif src == "panel":
                    self.panel_counter += 1; p_node = f"PanelAgent_{self.panel_counter}"
                    self._add_node(p_node, "PanelAgent", f"User Panel\n#{self.panel_counter}", device="Manual Panel", _dt=e['_dt'])
                    self.G.add_edge(p_node, cmd_node, label="wasAssociateWith", type="wasAssociateWith")
                for cid in e.get("condition_ids", []):
                    if (cond_ev := self.ev_map.get(str(cid))) and (target_eid := self._latest_entity_before(cond_ev.get("condition_entity_id"), e["_dt"])) in self.node_of_event:
                        res = cond_ev.get("condition_result"); label = "isConditionOf" if res else "Forbid"
                        self.G.add_edge(self.node_of_event[target_eid], cmd_node, label=f"{label}\n({cond_ev.get('condition_state')})", type=label, color="green" if res else "red")
            elif et == "Entity":
                if (curr_entity_node := self.node_of_event.get(eid)) and (ctx_id := e.get("context_id")):
                    for sibling in self.context_map.get(str(ctx_id), []):
                        if sibling.get("event_type") == "Command" and e["_dt"] > sibling["_dt"] and sibling.get("target_device") == e.get("entity_id") and sibling.get("status") == "executed" and (cmd_eid := str(sibling["event_ID"])) in self.node_of_event:
                            self.G.add_edge(self.node_of_event[cmd_eid], curr_entity_node, label="Generate", type="Generate")

    def _pass_add_derive(self):
        for _, timeline in self.entity_timeline.items():
            for i in range(1, len(timeline)):
                if (prev := self.node_of_event.get(timeline[i-1][1])) and (curr := self.node_of_event.get(timeline[i][1])):
                    self.G.add_edge(prev, curr, label="Derive", type="Derive")

    def build(self, use_concise_labels=True):
        self.use_concise_labels = use_concise_labels
        self.G.clear() # Ensure graph is empty before building
        self._pass_add_nodes(); self._pass_add_semantic_edges(); self._pass_add_derive(); return self.G


    def export_json(self, path="provenance_data.json"):
        """将图结构导出为便于程序分析的 JSON 格式"""
        try:
            # 使用 networkx 的 node_link_data 格式
            # 它会生成一个包含 "nodes" 和 "links" 的字典
            data = nx.node_link_data(self.G)
            
            # 清理数据以确保 JSON 可序列化（移除 datetime 对象）
            for node in data['nodes']:
                for k, v in list(node.items()):
                    if isinstance(v, datetime):
                        node[k] = v.isoformat()
            
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"溯源数据 JSON 已导出至: {path}")
        except Exception as e:
            logger.error(f"导出 JSON 失败: {e}")


    def export_pyvis(self, path="provenance_graph.html", mode="B", layout_direction="UD"):
        sub_G = self.G.copy()
        # 模式过滤逻辑
        if mode == "A": 
            nodes_to_remove = [n for n, d in sub_G.nodes(data=True) if str(d.get('status')).lower() == 'blocked']
            sub_G.remove_nodes_from(nodes_to_remove)
            edges_to_remove = [(u, v) for u, v, d in sub_G.edges(data=True) if d.get('type') == 'Forbid']
            sub_G.remove_edges_from(edges_to_remove)
        elif mode == "C": 
            relevant_nodes = set()
            for u, v, d in sub_G.edges(data=True):
                if d.get('type') == 'Forbid' or str(sub_G.nodes[v].get('status', '')).lower() == 'blocked':
                    relevant_nodes.update([u, v])
            nodes_to_remove = [n for n in sub_G.nodes() if n not in relevant_nodes]
            sub_G.remove_nodes_from(nodes_to_remove)

        # 清理 datetime 对象
        for _, attrs in sub_G.nodes(data=True):
            safe_attrs = {k: v for k, v in attrs.items() if not isinstance(v, datetime)}
            attrs.clear()
            attrs.update(safe_attrs)
        
        net = Network(height=self.height, width=self.width, directed=True, bgcolor="#f0f0f0")
        net.from_nx(sub_G)
        
        # 注意：这里移除了所有 Python 风格的注释，确保是纯净的 JSON 字符串
        options_str = f"""{{
          "edges": {{
            "smooth": {{
              "enabled": true,
              "type": "cubicBezier",
              "forceDirection": "vertical",
              "roundness": 0.5
            }},
            "arrows": {{ "to": {{ "enabled": true, "scaleFactor": 1 }} }}
          }},
          "layout": {{
            "hierarchical": {{
              "enabled": true,
              "direction": "{layout_direction}",
              "sortMethod": "hubsize",
              "levelSeparation": 180, 
              "nodeSpacing": 350,
              "treeSpacing": 350,
              "blockShifting": true,
              "edgeMinimization": true,
              "parentCentralization": true
            }}
          }},
          "physics": {{
            "enabled": true,
            "hierarchicalRepulsion": {{
              "centralGravity": 0.0,
              "springLength": 250,
              "springConstant": 0.01,
              "nodeDistance": 350,
              "damping": 0.09
            }},
            "solver": "hierarchicalRepulsion",
            "stabilization": {{
              "enabled": true,
              "iterations": 1000,
              "updateInterval": 50
            }}
          }},
          "interaction": {{
            "dragNodes": true,
            "hideEdgesOnDrag": false,
            "hideNodesOnDrag": false,
            "hover": true,
            "navigationButtons": true,
            "multiselect": true
          }}
        }}"""
        
        net.set_options(options_str)
        net.write_html(path)
        logger.info(f"PyVis Graph (Mode: {mode}) exported to: {path}")


if __name__ == "__main__":
    try:
        json_path = '../RawLogs/A1/S2/delay/filtered_logs.json' 
        if not os.path.exists(json_path):
            logger.error(f"错误: 文件 '{json_path}' 未找到。请将日志数据保存到该文件中。")
        else:
            with open(json_path, 'r', encoding='utf-8') as f: json_data = json.load(f)
            
            builder = RobustOriginalPGBuilder(json_data)
            
            # --- 使用简洁标签构建和导出 ---
            logger.info("--> 构建溯源图 (使用简洁标签)...")
            builder.build(use_concise_labels=True)
            builder.export_json("provenance_analysis_data.json")
            
            # 模式 'B': 完整的溯源图 (推荐)
            logger.info("正在导出 Mode 'B' (完整图)...")
            builder.export_pyvis("graph_B_full_concise.html", mode="B", layout_direction="UD")
            
            # 模式 'A': 只显示成功执行的路径
            logger.info("正在导出 Mode 'A' (仅成功路径)...")
            builder.export_pyvis("graph_A_executed_concise.html", mode="A", layout_direction="UD")

            # 模式 'C': 只显示导致失败/阻塞的路径
            logger.info("正在导出 Mode 'C' (仅失败路径)...")
            builder.export_pyvis("graph_C_violations_concise.html", mode="C", layout_direction="UD")

            logger.info("\n所有图形已成功导出！")
            
    except Exception as e: 
        logger.error(f"执行时发生错误: {e}", exc_info=True)