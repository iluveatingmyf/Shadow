import os
import json
import sys
from collections import defaultdict
import networkx as nx
from typing import List, Dict, Any, Tuple, Optional

# 路径处理（保持不变）
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, ".."))
if project_root not in sys.path:
    sys.path.append(project_root)

def get_absolute_path(relative_path):
    return os.path.join(project_root, relative_path)


class RCAFactExtractor:
    def __init__(self, ha_ip: str, shadow_data: Dict):
        self.ha_ip = ha_ip
        self.shadow = shadow_data
        # 物理层基准线：IP -> 期待的真实 MAC
        self.baseline_macs = {
            "192.168.0.1": "50:64:2B:40:6C:54",
            "192.168.0.157": "DC:A6:32:F3:76:22",
            "192.168.0.192": "78:11:DC:B2:60:63",
            "192.168.0.217": "CC:4D:75:44:D4:74",
            "192.168.0.48": "54:EF:44:C8:4E:93",
            "192.168.0.252": "3C:BD:3E:99:C0:45",
            "192.168.0.196": "C4:93:BB:F0:6D:F1",
            "192.168.0.61": "04:CF:8C:08:B9:18",
            "192.168.0.176": "78:11:DC:90:B7:45"
        }

    def _get_flow_map(self, node_data: Dict) -> List[Dict]:
        """从聚合节点展开原始流列表"""
        flow_ids = node_data.get('flow_ids')
        sigs = node_data.get('sig_history')
        if flow_ids is None:
            flow_ids = [node_data.get('net_id')]
        if sigs is None:
            sigs = [node_data.get('sig', [])]
        res = []
        for fid, s in zip(flow_ids, sigs):
            if fid:
                res.append({"id": fid, "sig": self._parse_sig(s)})
        return res

    def _analyze_retransmission_patterns(self, entity_graph: nx.DiGraph) -> List[Tuple]:
        """
        检测重传模式：返回列表，每个元素为 (pkt_size, ids, info)
        info 包含 repeat_count
        """
        pkt_to_netids = defaultdict(set)
        for _, data in entity_graph.nodes(data=True):
            for f in self._get_flow_map(data):
                for val in f['sig']:
                    if abs(val) < 70:  # 过滤心跳/ACK
                        continue
                    pkt_to_netids[abs(val)].add(f['id'])
        results = []
        for pkt, ids in pkt_to_netids.items():
            if len(ids) >= 3:
                sorted_ids = sorted(ids)
                results.append((pkt, sorted_ids, {"repeat_count": len(ids)}))
        return results

    def _find_shadow_entry(self, p_label: str) -> Dict:
        """语义匹配应用标签到影子配置"""
        if p_label in self.shadow:
            return self.shadow[p_label]
        try:
            def clean(s):
                return s.lower().replace("alarm_control_panel.", "").strip()
            p_parts = [clean(x) for x in p_label.split('|')]
            for k, v in self.shadow.items():
                k_parts = [clean(x) for x in k.split('|')]
                if len(p_parts) == 2 and len(k_parts) == 2:
                    if (p_parts[0] in k_parts[0] or k_parts[0] in p_parts[0]) and \
                       (p_parts[1] in k_parts[1] or k_parts[1] in p_parts[1]):
                        return v
        except:
            pass
        return {}

    def _parse_sig(self, sig_data) -> List[int]:
        """将指纹解析为整数列表"""
        if not sig_data or sig_data == "None":
            return []
        if isinstance(sig_data, list):
            return sig_data
        if isinstance(sig_data, str):
            try:
                cleaned = sig_data.replace("'", '"')
                return json.loads(cleaned)
            except:
                return []
        return []

    def _contains_subsequence(self, full_seq: List[int], sub_seq: List[int]) -> bool:
        """检查子序列（仅首包）"""
        if not sub_seq:
            return False
        target_pkt = sub_seq[0]
        return target_pkt in full_seq


    def extract_facts(self, entity_graph: nx.DiGraph, target_ip: str,
                      primitive: Dict, all_flows: Optional[List[Dict]] = None) -> List[Tuple]:
        """
        提取事实，all_flows 为可选参数，用于精确响应检测。
        """
        facts = []
        p_id = primitive.get('node_id', 'unknown_event')
        p_type = primitive.get('type')          # MATCHED / UNSUPPORTED
        p_label = primitive.get('metadata', {}).get("label", "Unknown")

        shadow_entry = self._find_shadow_entry(p_label)
        expected_cmd = self._parse_sig(shadow_entry.get("cmd", []))
        cmd_pkt_size = abs(expected_cmd[0]) if expected_cmd else None

        # --- 1. 因果事实 ---
        for u, v in entity_graph.edges():
            u_data = entity_graph.nodes[u]
            v_data = entity_graph.nodes[v]
            facts.append(("cause", u, v, {
                "u_label": u_data.get('label'),
                "v_label": v_data.get('label'),
                "delay": v_data['ts_start'] - u_data['ts_end']
            }))

        # --- 2. 重传风暴检测 ---
        for pkt, ids, info in self._analyze_retransmission_patterns(entity_graph):
            facts.append(("pkt_storm", pkt, tuple(ids), info))

        # --- 3. 逐节点分析 ---
        for node_id, data in entity_graph.nodes(data=True):
            # 3.1 MAC 欺骗
            src_ip, dst_ip = data.get('src'), data.get('dst')
            src_mac, dst_mac = data.get('src_mac'), data.get('dst_mac')
            if src_ip in self.baseline_macs and src_mac:
                if src_mac.lower() != self.baseline_macs[src_ip].lower():
                    facts.append(("mac_spoof", "src", node_id, {
                        "ip": src_ip,
                        "expected": self.baseline_macs[src_ip],
                        "actual": src_mac
                    }))
            if dst_ip in self.baseline_macs and dst_mac:
                if dst_mac.lower() != self.baseline_macs[dst_ip].lower():
                    facts.append(("mac_spoof", "dst", node_id, {
                        "ip": dst_ip,
                        "expected": self.baseline_macs[dst_ip],
                        "actual": dst_mac
                    }))

            # 3.2 未授权注入
            if data.get('label') == "Unknown" and data.get('dst') == self.ha_ip:
                facts.append(("unauth_inject", p_id, node_id, {
                    "src": data.get('src'),
                    "count": data.get('count'),
                    "ts": data.get('ts_start')
                }))

        # --- 4. 跨层一致性（仅对 UNSUPPORTED 原语，且仅当存在部分包时生成事实）---
        if p_type == "UNSUPPORTED" and expected_cmd:
            partial_flows = []
            for _, d in entity_graph.nodes(data=True):
                for f in self._get_flow_map(d):
                    if self._contains_subsequence(f['sig'], expected_cmd):
                        partial_flows.append(f['id'])
            if partial_flows:
                facts.append(("missing_response", p_id, tuple(partial_flows), {
                    "cmd_sig": expected_cmd
                }))

        return facts