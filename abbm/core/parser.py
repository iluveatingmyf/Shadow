# core/parser.py
import yaml
import json
import os
import sys

# 确保可以引用同目录下的 translator
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from translator import SemanticTranslator

class StaticParser:
    def __init__(self, input_path, output_path):
        self.input_path = input_path
        self.output_path = output_path

    def parse_and_export(self):
        if not os.path.exists(self.input_path):
            print(f"[Error] {self.input_path} not found. Please place your automations.yaml there.")
            return

        with open(self.input_path, 'r', encoding='utf-8') as f:
            raw_rules = yaml.safe_load(f)

        logic_graph = {}
        for r in raw_rules:
            rid = r.get('id', 'rule_' + str(len(logic_graph)))
            logic_graph[rid] = {
                'id': rid,
                'alias': r.get('alias', 'unnamed'),
                'triggers': self._extract_state(r.get('trigger', [])),
                'conditions': self._extract_state(r.get('condition', [])),
                'actions': self._extract_actions(r.get('action', []))
            }

        # 核心：写入 JSON 文件
        os.makedirs(os.path.dirname(self.output_path), exist_ok=True)
        with open(self.output_path, 'w', encoding='utf-8') as f:
            json.dump(logic_graph, f, indent=4)
        
        print(f"[Verification] Static Analysis Complete.")
        print(f"  -> Input: {self.input_path}")
        print(f"  -> Output: {self.output_path}")
        print(f"  -> Rules Processed: {len(logic_graph)}")

    def _extract_state(self, data):
        if not data: return []
        if isinstance(data, dict): data = [data]
        res = []
        for x in data:
            entity = x.get('entity_id')
            state = str(x.get('to') or x.get('state', '')).lower()
            if entity: res.append({'entity': entity, 'state': state})
        return res

    def _extract_actions(self, data):
        if not data: return []
        if isinstance(data, dict): data = [data]
        actions = []
        for a in data:
            svc = a.get('service')
            entity = a.get('entity_id') or a.get('target', {}).get('entity_id')
            if svc and entity:
                actions.append({
                    'entity': entity,
                    'service': svc,
                    'expected_state': SemanticTranslator.to_physical_state(svc)
                })
        return actions

if __name__ == "__main__":
    # 执行解析
    parser = StaticParser('../input/automations.yaml', '../data/logic_graph.json')
    parser.parse_and_export()