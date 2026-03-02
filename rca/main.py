import os
import json
import sys
current_dir = os.path.dirname(os.path.abspath(__file__))
# 获取项目根目录 (rca/ 的上一级，即 shadowprov/)
project_root = os.path.abspath(os.path.join(current_dir, ".."))
# 1. 解决跨文件夹调用 dsa_engine 的问题
if project_root not in sys.path:
    sys.path.append(project_root)

# 2. 修改文件加载函数，使其基于根目录
def get_absolute_path(relative_path):
    """将基于根目录的相对路径转换为绝对路径"""
    return os.path.join(project_root, relative_path)


from dsa.dsa_engine import DeviationSearchEngine
from selector import InteractionCausalSelector
from contextual_graph import ContextualGraphBuilder
from facts import RCAFactExtractor
from diagnosis import RCADiagnoser  


def load_json(filepath):
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def main():
    HA_IP='192.168.0.157'
    PCAP_FILE = get_absolute_path("RawLogs/A1/S2/delay/capture_br-lan.pcap")
    PROFILES_DIR = get_absolute_path("dsa/profiles") 
    ENTITY_CONFIG_PATH = get_absolute_path("dsa/profiles/entity_config.json")
    APP_LOG_FILE = get_absolute_path("dsa/data/app_atomics_A1S2Delay.json")
    SHADOW_FILE = get_absolute_path("dsa/profiles/actuator_profiles.json")
        
    # --- 新增：加载实体配置 ---
    entity_config= load_json(ENTITY_CONFIG_PATH).get("ENTITY_CONFIG", {})

    # 2. 引擎启动：提取跨层基元与网络流
    engine = DeviationSearchEngine(PCAP_FILE, APP_LOG_FILE, PROFILES_DIR, "192.168.0.1")
    bundle = engine.get_results_bundle()
    all_net_atoms = bundle['net_atomic_pool']
    dsa_primitives = bundle['dsa_primitives'][:-8]
    print(f"[*] Net atoms: {len(all_net_atoms)}, DSA primitives: {len(dsa_primitives)}")

    # 2. 提取因果上下文
    selector = InteractionCausalSelector(all_net_atoms, entity_config)
    causal_contexts = selector.batch_extract(dsa_primitives)[:-8]
    print(f"[*] Extracted {len(causal_contexts)} contexts")

    # 3. 加载影子配置（用于事实提取）
    shadow_data = load_json(SHADOW_FILE)

    # 4. 实例化事实提取器和诊断器
    fact_extractor = RCAFactExtractor(HA_IP, shadow_data)
    diagnoser = RCADiagnoser(entity_config, time_window=120.0)


    # 5. 对每个原语进行诊断
    all_diagnoses = []
    results_by_id = {}  # 用 primitive_id 索引

    print("\n" + "="*80)
    print(" RCA Diagnosis Results")
    print("="*80)


    for ctx in causal_contexts:
        primitive = ctx['primitive']
        flows = ctx['context_flows']
        entity_id = ctx['entity_id']
        target_device_ip = entity_config.get(entity_id, "Null")

        if not flows: continue

        # 4. 构建图
        builder = ContextualGraphBuilder(HA_IP, agg_window=5.0)
        G = builder.build_micro_graph(flows)

        # 5. 执行提取
        facts = fact_extractor.extract_facts(G, target_device_ip, primitive, all_flows=all_net_atoms)

        
        print(f"\n[FACTS for {entity_id}]")
        if facts:
            for fact in facts:
                # fact 格式: (type, subject, object, details)
                fact_type, subj, obj, details = fact
                print(f"   {fact_type}: {subj} -> {obj} | {details}")
        else:
            print("   No facts extracted")

        # 诊断
        diag = diagnoser.diagnose(primitive, facts)

        # 获取当前原语的唯一 ID（假设 primitive 中有 node_id）
        prim_id = primitive.get('node_id')
        if prim_id:
            results_by_id[prim_id] = diag

        # 如果诊断结果中包含 matched_cmd_id，更新对应原语的诊断
        if 'matched_cmd_id' in diag and diag['matched_cmd_id'] in results_by_id:
            # 将原命令原语的诊断也设为延迟（或标记为已处理）
            cmd_diag = results_by_id[diag['matched_cmd_id']]
            cmd_diag['attack_atomic'] = 'COMMAND_DELAY'
            cmd_diag['confidence'] = diag['confidence']
            cmd_diag['explanation'] = f"Resolved as delayed CMD matched at {primitive['timestamp']:.2f}"
        
        all_diagnoses.append({
            "entity": entity_id,
            "primitive_type": primitive['type'],
            "label": primitive['metadata'].get('label', ''),
            "diagnosis": diag
        })
        
        # 打印简要结果
        print(f"\n[{entity_id}] {primitive['type']} -> {diag['attack_atomic']} (conf={diag['confidence']})")
        print(f"   Explanation: {diag['explanation']}")
        if facts:
            print(f"   Facts extracted: {len(facts)}")

    # 6. 攻击原子统计
    print("\n" + "="*80)
    attack_counts = {}
    for d in all_diagnoses:
        atom = d['diagnosis']['attack_atomic']
        attack_counts[atom] = attack_counts.get(atom, 0) + 1
    print("Attack Atomic Summary:")
    for atom, cnt in sorted(attack_counts.items()):
        print(f"  {atom}: {cnt}")



if __name__ == "__main__":
    main()