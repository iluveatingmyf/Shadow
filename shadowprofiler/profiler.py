import json
import os
import warnings
from collections import defaultdict
from core.associative_engine import AssociativeEngine
from analyzer.pattern_miner import NoiseRobustMiner

# 屏蔽异步告警
warnings.filterwarnings("ignore", category=RuntimeWarning)

def main():
    # 1. 初始化引擎与应用信息
    PCAP_DIR = "data/pcap"
    DEVICE_MAP = "data/device_map.json"
    TRACE_FILE = "data/experimental.jsonl"
    OUTPUT = "final_fingerprints.json"

    print("[*] Loading Application Traces...")
    engine = AssociativeEngine(PCAP_DIR, DEVICE_MAP)

    with open(TRACE_FILE, 'r') as f:
        traces = [json.loads(line) for line in f if line.strip()]

    # 1. 校准 HA 偏移
    # 1. 校准 HA 偏移
    engine.calibrate_ha_offset(traces)

    # 2. 自动搜索最佳路由器偏移
    engine.auto_search_router_offset(traces, offset_range=(-20, 20), step=0.5)
    print("[*] Grouping Atomic Flows by Rule...")
    rule_data = defaultdict(lambda: {"cmds": [], "ents": []})
    
    success_count = 0
    fail_count = 0

    for t in traces:
        dual = engine.get_dual_flows(t)
        
        # 修复：增加非空判定
        if dual is None:
            fail_count += 1
            continue
            
        rid = t['rule_id']
        # 只有当 Command 流存在时才记录（一个动作必须有指令）
        if dual.get("cmd"):
            rule_data[rid]["cmds"].append(dual["cmd"])
            success_count += 1
            # Entity 可能在同一个流里，也可能在独立流里，由 engine 处理
            if dual.get("ent"):
                rule_data[rid]["ents"].append(dual["ent"])
        else:
            fail_count += 1

    print(f"[*] Extraction Summary: {success_count} success, {fail_count} failed.")
    # 4. 挖掘指纹身段
    print("[*] Mining Flow Skeletons...")
    miner = NoiseRobustMiner()
    final_fingerprints = {}

    # profiler.py 核心修改部分

    for rid, data in rule_data.items():
        all_samples = data["cmds"]
        # 获取切分后的指纹及其置ional
        cmd_fp, ent_fp, confidence = miner.mine_parts(all_samples)
        
        if cmd_fp or ent_fp:
            final_fingerprints[rid] = {
                "command_flow_fp": cmd_fp,
                "entity_flow_fp": ent_fp,
                "confidence": confidence, # <--- 关键指标
                "sample_count": len(all_samples),
                "is_unified_flow": True if not data["ents"] else False
            }
            print(f" [+] Rule {rid}: CmdLen={len(cmd_fp)}, EntLen={len(ent_fp)}, Conf={confidence:.1%}")

    # 5. 持久化
    with open(OUTPUT, 'w') as f:
        json.dump(final_fingerprints, f, indent=2)
    print(f"\n[✓] Done! {len(final_fingerprints)} fingerprints saved to {OUTPUT}")

if __name__ == "__main__":
    main()