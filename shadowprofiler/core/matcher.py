import json
import os
import numpy as np
from dtaidistance import dtw
from flow_generator import ForensicFlowGenerator

class FlowMatcher:
    def __init__(self, fingerprint_path, device_map_path):
        with open(fingerprint_path, 'r') as f:
            self.fingerprints = json.load(f)
        with open(device_map_path, 'r') as f:
            self.device_map = json.load(f)

    def match_flow_subseq(self, flow_signature, fingerprint, threshold, normalize=False):
        if len(flow_signature) < len(fingerprint):
            return False, float('inf')
        min_dist = float('inf')
        fp_len = len(fingerprint)
        for i in range(len(flow_signature) - fp_len + 1):
            subseq = flow_signature[i:i+fp_len]
            seq1 = np.array(subseq, dtype=float)
            seq2 = np.array(fingerprint, dtype=float)
            dist = dtw.distance(seq1, seq2)
            if normalize:
                dist /= fp_len
            if dist < min_dist:
                min_dist = dist
        return min_dist < threshold, min_dist

    def match_pcap(self, pcap_path, rule_id, target_entity,
                   cmd_threshold=50.0, ent_threshold=120.0,
                   force_unified=None, normalize=False, verbose=False):
        """
        force_unified: None 表示使用指纹库中的设置，True 强制统一流模式，False 强制分离流模式
        """
        target_ip = self.device_map.get(target_entity)
        if not target_ip:
            return {"error": f"Entity {target_entity} not found in device map"}

        gen = ForensicFlowGenerator(pcap_path)
        flows = gen.get_flows(target_ip)
        if not flows:
            return {"error": "No flows found in PCAP"}

        fp = self.fingerprints.get(rule_id)
        if not fp:
            return {"error": f"Rule {rule_id} not found in fingerprints"}

        cmd_fp = fp.get("command_flow_fp", [])
        ent_fp = fp.get("entity_flow_fp", [])
        # 决定使用哪种模式
        if force_unified is not None:
            unified = force_unified
        else:
            unified = fp.get("is_unified_flow", False)

        results = []
        min_ent_dist = float('inf')
        for f in flows:
            cmd_match, cmd_dist = self.match_flow_subseq(
                f.signature, cmd_fp, cmd_threshold, normalize
            )
            ent_match, ent_dist = False, float('inf')
            if ent_fp:
                ent_match, ent_dist = self.match_flow_subseq(
                    f.signature, ent_fp, ent_threshold, normalize
                )
                if ent_dist < min_ent_dist:
                    min_ent_dist = ent_dist

            # 对于统一流，整体匹配定义为同时匹配命令和实体
            if unified:
                overall = cmd_match and ent_match
            else:
                overall = cmd_match or ent_match

            flow_info = {
                "flow_start": f.start_ts,
                "initiator": f.initiator,
                "cmd_match": cmd_match,
                "cmd_distance": round(cmd_dist, 2),
                "ent_match": ent_match if ent_fp else None,
                "ent_distance": round(ent_dist, 2) if ent_fp else None,
                "overall_match": overall
            }
            if verbose:
                flow_info["flow_end"] = f.end_ts
                flow_info["signature"] = f.signature
            results.append(flow_info)

        # 构建精简的 identified_flows
        identified_flows = []
        for r in results:
            if r["cmd_match"] or (r.get("ent_match") and r["ent_match"] is not False):
                entry = {
                    "time": r["flow_start"],
                    "initiator": r["initiator"],
                }
                if r["cmd_match"]:
                    entry["cmd"] = True
                    entry["cmd_dist"] = r["cmd_distance"]
                if r.get("ent_match") and r["ent_match"] is not False:
                    entry["ent"] = True
                    entry["ent_dist"] = r["ent_distance"]
                identified_flows.append(entry)
        identified_flows.sort(key=lambda x: x["time"])

        # 判断成功状态
        if unified:
            # 统一流模式：需要至少一个流同时匹配命令和实体
            success = any(r["overall_match"] for r in results)
            if success:
                result_type = "success"
            elif any(r["cmd_match"] for r in results):
                result_type = "command_only"
            else:
                result_type = "no_match"
        else:
            # 分离流模式：需要存在命令匹配流和实体匹配流（可以不同）
            cmd_flows = [r for r in results if r["cmd_match"]]
            ent_flows = [r for r in results if r.get("ent_match")]
            if cmd_flows and ent_flows:
                success = True
                result_type = "success"
            elif cmd_flows:
                success = False
                result_type = "command_only"
            else:
                success = False
                result_type = "no_match"

        return {
            "success": success,
            "result_type": result_type,
            "rule_id": rule_id,
            "target_entity": target_entity,
            "target_ip": target_ip,
            "pcap": pcap_path,
            "identified_flows": identified_flows,
            "min_ent_distance": round(min_ent_dist, 2) if min_ent_dist != float('inf') else None,
            "flows": results if verbose else None,
            "details": f"Found {len(flows)} flows, min_ent_dist={min_ent_dist:.2f}, success={success}"
        }

    def batch_match(self, pcap_list, rule_id, target_entity,
                    cmd_threshold=50.0, ent_threshold=120.0,
                    force_unified=None, normalize=False, verbose=False):
        summary = {
            "total": len(pcap_list),
            "success": 0,
            "fail": 0,
            "command_only": 0,
            "no_match": 0,
            "details": []
        }
        for pcap in pcap_list:
            res = self.match_pcap(pcap, rule_id, target_entity,
                                   cmd_threshold, ent_threshold,
                                   force_unified, normalize, verbose)
            summary["details"].append(res)
            if res.get("success"):
                summary["success"] += 1
            else:
                summary["fail"] += 1
                if res.get("result_type") == "command_only":
                    summary["command_only"] += 1
                elif res.get("result_type") == "no_match":
                    summary["no_match"] += 1
        return summary


if __name__ == "__main__":
    FINGERPRINT_FILE = "../final_fingerprints.json"
    DEVICE_MAP_FILE = "../data/device_map.json"
    RULE_ID = "1770396219926"
    TARGET_ENTITY = "alarm_control_panel.lumi_mgl03_4e93_arming"

    matcher = FlowMatcher(FINGERPRINT_FILE, DEVICE_MAP_FILE)

    pcap_dir = "../data/pcap"
    pcap_files = [os.path.join(pcap_dir, f) for f in os.listdir(pcap_dir)
                  if f.endswith(".pcap") and RULE_ID in f]

    # 测试统一流模式（强制为 True）
    print("=== Testing UNIFIED flow mode (force_unified=True) ===")
    result_unified = matcher.batch_match(pcap_files, RULE_ID, TARGET_ENTITY,
                                         cmd_threshold=50.0, ent_threshold=120.0,
                                         force_unified=True, normalize=False, verbose=False)
    print(f"Total: {result_unified['total']}, Success: {result_unified['success']}, "
          f"Command Only: {result_unified['command_only']}, No Match: {result_unified['no_match']}")

    # 可以再测试分离流模式（指纹库默认，但 force_unified=False 强制分离）
    print("\n=== Testing SEPARATE flow mode (force_unified=False) ===")
    result_separate = matcher.batch_match(pcap_files, RULE_ID, TARGET_ENTITY,
                                          cmd_threshold=50.0, ent_threshold=120.0,
                                          force_unified=False, normalize=False, verbose=False)
    print(f"Total: {result_separate['total']}, Success: {result_separate['success']}, "
          f"Command Only: {result_separate['command_only']}, No Match: {result_separate['no_match']}")

    # 打印详细结果（可选）
    print("\nDetailed results for unified mode:")
    for i, res in enumerate(result_unified["details"][:5]):  # 只打印前5个样本，避免刷屏
        print(f"\nSample {i+1}: {res['pcap']} -> {res['result_type']} (min_ent_dist={res['min_ent_distance']})")
        for f in res["identified_flows"]:
            tags = []
            if f.get("cmd"): tags.append("CMD")
            if f.get("ent"): tags.append("ENT")
            print(f"  time={f['time']:.3f} initiator={f['initiator']} type={','.join(tags)} "
                  f"dist_cmd={f.get('cmd_dist')} dist_ent={f.get('ent_dist')}")