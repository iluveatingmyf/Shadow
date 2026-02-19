import json
import os
import statistics
import numpy as np
from .flow_generator import ForensicFlowGenerator

class AssociativeEngine:
    def __init__(self, pcap_root, device_map_path):
        self.pcap_root = pcap_root
        with open(device_map_path, 'r') as f:
            self.device_map = json.load(f)
        self.ha_to_local_offset = 0.0
        self.router_to_local_offset = 0.0
        self.calibrated = False

    def calibrate_ha_offset(self, traces):
        """从日志中计算 HA 时间与本地时间的固定偏移。"""
        print("[*] Calibrating HA -> Local offset...")
        diffs = []
        for t in traces[:10]:
            event = t['app_events']['automation_triggered']
            ha_ts = event['ha_fired_at']
            local_ts = event['timestamp']
            diffs.append(local_ts - ha_ts)
        if diffs:
            self.ha_to_local_offset = statistics.median(diffs)
            print(f"[✓] HA->Local offset: {self.ha_to_local_offset:.3f}s")
        else:
            self.ha_to_local_offset = 0.0
            print("[!] No valid HA events, offset set to 0.")

    def auto_search_router_offset(self, traces, offset_range=(-20, 20), step=0.5, progress_interval=10):
        """
        自动搜索最优路由器偏移，使得成功提取命令流的样本数最多。
        offset_range: 搜索范围（秒）
        step: 步长（秒）
        progress_interval: 每多少个候选值打印一次进度
        """
        print(f"[*] Auto-searching router offset in range {offset_range} with step {step}s...")
        best_offset = 0.0
        best_count = -1
        candidate_offsets = np.arange(offset_range[0], offset_range[1] + step, step)
        total_samples = len(traces)
        total_candidates = len(candidate_offsets)

        for idx, offset in enumerate(candidate_offsets):
            # 进度显示
            if idx % progress_interval == 0:
                print(f"   Progress: {idx}/{total_candidates} offsets tested...")
            
            success_count = 0
            for t in traces:
                try:
                    dual = self._get_dual_flows_with_offset(t, test_offset=offset)
                    if dual and dual.get("cmd"):
                        success_count += 1
                except Exception as e:
                    # 捕获异常，避免单个样本导致搜索中断
                    print(f"      Warning: sample {t.get('sample_idx')} failed with offset {offset:.2f}: {e}")
                    continue
            if success_count > best_count:
                best_count = success_count
                best_offset = offset

        self.router_to_local_offset = best_offset
        print(f"[✓] Auto-selected router offset: {best_offset:.2f}s (achieved {best_count}/{total_samples} success)")
        self.calibrated = True


    def set_router_offset(self, offset):
        """手动设置路由器偏移"""
        self.router_to_local_offset = offset
        print(f"[✓] Router offset set to {offset:.3f}s")
        self.calibrated = True

    def _get_dual_flows_with_offset(self, trace, test_offset=None):
        """
        内部方法，使用给定的 test_offset 提取流（不修改实例属性）。
        如果 test_offset 为 None，则使用实例的 router_to_local_offset。
        """
        target_ip = self.device_map.get(trace['metadata']['target_entity'])
        if not target_ip:
            return None

        # 本地触发时间
        ha_ts = trace['app_events']['automation_triggered']['ha_fired_at']
        local_trigger = ha_ts + self.ha_to_local_offset

        pcap_path = os.path.join(self.pcap_root, f"{trace['pcap_file']}_br-lan.pcap")
        if not os.path.exists(pcap_path):
            return None

        gen = ForensicFlowGenerator(pcap_path)
        all_flows = gen.get_flows(target_ip)

        # 决定使用的偏移
        offset = test_offset if test_offset is not None else self.router_to_local_offset

        # 转换流起始时间到本地，并筛选窗口
        win_start = local_trigger - 1.0
        win_end = local_trigger + 15.0
        candidate_flows = []
        for f in all_flows:
            f_local_start = f.start_ts - offset
            if win_start <= f_local_start <= win_end:
                f.local_start = f_local_start
                candidate_flows.append(f)

        if not candidate_flows:
            return None

        # 命令流：HA发起，取最早
        cmd_candidates = [f for f in candidate_flows if f.initiator != target_ip]
        if not cmd_candidates:
            return None
        cmd_candidates.sort(key=lambda f: f.local_start)
        best_cmd_flow = cmd_candidates[0]

        # 实体流：设备发起，不早于命令流
        ent_candidates = [f for f in candidate_flows 
                          if f.initiator == target_ip 
                          and f.local_start >= best_cmd_flow.local_start]
        ent_candidates.sort(key=lambda f: f.local_start)

        res = {"cmd": best_cmd_flow.signature, "ent": None}
        if ent_candidates:
            res["ent"] = ent_candidates[0].signature

        return res

    def get_dual_flows(self, trace):
        """对外接口，使用实例的 router_offset"""
        if not self.calibrated:
            raise RuntimeError("Router offset not calibrated. Call auto_search_router_offset() or set_router_offset() first.")
        return self._get_dual_flows_with_offset(trace, test_offset=None)