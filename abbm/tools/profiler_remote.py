import asyncio
import json
import statistics
import time
import os
import requests
import websockets
import subprocess
import sys
from datetime import datetime
import re

# --- 动态路径修复 ---
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(current_dir)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from core.translator import SemanticTranslator

# ================= 配置区 =================
HA_URL_HTTP = "http://192.168.0.157:8123"
HA_URL_WS = "ws://192.168.0.157:8123/api/websocket"
TOKEN_FILE = "/Users/myf/shadowprov/token.txt"

ROUTER_ALIAS = "mi" 
REMOTE_SCRIPT = "/data/capture_abbm.sh"
REMOTE_PCAP_DIR = "/extdisks/sda1/pcap" 
LOCAL_PCAP_DIR = "/Users/myf/smartprov/pcap"
PCAP_FILES_SUFFIX = ["_br-lan.pcap", "_wl1.pcap"]

# ================= 辅助工具 =================
def enrich_timestamps(ts):
    if ts is None: return "N/A"
    return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

class ExperimentLogger:
    def __init__(self, log_file="experiment.log"):
        self.terminal = sys.stdout
        self.log_file = open(os.path.join(current_dir, log_file), "a", encoding="utf-8")
        self.success_list = []

    def write(self, message):
        self.terminal.write(message)
        self.log_file.write(message)
        self.log_file.flush()

    def flush(self):
        self.terminal.flush()
        self.log_file.flush()

    def add_success(self, rid, sample_idx, pcap_tag):
        self.success_list.append({
            "rule": rid,
            "sample": sample_idx,
            "pcap": pcap_tag,
            "time": datetime.now().strftime("%H:%M:%S")
        })

    def generate_final_report(self):
        print("\n" + "="*50)
        print("📊 FINAL EXECUTABLE LOG REPORT")
        print("="*50)
        if not self.success_list:
            print("❌ No successful execution traces found.")
        else:
            print(f"✅ Total Successful Traces: {len(self.success_list)}")
            print(f"{'RULE_ID':<25} | {'SAMPLE':<8} | {'PCAP_TAG'}")
            for item in self.success_list:
                print(f"{item['rule']:<25} | {item['sample']:<8} | {item['pcap']}")
        print("="*50 + "\n")

exp_logger = ExperimentLogger()
sys.stdout = exp_logger

def save_app_trace(record, filename="experiment_traces.jsonl"):
    abs_path = os.path.join(current_dir, filename) 
    try:
        with open(abs_path, 'a', encoding='utf-8') as f:
            line = json.dumps(record, ensure_ascii=False)
            f.write(line + '\n')
            f.flush()
    except Exception as e:
        log(f"CRITICAL: Failed to write JSONL: {e}", "ERR")

def log(msg, level="INFO"):
    timestamp = datetime.now().strftime("%H:%M:%S")
    color = {"INFO": "\033[94m", "SUCCESS": "\033[92m", "WARN": "\033[93m", "ERR": "\033[91m"}.get(level, "")
    print(f"{timestamp} [{color}{level}\033[0m] {msg}")

def load_token(path):
    with open(path, 'r') as f: return f.read().strip()

HA_TOKEN = load_token(TOKEN_FILE)
HEADERS = {"Authorization": f"Bearer {HA_TOKEN}", "content-type": "application/json"}

# ================= 1. 环境致动逻辑 =================
def ensure_physical_state(entity, target_state, timeout=80):
    if isinstance(entity, list): entity = entity[0]
    if target_state == "unknown": return True

    domain = entity.split('.')[0]
    actuator_map = {
        "light": {"on": "turn_on", "off": "turn_off"},
        "switch": {"on": "turn_on", "off": "turn_off"},
        "alarm_control_panel": {"armed_away": "alarm_arm_away", "armed_home": "alarm_arm_home", 
                                "armed_night": "alarm_arm_night", "disarmed": "alarm_disarm"},
        "input_boolean": {"on": "turn_on", "off": "turn_off"}
    }

    start_wait = time.time()
    while time.time() - start_wait < timeout:
        service = actuator_map.get(domain, {}).get(target_state)
        if service:
            requests.post(f"{HA_URL_HTTP}/api/services/{domain}/{service}", 
                          headers=HEADERS, json={"entity_id": entity})
        else:
            requests.post(f"{HA_URL_HTTP}/api/states/{entity}", 
                          headers=HEADERS, json={"state": target_state})
        
        time.sleep(1.5)
        current = requests.get(f"{HA_URL_HTTP}/api/states/{entity}", headers=HEADERS).json().get('state')
        if current == target_state:
            log(f"Verified: {entity} is now {target_state}", "SUCCESS")
            return True
    return False

def toggle_automations(enable=True):
    service = "turn_on" if enable else "turn_off"
    try:
        r = requests.get(f"{HA_URL_HTTP}/api/states", headers=HEADERS, timeout=5)
        autos = [s['entity_id'] for s in r.json() if s['entity_id'].startswith("automation.")]
        for auto_id in autos:
            requests.post(f"{HA_URL_HTTP}/api/services/automation/{service}", headers=HEADERS, json={"entity_id": auto_id})
    except: pass

# ================= 2. WebSocket 追踪逻辑 (多 Action 增强版) =================
async def monitor_event_bus(rid, auto_id, action_list, timeout=40.0):
    trace_map = {}
    for act in action_list:
        entities = act['entity'] if isinstance(act['entity'], list) else [act['entity']]
        target_state = SemanticTranslator.to_physical_state(act.get('service'))
        for ent in entities:
            trace_map[ent] = {
                "entity": ent,
                "target_state": target_state,
                "service_called": {"timestamp": None, "ha_fired_at": None, "service": act.get('service')},
                "state_reached": {"timestamp": None, "ha_fired_at": None},
                "success": False
            }

    results = {
        "automation_triggered": {"timestamp": None, "ha_fired_at": None},
        "device_traces": trace_map
    }

    async with websockets.connect(HA_URL_WS) as websocket:
        await websocket.send(json.dumps({"type": "auth", "access_token": HA_TOKEN}))
        await websocket.recv()
        await websocket.send(json.dumps({"id": 1, "type": "subscribe_events"}))
        await websocket.recv()

        start_t = time.time()
        while time.time() - start_t < timeout:
            if all(v["success"] for v in trace_map.values()): break
            try:
                msg = await asyncio.wait_for(websocket.recv(), timeout=0.1)
                data = json.loads(msg)
                if data.get("type") != "event": continue
                
                event = data["event"]
                etype = event["event_type"]
                edata = event["data"]
                ha_ts = datetime.fromisoformat(event.get("time_fired").replace('Z', '+00:00')).timestamp()

                if etype == "automation_triggered" and edata.get("entity_id") == auto_id:
                    results["automation_triggered"].update({"timestamp": time.time(), "ha_fired_at": ha_ts})

                if etype == "call_service":
                    target_e = edata.get("service_data", {}).get("entity_id", [])
                    if isinstance(target_e, str): target_e = [target_e]
                    for ent in target_e:
                        if ent in trace_map:
                            trace_map[ent]["service_called"].update({"timestamp": time.time(), "ha_fired_at": ha_ts})

                if etype == "state_changed":
                    ent = edata["entity_id"]
                    if ent in trace_map:
                        new_s = edata["new_state"]["state"]
                        if new_s == trace_map[ent]["target_state"]:
                            trace_map[ent]["state_reached"].update({"timestamp": time.time(), "ha_fired_at": ha_ts})
                            trace_map[ent]["success"] = True
                            log(f"Captured: {ent} reached {new_s}", "SUCCESS")
            except asyncio.TimeoutError: continue
    return results

# ================= 3. SSH 与主流程 =================

def run_remote_capture(rule_id, sample_idx):
    session_tag = f"R{rule_id.split('_')[-1]}_s{sample_idx}"
    log(f"SSH: Starting capture (Session: {session_tag})")
    proc = subprocess.Popen(["ssh", "-tt", ROUTER_ALIAS, f"sh {REMOTE_SCRIPT} {session_tag}"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=0)
    start_wait = time.time()
    while True:
        line = proc.stdout.readline()
        if "Capturing" in line: return proc, session_tag
        if time.time() - start_wait > 10: 
            proc.terminate()
            raise Exception("Router Start Timeout")

def stop_remote_capture_and_pull(proc, session_tag):
    if not proc: return
    log(f"SSH: Stopping session {session_tag}...")
    try:
        proc.stdin.write("\n")
        proc.stdin.flush()
        time.sleep(2)
        for suffix in PCAP_FILES_SUFFIX:
            filename = f"{session_tag}{suffix}"
            remote_path = f"{REMOTE_PCAP_DIR}/{filename}"
            local_path = os.path.join(LOCAL_PCAP_DIR, filename)
            scp_cmd = ["scp", "-O", f"{ROUTER_ALIAS}:{remote_path}", local_path]
            if subprocess.run(scp_cmd, capture_output=True).returncode == 0:
                subprocess.run(["ssh", ROUTER_ALIAS, f"rm {remote_path}"])
    except Exception as e: log(f"Stop/Pull Error: {e}", "ERR")
    finally: proc.terminate()

def run_abbm_profiling(logic_graph_path, sample_cnt=10):
    r_autos = requests.get(f"{HA_URL_HTTP}/api/states", headers=HEADERS, timeout=5)
    real_ha_autos = [s['entity_id'] for s in r_autos.json() if s['entity_id'].startswith("automation.")]

    if not os.path.exists(logic_graph_path): return
    with open(logic_graph_path, 'r') as f: rules = json.load(f)
    if not os.path.exists(LOCAL_PCAP_DIR): os.makedirs(LOCAL_PCAP_DIR)
    
    log(">>> PHASE 1: Environment Isolation", "INFO")
    toggle_automations(enable=False)

    try:
        SKIPPED_RULES = ["1770396219926"]
        for rid, rule in rules.items():
            if rid in SKIPPED_RULES:
                continue
            alias = rule.get('alias', '')
            auto_id = f"automation.{alias.lower().replace(' ', '_').replace('-', '_').replace(':', '_')}"
            auto_id = re.sub(r'_+', '_', auto_id).strip('_')
            if auto_id not in real_ha_autos: auto_id = rid

            log(f"\nPROFILING: {alias} ({auto_id}) " + "="*20)
            requests.post(f"{HA_URL_HTTP}/api/services/automation/turn_on", headers=HEADERS, json={"entity_id": auto_id})
            time.sleep(2)

            trigger = rule['triggers'][0]
            trigger_entities = trigger['entity'] if isinstance(trigger['entity'], list) else [trigger['entity']]

            for i in range(sample_cnt):
                log(f"--- Sample {i+1}/{sample_cnt} ---")
                # 初始化环境
                for act in rule['actions']:
                    t_ents = act['entity'] if isinstance(act['entity'], list) else [act['entity']]
                    rev = SemanticTranslator.get_reverse_state(SemanticTranslator.to_physical_state(act.get('service')))
                    for ent in t_ents: ensure_physical_state(ent, rev)
                for ent in trigger_entities: ensure_physical_state(ent, SemanticTranslator.get_reverse_state(trigger['state']))
                for cond in rule['conditions']: ensure_physical_state(cond['entity'], cond['state'])
                
                time.sleep(5)
                proc, session_tag = run_remote_capture(rid, i+1)

                async def task():
                    listener = asyncio.create_task(monitor_event_bus(rid, auto_id, rule['actions']))
                    await asyncio.sleep(2) 
                    t0 = time.time()
                    ensure_physical_state(trigger_entities[0], trigger['state'])
                    return t0, await listener

                t_start, app_events = asyncio.run(task())
                time.sleep(5)
                stop_remote_capture_and_pull(proc, session_tag)

                # 构建详细记录
                experiment_record = {
                    "rule_id": rid,
                    "sample_idx": i + 1,
                    "pcap_file": session_tag,
                    "trigger_info": {
                        "inject_time": t_start,
                        "entity": trigger_entities[0],
                        "state": trigger['state']
                    },
                    "app_events": {
                        "ha_automation_triggered": app_events["automation_triggered"],
                        "device_details": list(app_events["device_traces"].values())
                    }
                }

                # 判定：是否有任何 Action 成功
                success_count = sum(1 for d in app_events["device_traces"].values() if d["success"])
                if success_count > 0:
                    log(f"Trace Successful: {success_count} actions captured", "SUCCESS")
                    exp_logger.add_success(rid, i + 1, session_tag)
                else:
                    log("Trace Incomplete", "WARN")

                save_app_trace(experiment_record)

    finally:
        log(">>> PHASE 3: Restoring Environment", "INFO")
        toggle_automations(enable=True)
        exp_logger.generate_final_report()

if __name__ == "__main__":
    run_abbm_profiling("../data/logic_graph.json", sample_cnt=20)