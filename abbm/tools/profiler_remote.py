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
from scapy.all import rdpcap, IP
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

# 路由器 SSH 别名 (必须在 ~/.ssh/config 中定义)
ROUTER_ALIAS = "mi" 
REMOTE_SCRIPT = "/data/capture_abbm.sh"
REMOTE_PCAP_DIR = "/extdisks/sda1/pcap" 
LOCAL_PCAP_DIR = "/Users/myf/smartprov/pcap"
PCAP_FILES_SUFFIX = ["_br-lan.pcap", "_wl1.pcap"]

# ================= 辅助工具 =================
def enrich_timestamps(ts):
    return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

def slugify(text):
    # 模拟 HA 的内部 slugify 逻辑
    text = text.lower()
    text = re.sub(r'[^a-z0-9_]', '_', text) # 非字母数字全变下划线
    text = re.sub(r'_+', '_', text)         # 连续下划线变一个
    return text.strip('_')

# --- 在 save_app_trace 之前添加 ---

class ExperimentLogger:
    def __init__(self, log_file="experiment.log"):
        self.terminal = sys.stdout
        self.log_file = open(os.path.join(current_dir, log_file), "a", encoding="utf-8")
        self.success_list = [] # 用于存放成功的记录摘要

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
        print("\n" + "="*30)
        print("📊 FINAL EXECUTABLE LOG REPORT")
        print("="*30)
        if not self.success_list:
            print("❌ No successful execution traces found.")
        else:
            print(f"✅ Total Successful Traces: {len(self.success_list)}")
            print(f"{'RULE_ID':<20} | {'SAMPLE':<8} | {'PCAP_TAG'}")
            for item in self.success_list:
                print(f"{item['rule']:<20} | {item['sample']:<8} | {item['pcap']}")
        print("="*30 + "\n")

# 初始化全局 Logger
exp_logger = ExperimentLogger()
sys.stdout = exp_logger # 重定向所有 print 和 log 函数的输出



def save_app_trace(record, filename="experiment_traces.jsonl"):
    abs_path = os.path.join(current_dir, filename) 
    try:
        with open(abs_path, 'a', encoding='utf-8') as f:
            line = json.dumps(record, ensure_ascii=False)
            f.write(line + '\n')
            f.flush()
            os.fsync(f.fileno())
        log(f"File written to: {abs_path}", "SUCCESS") # 增加一行确认日志
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

def ensure_physical_state(entity, target_state, timeout=10):
    """
    强制确保状态到达，并循环检查直到 HA 确认
    """
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
        # 1. 尝试执行
        service = actuator_map.get(domain, {}).get(target_state)
        if service:
            requests.post(f"{HA_URL_HTTP}/api/services/{domain}/{service}", 
                          headers=HEADERS, json={"entity_id": entity})
        else:
            # 传感器类直接注入
            requests.post(f"{HA_URL_HTTP}/api/states/{entity}", 
                          headers=HEADERS, json={"state": target_state})
        
        time.sleep(1.5) # 给物理设备反应时间
        
        # 2. 检查是否成功
        current = requests.get(f"{HA_URL_HTTP}/api/states/{entity}", headers=HEADERS).json().get('state')
        if current == target_state:
            log(f"Verified: {entity} is now {target_state}", "SUCCESS")
            return True
            
    log(f"Failed to force {entity} to {target_state}", "ERR")
    return False

def toggle_automations(enable=True):
    service = "turn_on" if enable else "turn_off"
    try:
        r = requests.get(f"{HA_URL_HTTP}/api/states", headers=HEADERS, timeout=5)
        autos = [s['entity_id'] for s in r.json() if s['entity_id'].startswith("automation.")]
        for auto_id in autos:
            requests.post(f"{HA_URL_HTTP}/api/services/automation/{service}", headers=HEADERS, json={"entity_id": auto_id})
    except: pass

# ================= 2. WebSocket 追踪逻辑 (已优化) =================
async def monitor_event_bus(rid, auto_id, target_entity, expected_state, timeout=80.0):
    events = {
        "automation_triggered": {"timestamp": None, "ha_fired_at": None, "entity_id": auto_id},
        "service_call": {"timestamp": None, "ha_fired_at": None, "entity_id": None, "service": None},
        "state_changed": {"timestamp": None, "ha_fired_at": None, "entity_id": target_entity, "new_state": expected_state}
    }
    
    async with websockets.connect(HA_URL_WS) as websocket:
        await websocket.send(json.dumps({"type": "auth", "access_token": HA_TOKEN}))
        await websocket.recv()
        await websocket.send(json.dumps({"id": 1, "type": "subscribe_events"}))
        await websocket.recv()

        start_t = time.time()
        while time.time() - start_t < timeout:
            try:
                msg = await asyncio.wait_for(websocket.recv(), timeout=0.1)
                data = json.loads(msg)
                
                if data.get("type") == "event":
                    event = data["event"]
                    etype = event["event_type"]
                    edata = event["data"]
                    
                    # 关键点：提取 HA 官方的事件触发时间 (ISO 格式)
                    # 例如: "2026-02-17T15:20:00.123456+00:00"
                    ha_time_str = event.get("time_fired")
                    ha_ts = None
                    if ha_time_str:
                        # 将 ISO 字符串转为 Unix 时间戳，方便后续做减法计算
                        dt = datetime.fromisoformat(ha_time_str.replace('Z', '+00:00'))
                        ha_ts = dt.timestamp()

                    # 1. 捕捉状态变化
                    if etype == "state_changed" and edata["entity_id"] == target_entity:
                        actual_s = edata["new_state"]["state"]
                        if actual_s == expected_state:
                            events["state_changed"]["timestamp"] = time.time() # 脚本收到时间
                            events["state_changed"]["ha_fired_at"] = ha_ts     # HA 核心记录时间
                            log(f"Captured: State Changed (HA internal delay: {events['state_changed']['timestamp'] - ha_ts:.4f}s)", "SUCCESS")
                            return events

                    # 2. 捕捉服务调用
                    if etype == "call_service" and target_entity in str(edata.get("service_data", {})):
                         events["service_call"]["timestamp"] = time.time()
                         events["service_call"]["ha_fired_at"] = ha_ts
                         log(f"Captured: Call Service", "SUCCESS")
                         
                    # 3. 捕捉自动化触发
                    if etype == "automation_triggered" and edata.get("entity_id") == auto_id:
                        events["automation_triggered"]["timestamp"] = time.time()
                        events["automation_triggered"]["ha_fired_at"] = ha_ts
                        log(f"Captured: Automation Triggered", "SUCCESS")

            except asyncio.TimeoutError:
                continue 
    return events

# ================= 3. SSH 控制与系统 SCP 拉取 =================

def run_remote_capture(rule_id, sample_idx):
    session_tag = f"R{rule_id.split('_')[-1]}_s{sample_idx}"
    log(f"SSH: Starting capture (Session: {session_tag})")
    # 使用系统 ssh 命令和别名
    proc = subprocess.Popen(
        ["ssh", "-tt", ROUTER_ALIAS, f"sh {REMOTE_SCRIPT} {session_tag}"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=0
    )
    start_wait = time.time()
    while True:
        line = proc.stdout.readline()
        if "Capturing" in line:
            log("SSH: Router is capturing.", "SUCCESS")
            return proc, session_tag
        if time.time() - start_wait > 10: 
            proc.terminate()
            raise Exception("Router Start Timeout")

def stop_remote_capture_and_pull(proc, session_tag):
    if not proc: return
    log(f"SSH: Stopping session {session_tag}...")
    try:
        # 1. 停止路由器抓包
        proc.stdin.write("\n")
        proc.stdin.flush()
        time.sleep(2) # 等待文件落盘
        
        # 2. 使用系统 SCP 命令拉取文件 (绕过 Paramiko 认证坑)
        log("SCP: Pulling files from router...")
        for suffix in PCAP_FILES_SUFFIX:
            filename = f"{session_tag}{suffix}"
            remote_path = f"{REMOTE_PCAP_DIR}/{filename}"
            local_path = os.path.join(LOCAL_PCAP_DIR, filename)
            
            # 执行命令: scp mi:/path/file /local/path
            scp_cmd = ["scp", "-O", f"{ROUTER_ALIAS}:{remote_path}", local_path]
            scp_res = subprocess.run(scp_cmd, capture_output=True, text=True)
            
            if scp_res.returncode == 0:
                log(f"SCP: Pulled {filename}", "SUCCESS")
                # 3. 顺便删除远程文件以防磁盘满
                subprocess.run(["ssh", ROUTER_ALIAS, f"rm {remote_path}"])
            else:
                log(f"SCP Error for {filename}: {scp_res.stderr}", "WARN")
                
    except Exception as e: log(f"Stop/Pull Error: {e}", "ERR")
    finally: proc.terminate()

# ================= 4. 主流程 (已简化记录逻辑) =================

def run_abbm_profiling(logic_graph_path, sample_cnt=10):
    
    r_autos = requests.get(f"{HA_URL_HTTP}/api/states", headers=HEADERS, timeout=5)
    real_ha_autos = [s['entity_id'] for s in r_autos.json() if s['entity_id'].startswith("automation.")]

    if not os.path.exists(logic_graph_path): return
    with open(logic_graph_path, 'r') as f: rules = json.load(f)
    if not os.path.exists(LOCAL_PCAP_DIR): os.makedirs(LOCAL_PCAP_DIR)
    
    log(">>> PHASE 1: Environment Isolation", "INFO")
    toggle_automations(enable=False)

    try:
        for rid, rule in rules.items():
            alias = rule.get('alias', '')
            # 尝试匹配
            possible_id = f"automation.{alias.lower().replace(' ', '_').replace('-', '_').replace(':', '_')}"
            possible_id = re.sub(r'_+', '_', possible_id)
            
            if possible_id in real_ha_autos:
                auto_id = possible_id
            else:
                # 如果没找到，打印出来帮你自己纠错
                log(f"Mapping Fail! Expected {possible_id}, but not found in HA.", "WARN")
                log(f"Available automations in HA: {real_ha_autos[:5]}...", "INFO")
                auto_id = rid # 降级使用规则 ID

            log(f"\nPROFILING: {alias} ({auto_id}) " + "="*20)
            log(f"Activating target automation: {auto_id}")
            resp = requests.post(f"{HA_URL_HTTP}/api/services/automation/turn_on", 
                                 headers=HEADERS, json={"entity_id": auto_id})
            
            # 2. 增加验证：检查该自动化是否真的变成了 'on'
            time.sleep(5) # 给 HA 一点反应时间
            check_r = requests.get(f"{HA_URL_HTTP}/api/states/{auto_id}", headers=HEADERS)
            if check_r.status_code == 200:
                current_status = check_r.json().get('state')
                if current_status == 'on':
                    log(f"Verified: {auto_id} is ACTIVE.", "SUCCESS")
                else:
                    log(f"CRITICAL: {auto_id} is still {current_status}! The test will fail.", "ERR")
            else:
                log(f"CRITICAL: Could not find automation {auto_id} in HA!", "ERR")


            trigger = rule['triggers'][0]
            action = rule['actions'][0]
            target_phys_state = SemanticTranslator.to_physical_state(action.get('service'))

            for i in range(sample_cnt):
                log(f"--- Sample {i+1}/{sample_cnt} ---")
                
                # 初始化设备状态
                rev_state = SemanticTranslator.get_reverse_state(target_phys_state)
                ensure_physical_state(action['entity'], rev_state)
                trigger_entity = trigger['entity'] if not isinstance(trigger['entity'], list) else trigger['entity'][0]
                ensure_physical_state(trigger_entity, SemanticTranslator.get_reverse_state(trigger['state']))
                for cond in rule['conditions']: ensure_physical_state(cond['entity'], cond['state'])
                
                log("Waiting 5s for network silence...")
                time.sleep(5)

                # 抓包启动
                proc, session_tag = run_remote_capture(rid, i+1)

                async def task():
                    listener = asyncio.create_task(monitor_event_bus(rid, auto_id, action['entity'], target_phys_state))
                    await asyncio.sleep(2) 
                    t_0_inject = time.time() # 记录脚本触发时刻
                    ensure_physical_state(trigger_entity, trigger['state'])
                    captured_events = await listener
                    return t_0_inject, captured_events

                t_start, app_events = asyncio.run(task())
                
                log("Post-action cooling: waiting 30s...")
                time.sleep(10) 

                # 停止抓包并拉取文件
                stop_remote_capture_and_pull(proc, session_tag)

                # 构建实验记录 (记录原始条目，不进行任何减法计算)
                experiment_record = {
                    "rule_id": rid,
                    "sample_idx": i + 1,
                    "pcap_file": session_tag,
                    "trigger_action": {
                        "timestamp": t_start,
                        "readable": enrich_timestamps(t_start),
                        "entity": trigger_entity,
                        "to_state": trigger['state']
                    },
                    "app_events": app_events,
                    "metadata": {
                        "target_entity": action['entity'],
                        "expected_final_state": target_phys_state,
                        "readable_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                }

                # 简单判定：只要拿到了状态改变的时间戳，就算采集成功
                if app_events["state_changed"]["timestamp"]:
                    log(f"Trace Complete: {action['entity']} reached {target_phys_state}", "SUCCESS")
                    exp_logger.add_success(rid, i + 1, session_tag)
                else:
                    log(f"Trace Incomplete: Missing final state change", "WARN")

                print(f"\n[DEBUG DATA] {json.dumps(experiment_record)[:100]}...") # 打印前100字符确认
                save_app_trace(experiment_record)

    finally:
        log(">>> PHASE 3: Restoring Environment", "INFO")
        toggle_automations(enable=True)
        exp_logger.generate_final_report()



if __name__ == "__main__":
    run_abbm_profiling("../data/logic_graph.json", sample_cnt=20)