import requests
import time
import random
import json
import os

# ================= 配置区 =================
HA_URL = "http://192.168.0.157:8123"
TOKEN_FILE = "../../token.txt"

# 实体映射 (严格对应 ID 1-11)
DEVICE_GATEWAY = "alarm_control_panel.lumi_mgl03_4e93_arming" # (3)
DEVICE_BED_LIGHT = "light.yeelink_bslamp1_b745_light"       # (5)
DEVICE_FLOOR_LIGHT = "light.lumi_v3_6063_light"             # (4)
DEVICE_CAMERA_SWITCH = "switch.chuangmi_ipc009_b918_switch_status" # (6)
DEVICE_COFFEE_PLUG = "switch.cuco_v3_6df1_switch"           # (9) - 原脚本名为NIGHT_LIGHT
DEVICE_TOILET_LIGHT = "switch.cuco_v3_d474_switch"          # (8) - 原脚本名为TOILET_PLUG

def load_token(file_path):
    """从外部文件读取 Token"""
    try:
        # 处理相对路径
        abs_path = os.path.join(os.path.dirname(__file__), file_path)
        with open(abs_path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception as e:
        print(f"[ERROR] 无法加载 Token: {e}")
        exit(1)

# 初始化 HEADERS
HEADERS = {
    "Authorization": f"Bearer {load_token(TOKEN_FILE)}",
    "content-type": "application/json",
}

def physical_control(domain, service, entity_id, data={}):
    url = f"{HA_URL}/api/services/{domain}/{service}"
    payload = {"entity_id": entity_id}
    payload.update(data)
    try:
        r = requests.post(url, headers=HEADERS, json=payload, timeout=10)
        print(f"[ACTUATION] {domain}.{service} -> {entity_id} | Code: {r.status_code}")
        time.sleep(1.0) # 物理致动建议留 1 秒等待信号在网关排队
    except Exception as e:
        print(f"[ERROR] Connection failed: {e}")

def randomize_device(entity_id, device_type="switch"):
    """生成背景噪声流量"""
    action = random.choice(["turn_on", "turn_off"])
    print(f"[NOISE] Randomizing {entity_id} -> {action}")
    physical_control(device_type, action, entity_id)

# ================= 场景初始化逻辑 =================

def init_s1_morning():
    """S1: 模拟清晨状态"""
    print("\n>>> Resetting for S1: Morning Rush")
    # 关键：设为夜间模式，保证人在家
    physical_control("alarm_control_panel", "alarm_arm_night", DEVICE_GATEWAY)
    # 关键：所有灯和插座关闭，等待唤醒规则和手动触发
    physical_control("light", "turn_off", DEVICE_BED_LIGHT)
    physical_control("light", "turn_off", DEVICE_FLOOR_LIGHT) # 确保R12是从关到开
    physical_control("switch", "turn_off", DEVICE_COFFEE_PLUG)
    physical_control("switch", "turn_off", DEVICE_TOILET_LIGHT)
    # 噪声
    randomize_device(DEVICE_CAMERA_SWITCH, "switch")

def init_s2_evening():
    """S2: 模拟离家待归状态"""
    print("\n>>> Resetting for S2: Evening Return")
    # 关键：设为离家模式
    physical_control("alarm_control_panel", "alarm_arm_away", DEVICE_GATEWAY)
    # 关键：摄像头必须打开，用来测试回家的隐私保护规则R6
    physical_control("switch", "turn_on", DEVICE_CAMERA_SWITCH)
    # 关键：所有灯光关闭，等待欢迎灯规则R4
    physical_control("light", "turn_off", DEVICE_FLOOR_LIGHT)
    physical_control("light", "turn_off", DEVICE_BED_LIGHT)
    # 噪声
    randomize_device(DEVICE_COFFEE_PLUG, "switch")

def init_s3_intrusion():
    """S3: 模拟深夜无人状态"""
    print("\n>>> Resetting for S3: Intrusion Watch")
    # 关键：设为离家模式
    physical_control("alarm_control_panel", "alarm_arm_away", DEVICE_GATEWAY)
    # 关键：摄像头开启备战
    physical_control("switch", "turn_on", DEVICE_CAMERA_SWITCH)
    # 关键：灯光全灭，等待补光联动规则R7
    physical_control("light", "turn_off", DEVICE_BED_LIGHT)
    physical_control("light", "turn_off", DEVICE_FLOOR_LIGHT)
    # 噪声
    randomize_device(DEVICE_TOILET_LIGHT, "switch")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python physical_init.py [s1|s2|s3]")
    else:
        cmd = sys.argv[1].lower()
        if cmd == "s1": init_s1_morning()
        elif cmd == "s2": init_s2_evening()
        elif cmd == "s3": init_s3_intrusion()