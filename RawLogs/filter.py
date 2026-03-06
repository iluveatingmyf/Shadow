import json

def filter_and_save_logs(input_file, output_file, allowed_entities):
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        filtered_data = []
        # 用于去重的缓存：记录 (context_id, device, command)
        seen_commands = set()

        for event in data:
            event_type = event.get("event_type")
            eid = event.get("event_ID")
            
            # --- 优化逻辑: Command 去重 ---
            if event_type == "Command":
                # 创建一个基于业务特征的唯一标识
                # 注意：我们保留 context_id 确保不同自动化触发的同名指令不被合并
                cmd_sig = (
                    event.get("context_id"),
                    event.get("raw_device_id") or event.get("device"),
                    event.get("command")
                )
                
                if cmd_sig in seen_commands:
                    # 如果该上下文已经记录过同样的指令，则跳过
                    print(f"过滤重复指令: Event {eid} ({event.get('command')})")
                    continue
                
                seen_commands.add(cmd_sig)
                filtered_data.append(event)
            
            # 逻辑 A: Agent 类型，无条件保留（因为 Agent 记录了 Condition 判断，很重要）
            elif event_type == "Agent":
                filtered_data.append(event)
            
            # 逻辑 B: Entity 类型，白名单检查
            elif event_type == "Entity":
                if event.get("entity_id") in allowed_entities:
                    filtered_data.append(event)

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(filtered_data, f, indent=4, ensure_ascii=False)
            
        print(f"成功！过滤后条数: {len(filtered_data)} (原始: {len(data)})")

    except Exception as e:
        print(f"处理失败: {e}")

# --- 配置部分保持不变 ---
ent_list = [
    'alarm_control_panel.lumi_mgl03_4e93_arming', 'binary_sensor.isa_dw2hl_3ff9_contact_state', 
    'binary_sensor.lumi_bmgl01_2821_motion_sensor', 'binary_sensor.lumi_bmgl01_2c6c_motion_sensor', 
    'binary_sensor.switch_158d0001c1f861', 'button.xiaomi_s12_c045_play_music', 
    'camera.chuangmi_ipc009_b918_camera_control', 'light.yeelink_bslamp1_b745_light', 
    'sensor.cuco_v3_6df1_electric_power', 'sensor.linp_hb01_7654_occupancy_sensor', 
    'switch.chuangmi_ipc009_b918_switch_status', 'switch.cuco_v3_6df1_switch', 
    'switch.cuco_v3_d474_switch', 'switch.cuco_v3_d474_switch_status', 
    'text.xiaomi_s12_c045_play_text', 'text.xiaomi_s12_c045_execute_text_directive', 
    'light.lumi_v3_6063_light', 'input_boolean.simulate_07_00', 'input_boolean.simulate_23_00'
]

if __name__ == "__main__":
    filter_and_save_logs('/Users/myf/shadowprov/RawLogs/A1/S2/app/app.json', '/Users/myf/shadowprov/RawLogs/A1/S2/app/filtered_logs.json', ent_list)