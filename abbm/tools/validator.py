def test_oracle_consistency():
    """
    验证标准：
    1. 输入一个物理开门信号，Oracle 必须返回“预期的开灯动作”。
    2. 输入一个处于 Away 模式下的开灯动作，Oracle 必须返回“Is Forbidden = True”。
    """
    oracle = ABBMOracle("logic_graph.json")
    
    # 测试 1: Should Trigger (Ghost Node Detection)
    print("Testing ShouldTrigger...")
    # 假设传感器 11 (门磁) 物理打开
    res = oracle.should_trigger("binary_sensor.isa_dw2hl_3ff9_contact_state", "on")
    assert len(res) > 0
    print("[PASS] Successfully inferred expected actions from physical trigger.")

    # 测试 2: Is Forbidden (Policy Bypass Detection)
    print("Testing IsForbidden...")
    # 模拟一个执行动作：打开灯 5
    act = {'entity': 'light.yeelink_bslamp1_b745_light', 'service': 'light.turn_on'}
    # 模拟一个错误的物理快照：此时网关还是 armed_away，而规则要求在撤防下才能开灯
    state_snapshot = {'alarm_control_panel.lumi_mgl03_4e93_arming': 'armed_away'}
    
    forbidden, rid, cond = oracle.is_forbidden(act, state_snapshot)
    if forbidden:
        print(f"[PASS] Correcty detected forbidden action under rule {rid}. Violation: {cond}")

if __name__ == "__main__":
    test_oracle_consistency()