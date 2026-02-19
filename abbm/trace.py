# tools/simulator.py
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from exports.abbm_oracle import ABBMOracle

def run_test():
    oracle = ABBMOracle()
    
    print("\n" + "="*60)
    print(" SHADOWPROV-ABBM SUITE: FUNCTIONAL VERIFICATION REPORT")
    print("="*60)

    # 1. 验证 Ghost Node 显化 (Should Trigger)
    print("\n[STEP 1: Testing Ghost Node Inference]")
    # 模拟物理层观测到“人在洗手间移动” (R17)
    trigger_event = ("binary_sensor.lumi_bmgl01_2c6c_motion_sensor", "on")
    res = oracle.get_expectations(*trigger_event)
    
    if res:
        for r in res:
            print(f" SUCCESS: Trigger {trigger_event[0]} detected.")
            print(f"  -> Expectation: Device {r['actions'][0]['entity']} should turn {r['actions'][0]['expected_state']}")
            print(f"  -> Constraint: Must manifest within {r['constraint'].get('max_wait')}s")
    else:
        print(" FAIL: No logical mapping found for trigger.")

    # 2. 验证 sforbid 边判定 (Policy Bypass)
    print("\n[STEP 2: Testing Forbidden Activity Detection]")
    # 模拟攻击：用户在家，但系统尝试执行“开启摄像头” (R5要求离家模式)
    malicious_act = {'entity': 'switch.chuangmi_ipc009_b918_switch_status', 'service': 'switch.turn_on'}
    # 模拟物理真实快照：人在家
    context = {'sensor.linp_hb01_7654_occupancy_sensor': 'has one'}
    
    is_valid, rid, cond = oracle.verify_policy(malicious_act, context)
    if not is_valid:
        print(f" ALERT: Forbidden Activity Captured!")
        print(f"  -> Root Cause: Violated Rule {rid}")
        print(f"  -> Conflict: Expect {cond['entity']} == {cond['state']}, but physically it is {context.get(cond['entity'])}")
    else:
        print(" FAIL: Malicious activity was not flagged.")

if __name__ == "__main__":
    run_test()