# core/translator.py

class SemanticTranslator:
    # 状态映射表 (Action -> Physical State)
    TAU_MAP = {
        'light.turn_on': 'on', 'light.turn_off': 'off',
        'switch.turn_on': 'on', 'switch.turn_off': 'off',
        'lock.lock': 'locked', 'lock.unlock': 'unlocked',
        'alarm_control_panel.alarm_arm_away': 'armed_away',
        'alarm_control_panel.alarm_arm_home': 'armed_home',
        'alarm_control_panel.alarm_arm_night': 'armed_night',
        'alarm_control_panel.alarm_disarm': 'disarmed'
    }

    # 对立状态表 (State A <-> State B)
    OPPOSITE_STATES = {
        'on': 'off', 'off': 'on',
        'locked': 'unlocked', 'ununlocked': 'locked',
        'armed_away': 'disarmed', 'armed_night': 'disarmed', 
        'armed_home': 'disarmed', 'disarmed': 'armed_away'
    }

    @classmethod
    def to_physical_state(cls, service):
        return cls.TAU_MAP.get(service, 'unknown')

    @classmethod
    def get_reverse_state(cls, current_state):
        """获取物理状态的对立面"""
        return cls.OPPOSITE_STATES.get(current_state, 'off')

    @classmethod
    def get_service_for_state(cls, domain, state):
        """根据目标物理状态反推对应的 HA Service"""
        # 针对报警面板的特殊处理
        if domain == "alarm_control_panel":
            # 修正：去掉了中间多余的 'ed'
            if state == "disarmed": return "alarm_disarm"
            if state == "armed_away": return "alarm_arm_away" # 正确的服务名
            if state == "armed_home": return "alarm_arm_home"
            if state == "armed_night": return "alarm_arm_night"
            return f"alarm_{state.replace('armed_', 'arm_')}"
        
        # 针对普通开关和灯
        if state in ["on", "off"]:
            return f"turn_{state}"
        
        # 针对门锁
        if state == "locked": return "lock"
        if state == "unlocked": return "unlock"
        
        return "turn_off" # 默认兜底