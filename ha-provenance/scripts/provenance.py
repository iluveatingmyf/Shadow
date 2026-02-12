from __future__ import annotations
from contextvars import ContextVar
from typing import Any, Dict, List, Optional, Tuple, Sequence, TYPE_CHECKING
import logging
import json
import os
from datetime import datetime
import uuid

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)

# 全局 HASS 引用，由 Core 启动时注入
_HASS_REF: Optional[Any] = None

def set_global_hass(hass: Any):
    """注入HASS实例，用于查表"""
    global _HASS_REF
    _HASS_REF = hass
    
# 定义事件类型
EVENT_TYPE_ENTITY = "Entity"
EVENT_TYPE_COMMAND = "Command"
EVENT_TYPE_AGENT = "Agent"

# 全局事件存储
event_log: List[Dict[str, Any]] = []
event_id_counter = 1
context_id_map: Dict[str, int] = {}  # context.id -> event_ID
context_vars: ContextVar[Dict[str, Any]] = ContextVar(
    "context_vars", default={}
)


# 状态机：跟踪自动化执行状态和条件关联
class StateMachine:
    def __init__(self):
        # automation_id -> state (存储完整条件链和目标活动)
        self.automation_states: Dict[str, Dict[str, Any]] = {}
        self.automation_commands: Dict[str,
                                       List[Dict[str, Any]]] = {}  # 自动化命令跟踪
        self.automation_conditions: Dict[str, List[int]] = {}  # 存储所有条件事件ID

    def start_automation(self, automation_id: str, trigger_event_id: int) -> None:
        """记录自动化开始执行，初始化条件链"""
        self.automation_states[automation_id] = {
            "active": True,
            "trigger_event_id": trigger_event_id,
            "last_condition_id": None,
            "condition_passed": True,
            "current_step": "trigger",
            "target_activity": None  # 最终触发的Command ID
        }
        self.automation_conditions[automation_id] = []  # 初始化条件ID列表

    def record_condition(self, automation_id: str, condition_event_id: int, result: bool) -> None:
        """记录条件检查结果，维护完整条件链"""
        if automation_id not in self.automation_states:
            _LOGGER.warning(
                f"Automation {automation_id} not active when recording condition")
            return

        state = self.automation_states[automation_id]
        state["last_condition_id"] = condition_event_id
        state["condition_passed"] = state["condition_passed"] and result
        state["current_step"] = "condition"
        # 存储所有条件ID（无论是否通过）
        self.automation_conditions[automation_id].append(condition_event_id)

    def set_target_activity(self, automation_id: str, activity_id: int) -> None:
        """记录自动化触发的目标Command ID"""
        if automation_id in self.automation_states:
            self.automation_states[automation_id]["target_activity"] = activity_id

    def get_conditions(self, automation_id: str) -> List[int]:
        """获取自动化的所有条件事件ID"""
        return self.automation_conditions.get(automation_id, [])

    def is_automation_active(self, automation_id: str) -> bool:
        """检查自动化是否仍在活跃状态（条件未失败）"""
        state = self.automation_states.get(automation_id, {})
        return state.get("active", False) and state.get("condition_passed", False)

    def is_automation_active_with_reason(self, automation_id: str) -> Tuple[bool, Optional[int]]:
        """检查自动化是否活跃并返回阻塞原因ID"""
        state = self.automation_states.get(automation_id, {})
        is_active = state.get("active", False) and state.get(
            "condition_passed", False)
        return is_active, state.get("last_condition_id") if not is_active else None

    def end_automation(self, automation_id: str) -> None:
        """标记自动化执行结束"""
        if automation_id in self.automation_states:
            self.automation_states[automation_id]["active"] = False
            self.automation_states[automation_id]["current_step"] = "completed"

    def get_automation_context(self, automation_id: str) -> Optional[Dict[str, Any]]:
        """获取自动化上下文信息"""
        return self.automation_states.get(automation_id)

    def track_commands(self, automation_id: str, sequence: Sequence[dict]) -> None:
        """解析自动化的动作配置，提取目标设备和命令"""
        parsed_commands = []
        for action in sequence:
            # 解析HomeAssistant动作配置中的核心信息：
            # 示例动作配置：{"service": "light.turn_on", "target": {"entity_id": "light.lumi_v3_6063_light_3"}}
            service = action.get("service")  # 命令类型（如"light.turn_on"）
            target_entity = action.get("target", {}).get("entity_id")  # 目标设备ID
            # 处理目标设备为列表的情况（取第一个）
            if isinstance(target_entity, list):
                target_entity = target_entity[0] if target_entity else None
            if service and target_entity:
                parsed_commands.append({
                    "target_device": target_entity,  # 目标设备实体ID
                    "command": service,  # 命令类型
                    "description": f"Execute {service.split('.')[-1]}"  # 描述（如"turn_on"）
                })
        # 存储解析后的命令，关联到自动化ID
        # 强制将 ID 转为字符串存储，防止类型不匹配
        self.automation_commands[str(automation_id)] = parsed_commands
        _LOGGER.warning(f"[Trace] Tracked {len(parsed_commands)} commands for {automation_id}")
        #self.automation_commands[automation_id] = parsed_commands

    
    def get_blocked_commands(self, automation_id: str) -> List[Dict[str, Any]]:
        """获取因条件失败而被阻止的命令"""
        return self.automation_commands.get(automation_id, [])


# 初始化状态机
state_machine = StateMachine()


def get_session_id() -> str:
    """从上下文获取当前会话ID（支持多会话隔离）"""
    vars = context_vars.get()
    if "session_id" not in vars:
        vars["session_id"] = str(uuid.uuid4())
        context_vars.set(vars)
    return vars["session_id"]


def clear_log() -> None:
    """清除事件日志并重置会话"""
    global event_log, event_id_counter, context_id_map
    event_log = []
    event_id_counter = 1
    context_id_map = {}
    # 重置上下文变量（保留结构，清空内容）
    vars = context_vars.get()
    vars.clear()
    context_vars.set(vars)
    # 重置状态机
    state_machine.automation_states.clear()
    state_machine.automation_commands.clear()
    state_machine.automation_conditions.clear()
    _LOGGER.info("Event log cleared and new session started")



# ========== 核心优化：富语义信息获取 ==========
def get_rich_entity_info(entity_id: str) -> dict:
    """获取实体名称、区域、型号等富语义信息，解决‘脏数据’问题"""
    # 引入注册表以获取富语义信息
    from homeassistant.helpers import entity_registry as er
    from homeassistant.helpers import device_registry as dr
    
    info = {
        "friendly_name": entity_id.split('.')[-1].replace('_', ' ').title(),
        "area_id": None,
        "model": None,
        "domain": entity_id.split('.')[0]
    }
    
    if not _HASS_REF or not entity_id:
        return info

    try:
        ent_reg = er.async_get(_HASS_REF)
        dev_reg = dr.async_get(_HASS_REF)
        
        # 1. 查询 Entity Registry
        entry = ent_reg.async_get(entity_id)
        if entry:
            if entry.name:
                info["friendly_name"] = entry.name
            elif entry.original_name:
                info["friendly_name"] = entry.original_name
            
            # 2. 查询 Device Registry
            if entry.device_id:
                device = dev_reg.async_get(entry.device_id)
                if device:
                    info["model"] = device.model
                    info["area_id"] = device.area_id # 之后可以进一步转为 area name
    except Exception:
        pass # 查表失败降级处理

    # 3. 尝试从 State 获取 (运行时名称通常最准)
    state = _HASS_REF.states.get(entity_id)
    if state and "friendly_name" in state.attributes:
        info["friendly_name"] = state.attributes["friendly_name"]

    return info


def record_event(
    event_type: str,
    device: str,
    description: str,
    context: Any,
    action: Optional[str] = None,  # "triggered" 或 "condition_check"
    condition: Optional[Dict[str, Any]] = None,
    extra_attributes: Optional[Dict[str, Any]] = None,
    # 三类事件特有字段（顶级参数）
    entity_id: Optional[str] = None,  # Entity特有：实体唯一ID
    target_activity: Optional[int] = None,  # Agent特有：触发的Command ID
    forbidden_activity: Optional[int] = None,  # Agent特有：阻止的Command ID
    condition_ids: Optional[List[int]] = None,  # Command特有：依赖的条件ID列表
) -> int:
    """记录事件的核心函数，支持三类事件特有字段和关联逻辑"""
    global event_id_counter

    """if ("unknown" in description.lower()) or ("None" in description.lower()) or ("unavailable" in description.lower()):
        _LOGGER.debug(f"过滤包含unknown的事件：{description}")
        return -1  # 返回无效ID表示事件未被记录"""
    
    # ===== 优化后的过滤逻辑 =====
    # 只有当事件类型是 Entity 时，才检查是否包含 unknown/None/unavailable
    # Agent 和 Command 事件即便包含这些词也必须记录，因为它们代表了逻辑路径
    if event_type == EVENT_TYPE_ENTITY:
        if any(word in description.lower() for word in ["unknown", "none", "unavailable"]):
            _LOGGER.debug(f"过滤 Entity 脏数据：{description}")
            return -1 
    # ===========================


    # 1. 从上下文获取会话ID
    current_session_id = get_session_id()

    # 2. 解析source（优先显式传入，再 fallback 到上下文）
    source = None
    if extra_attributes and "source" in extra_attributes:
        source = extra_attributes.pop("source")  # 提取显式source
    else:
        if context and context.parent_id:
            source = context_id_map.get(context.parent_id)
    
    rich_info = {}
    display_name = device
    if entity_id:
        rich_info = get_rich_entity_info(entity_id)
        display_name = rich_info.get("friendly_name", device)
    elif "." in device and "_" in device: # 猜测是 entity_id
        rich_info = get_rich_entity_info(device)
        display_name = rich_info.get("friendly_name", device)

    # 4. 构建基础事件结构
    event = {
        "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "device": display_name, # 用户可见名称
        "raw_device_id": entity_id or device, # 保留技术 ID
        "event_type": event_type,
        "description": description,
        "source": source,
        "event_ID": event_id_counter,
        "session_id": current_session_id,
        "action": action,
        "context_id": context.id if context else None,
        "parent_context_id": context.parent_id if context else None
    }

    if rich_info.get("area_id"):
        event["area"] = rich_info["area_id"]

    # 5. 添加事件类型特有字段（顶级字段）
    if event_type == EVENT_TYPE_ENTITY and entity_id:
        event["entity_id"] = entity_id
        event["old_state"] = extra_attributes.pop(
            "old_state", "") if extra_attributes else ""
        event["new_state"] = extra_attributes.pop(
            "new_state", "") if extra_attributes else ""

    elif event_type == EVENT_TYPE_AGENT:
        if target_activity is not None:
            event["target_activity"] = target_activity
        if forbidden_activity is not None:
            event["forbidden_activity"] = forbidden_activity

    elif event_type == EVENT_TYPE_COMMAND:
        if condition_ids is not None:
            event["condition_ids"] = condition_ids
        event["command"] = extra_attributes.pop(
            "command", "") if extra_attributes else ""
        event["target_device"] = extra_attributes.pop(
            "target_device", "") if extra_attributes else ""

    # 6. 添加条件信息（如Agent的条件检查结果）
    if condition is not None:
        event.update(condition)
    
    # 7. 添加剩余额外属性
    if extra_attributes:
        event.update(extra_attributes)

    # 8. 存储事件并更新映射
    event_log.append(event)
    if context and hasattr(context, 'id'):
        context_id_map[context.id] = event_id_counter  # 上下文ID -> 事件ID

    event_id_counter += 1
    _LOGGER.debug(f"Recorded {event_type} event: {event}")
    return event_id_counter - 1


def save_log(base_dir: str, prefix: str = "provenance_log") -> str:
    """
    保存带时间戳的事件日志。
    参数 base_dir: 存储目录，如 '/home/homeassistant/.homeassistant/logs/'
    参数 prefix: 文件名前缀
    """
    try:
        # 1. 生成人类可读的时间戳
        timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        filename = f"{prefix}_{timestamp}.json"
        full_path = os.path.join(base_dir, filename)

        # 2. 确保目录存在
        os.makedirs(base_dir, exist_ok=True)

        # 3. 写入文件
        with open(full_path, 'w', encoding='utf-8') as f:
            json.dump(event_log, f, indent=2, ensure_ascii=False)
        
        _LOGGER.warning(f"===== Provenance Log Saved: {full_path} =====")
        return full_path
    except Exception as e:
        _LOGGER.error(f"Failed to save event log: {e}")
        return ""




# ========== 事件记录工具函数 ==========
def log_agent_event(device: str, description: str, context: Any, condition: Optional[Dict[str, Any]] = None, extra_attributes: Optional[Dict[str, Any]] = None, automation_id: Optional[str] = None, target_activity: Optional[int] = None, forbidden_activity: Optional[int] = None, action: Optional[str] = None) -> int:
    _LOGGER.warning(f"Entering log_agent_event: Device={device}, Action={action}, AutoID={automation_id}")

    event_id = record_event(EVENT_TYPE_AGENT, device, description, context, action, condition, extra_attributes, target_activity=target_activity, forbidden_activity=forbidden_activity)
    if condition and automation_id:
        result = condition.get("condition_result", False)
        state_machine.record_condition(str(automation_id), event_id, result)
        if not result:
            if event_log and event_log[-1]["event_ID"] == event_id:
                event_log[-1]["description"] = f"Condition failed: {description}. Stopping automation." 
            _LOGGER.warning(f"[Trace] Condition Failed. Triggering block logging for {automation_id}")
            log_blocked_commands(str(automation_id), context, event_id)
            state_machine.end_automation(str(automation_id))
    return event_id
    
def log_trigger(action: str, entity_id: str, state: str, automation_name: str, context: Any, automation_id: str, sequence: Optional[Sequence[dict]] = None, is_start_point: bool = True) -> int:
    _LOGGER.warning(f"[Trace] Trigger Start: {automation_name} (ID: {automation_id})")
    
    # 获取触发源 Entity 事件 ID（实现 Trigger 溯源）
    vars = context_vars.get()
    trigger_entity_id = vars.get(context.id, {}).get("entity_event_id")
    
    rich_name = automation_name
    if _HASS_REF:
        rich_info = get_rich_entity_info(automation_name) # 这里 automation_name 其实是 entity_id
        rich_name = rich_info.get("friendly_name", automation_name)

    agent_event_id = log_agent_event(
        device=rich_name, # 使用富语义名称
        description=f"Triggered by {entity_id} state change",
        context=context,
        automation_id=automation_id,
        extra_attributes={"source": trigger_entity_id, "automation_entity_id": automation_name},
        action="triggered"
    )
    # 核心修复：同时用数字 ID 和 实体名注册状态机，解决匹配不上问题
    state_machine.start_automation(str(automation_id), agent_event_id)
    if automation_name and automation_name.startswith("automation."):
        state_machine.start_automation(automation_name, agent_event_id)


    if sequence:
        state_machine.track_commands(automation_id, sequence)
        if automation_name.startswith("automation."):
                state_machine.track_commands(automation_name, sequence)
    
    # 记录触发源 Entity 事件 (如果这是链条起点)
    if is_start_point:
        rich_entity = get_rich_entity_info(entity_id)
        entity_event_id = record_event(
            event_type=EVENT_TYPE_ENTITY,
            device=rich_entity.get("friendly_name", entity_id),
            description=f"Trigger state: {state}",
            context=context,
            entity_id=entity_id,
            extra_attributes={"old_state": "", "new_state": state}
        )
        vars[context.id] = {"automation": automation_name, "automation_id": automation_id, "trigger_event_id": agent_event_id, "entity_event_id": entity_event_id}
        context_vars.set(vars)
    return agent_event_id
    

def log_condition_check(
    automation_name: str,
    automation_id: str,
    entity_id: str,
    condition_desc: str,
    result: bool,
    context: Any,
    condition_state: Optional[str] = None
) -> None:
    """记录条件检查事件（用于构建isConditionOf边）"""
    _LOGGER.warning(f"[Trace] Condition Check: {automation_name} | ID: {automation_id} | Result: {result}")
    try:
        # 即使状态机里没有 active，我们也要继续记录日志，不要 return
        is_active = state_machine.is_automation_active(automation_id)
        if not is_active:
            _LOGGER.warning(f"[Trace] ID {automation_id} not found/active in state_machine, recording anyway.")

        device_name = get_friendly_name(entity_id)
        condition_info = f"{condition_desc} - {'Passed' if result else 'Failed'}"

        vars = context_vars.get()
        # 增加溯源健壮性：从当前或父 context 寻找 trigger source
        automation_context = vars.get(context.parent_id, {}) or vars.get(context.id, {})
        trigger_source = automation_context.get("entity_event_id")

        # 构造 condition 详情，增加 fallback 逻辑防止 related_trigger_id 报错
        auto_ctx = state_machine.get_automation_context(automation_id)
        related_trigger = auto_ctx.get("trigger_event_id") if auto_ctx else None

        condition_data = {
            "condition_result": result,
            "condition_entity": device_name,
            "condition_entity_id": entity_id,
            "condition_state": condition_state,
            "related_trigger_id": related_trigger
        }

        condition_event_id = log_agent_event(
            device=automation_name,
            description=condition_info,
            context=context,
            condition=condition_data,
            automation_id=automation_id,
            extra_attributes={"source": trigger_source},
            action="condition_check"
        )

        # 无论如何都要尝试记录被阻止的命令
        if not result:
            _LOGGER.warning(f"[Trace] Condition Failed, logging blocked commands for {automation_id}")
            log_blocked_commands(automation_id, context, condition_event_id)
    except Exception as e:
        _LOGGER.warning(f"Error in log_condition_check: {e}")


def log_condition(
    automation_name: str,
    entity_id: str,
    condition_desc: str,
    result: bool,
    context: Any,
    condition_state: Optional[str] = None,
    automation_id: Optional[str] = None,
    variables: Optional[Dict[str, Any]] = None
) -> None:
    """对接HomeAssistant条件检查逻辑的事件记录"""
    try:
        # --- 新增：ID 对齐逻辑 ---
        final_id = automation_id
        
        if variables:
            # 1. 尝试从 variables 直接拿数字 ID (最准)
            if "automation_id" in variables:
                final_id = variables["automation_id"]
            # 2. 尝试从 this 对象拿 (YAML 里的 id)
            elif "this" in variables and "attributes" in variables["this"]:
                final_id = variables["this"]["attributes"].get("id", final_id)
        
        # 3. 实在没有就用实体名，但加上警告
        if not final_id:
            final_id = automation_name 
            _LOGGER.debug(f"Using entity name as fallback ID: {final_id}")

        # --- 强制插入 Debug 日志 ---
        _LOGGER.warning(f"[Condition Trace] Name: {automation_name} | ID: {final_id} | Result: {result}")
        _LOGGER.warning(f"[Trace] Entering log_condition: {automation_name} | TargetID: {final_id}")

        log_condition_check(
            automation_name=automation_name,
            automation_id=str(final_id), # 统一转字符串防止类型冲突
            entity_id=entity_id,
            condition_desc=condition_desc,
            result=result,
            context=context,
            condition_state=condition_state
        )
    except Exception as e:
        _LOGGER.error(f"Error in log_condition: {e}")


def log_blocked_commands(
    automation_id: str,
    context: Any,
    source_agent_id: int  # 条件检查事件的ID（作为来源）
) -> None:
    """记录被条件阻止的命令"""
    # 尝试多种 ID 获取命令列表
    blocked_commands = state_machine.automation_commands.get(str(automation_id))
    if not blocked_commands:
        vars = context_vars.get()
        # 尝试从当前或父 context 变量里找回关联的实体名或 ID
        ctx_data = vars.get(context.id) or vars.get(context.parent_id)
        if ctx_data:
            alt_id = ctx_data.get("automation_id") or ctx_data.get("automation")
            blocked_commands = state_machine.automation_commands.get(str(alt_id))
    if not blocked_commands:
        _LOGGER.warning(f"[Trace] No commands found in StateMachine for block-logging (ID: {automation_id})")
        return

    # 为每个被阻止的命令生成事件
    for cmd in blocked_commands:
        # 调用record_event记录被阻止的命令
        record_event(
            event_type=EVENT_TYPE_COMMAND,
            device=cmd["target_device"],  # 目标设备ID
            # 描述（如"Blocked: turn_on"）
            description=f"Blocked: {cmd['description']}",
            context=context,
            condition_ids=state_machine.get_conditions(
                automation_id),  # 关联所有条件ID
            extra_attributes={
                "command": cmd["command"],  # 被阻止的命令（如"light.turn_on"）
                "target_device": cmd["target_device"],  # 目标设备
                "status": "blocked",  # 标记为“被阻止”
                "source": source_agent_id  # 关联条件检查事件ID
            }
        )

def log_state_change(
    entity_id: str,
    new_state: str,
    old_state: str,
    context: Any,
    source_activity_id: Optional[int] = None  # 触发该状态变化的Activity事件ID
) -> None:
    """记录实体状态变化（构建Derive/Generate边）"""
    try:
        device_name = get_friendly_name(entity_id)
        description = f"{old_state} → {new_state}" if old_state else f"Initialized to {new_state}"

        # 自动获取source_activity_id（如果未手动传入）
        if source_activity_id is None and context:
            # 1. 从上下文的parent_id找到触发源头的context.id
            # 实体状态变化的parent_id通常指向触发它的命令/活动的context.id
            source_context_id = getattr(context, 'parent_id', None)
            
            if not source_context_id:
                # 特殊情况：直接使用当前上下文ID（如面板操作）
                source_context_id = getattr(context, 'id', None)
            
            # 2. 通过context_id_map将context.id转换为事件ID（即source_activity_id）
            if source_context_id:
                source_activity_id = context_id_map.get(source_context_id)

        record_event(
            event_type=EVENT_TYPE_ENTITY,
            device=device_name,
            description=description,
            context=context,
            entity_id=entity_id,
            extra_attributes={
                "old_state": old_state,
                "new_state": new_state,
                "source": source_activity_id  # 核心：source=触发活动的事件ID
            }
        )

    except Exception as e:
        _LOGGER.error(f"Error in log_state_change: {e}")

def log_command(
    device_id: str,
    command: str,
    context: Any,
    source: Optional[int] = None,
    automation_id: Optional[str] = None,
    status: str = "executed",
    blocked_by: Optional[int] = None
) -> None:
    """记录命令执行（构建wasAssociatedWith/isConditionOf边）"""
    try:
        device_name = get_friendly_name(
            device_id) or get_friendly_name(command.split('.')[0])
        description = f"{command.split('.')[-1].replace('_', ' ').title()}"

        # 获取依赖的条件ID列表（从状态机）
        _LOGGER.warning("automation_id")
        _LOGGER.warning(automation_id)
        condition_ids = state_machine.get_conditions(
            automation_id) if automation_id else None

        # 记录Command事件
        cmd_event_id = record_event(
            event_type=EVENT_TYPE_COMMAND,
            device=device_name,
            description=description,
            context=context,
            condition_ids=condition_ids,
            extra_attributes={
                "command": command,
                "target_device": device_id,
                "context_id": context.id if context else None,
                "automation_id": automation_id,
                "status": status,
                "source": source
            }
        )
        if not context:
            from homeassistant.context import Context
            context = Context()  # 生成新上下文
        # 补充：显式记录上下文映射（防止遗漏）
        context_id_map[context.id] = cmd_event_id

        # 关联Agent与Command（更新状态机）
        if automation_id and status == "executed":
            state_machine.set_target_activity(automation_id, cmd_event_id)
            state_machine.end_automation(automation_id)

        # 被阻塞时补充关联
        #if status == "blocked" and blocked_by:
        #    for event in event_log:
        #        if event["event_ID"] == cmd_event_id:
        #            event["blocked_by"] = blocked_by
        #            break

    except Exception as e:
        _LOGGER.error(f"Error in log_command: {e}")



def get_friendly_name(entity_id: str) -> str:
    """从全局 HASS 引用中获取友好名称，支持无 HASS 时的降级处理"""
    if not entity_id:
        return "Unknown"
    
    # 1. 如果全局 HASS 引用存在，尝试从状态机获取
    if _HASS_REF:
        state = _HASS_REF.states.get(entity_id)
        if state and "friendly_name" in state.attributes:
            return state.attributes["friendly_name"]
            
        # 2. 尝试从 Registry 获取 (如果需要更精准，可以取消注释下面部分)
        # from homeassistant.helpers import entity_registry as er
        # registry = er.async_get(_HASS_REF) # 注意：在同步环境下调用 async_get 可能有风险
        # entry = registry.async_get(entity_id)
        # if entry and entry.name: return entry.name
    
    # 3. 降级处理：将 input_boolean.system_armed 变为 System Armed
    return entity_id.split('.')[-1].replace('_', ' ').title()
    

def init_startup_log():
    """初始化新日志会话"""
    try:
        # 1. 重置全局变量和状态机
        clear_log() 
        
        # 2. 记录系统启动事件作为 Log 的第一条数据
        record_event(
            event_type=EVENT_TYPE_AGENT,
            device="System",
            description="Home Assistant Startup: Logging Session Started",
            context=None,
            action="system_init"
        )
    except Exception as e:
        _LOGGER.error(f"Error initializing startup log: {e}")
