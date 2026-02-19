import subprocess

def get_router_time():
    # 通过 SSH 获取路由器当前 Unix 时间戳
    result = subprocess.run(["ssh", ROUTER_ALIAS, "date +%s.%N"], capture_output=True, text=True)
    return float(result.stdout.strip())

def get_ha_time():
    # 通过 HA API 获取服务器时间（需 HA 提供相应接口，或使用事件中的时间差估算）
    # 简单方法：调用一个快速 API 并记录本地时间，估算 RTT 后得到 HA 时间
    start = time.time()
    resp = requests.get(f"{HA_URL_HTTP}/api/", headers=HEADERS)
    end = time.time()
    # 假设 HA 返回的时间戳在其响应头中（通常没有），因此这里只能估算，但更可靠的是利用事件中的 ha_fired_at 与本地时间对比
    # 此处仅为示例
    pass