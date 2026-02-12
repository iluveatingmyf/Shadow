#!/bin/sh
# Xiaomi Router Capture & Auto-Transfer Script
# Requirement: 
# 1. Configuration file at /etc/testbed_config
# 2. tcpdump binary at /data/tcpdump
# 3. SSH Public Key authentication configured with Mac



# 1. 读取配置
CONFIG_FILE="/etc/testbed_config"
[ -f "$CONFIG_FILE" ] && . $CONFIG_FILE

# 2. 核心路径检查
if [ ! -d "$PCAP_DIR" ]; then
    mkdir -p "$PCAP_DIR"
fi

# 检查 U 盘是否真的可写
touch "$PCAP_DIR/write_test" >/dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "!!! ERROR: U-Disk ($PCAP_DIR) is NOT writable."
    echo "Check mount status or format U-disk to FAT32."
    exit 1
fi
rm "$PCAP_DIR/write_test"

# 3. 启用 CPU 路径 (禁用硬件加速)
echo "[*] Forcing traffic to CPU path..."
iptables -t mangle -F
iptables -t mangle -A PREROUTING -j MARK --set-mark 1

# 4. 开始抓包 (后台运行)
echo "[*] Capturing on $CAPTURE_INTERFACES..."
/data/tcpdump -i br-lan -n -w "$PCAP_DIR/capture_br-lan.pcap" "not host $EXCLUDE_IP" &
PID_LAN=$!
/data/tcpdump -i wl1 -n -w "$PCAP_DIR/capture_wl1.pcap" "not host $EXCLUDE_IP" &
PID_WL1=$!

echo "[*] Press ENTER to stop and transfer..."
read temp

# 5. 停止并回传
kill $PID_LAN $PID_WL1
wait $PID_LAN $PID_WL1 2>/dev/null  # 新增：等待进程彻底结束
echo "[*] Transferring to Mac..."

# 使用你验证成功的 dbclient/scp 组合
scp -i /etc/dropbear/dropbear_rsa_host_key \
    -o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1 \
    -o HostKeyAlgorithms=+ssh-rsa \
    -o MACs=+hmac-sha1 \
    "$PCAP_DIR"/*.pcap "${MAC_USER}@${MAC_IP}:${MAC_DIR}"

if [ $? -eq 0 ]; then
    echo "[+] Done! Files are on your Mac."
    # 建议开启：传输完自动删除 U 盘上的旧文件，省得下次占空间
    rm "$PCAP_DIR"/*.pcap
else
    echo "[-] Transfer failed."
fi

# 在 Done! 后面或脚本末尾增加
iptables -t mangle -D PREROUTING -j MARK --set-mark 1 2>/dev/null
echo "[*] Hardware acceleration hint restored."
