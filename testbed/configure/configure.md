步骤一：手动创建和写入 Key 文件（在路由器 SSH）
code
Bash
# 1. 进入临时可写目录
cd /tmp

# 2. 创建 authorized_keys 文件 (记得把 AAAA... 替换成你 Mac 的公钥内容)
echo "AAAA.......你的Mac公钥内容.......yourusername@MacBook-Pro" > authorized_keys

# 3. 设置权限（非常重要！）
chmod 700 .ssh  # 如果创建了 .ssh 目录
chmod 600 authorized_keys 

# 4. 告诉 SSH 服务器去哪里找这个文件 (Dropbear/sshd 的配置)
# 小米固件通常在 /etc/dropbear/authorized_keys
echo "Adding authorized_keys path to Dropbear config..."
echo "/tmp/authorized_keys" >> /etc/dropbear/authorized_keys
步骤二：重启 SSH 服务（让配置生效）
code
Bash
# 尝试重启 SSH 服务，让它加载新的 Key 文件
/etc/init.d/sshd restart
# 或者
/etc/init.d/dropbear restart
步骤三：在 Mac 上验证免密登录
回到你的 Mac 终端，尝试登录：
code
Bash
ssh root@192.168.0.1