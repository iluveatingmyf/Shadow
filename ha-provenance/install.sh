#!/bin/bash
# 自动寻找 HA 安装路径并插桩

HA_DIR=$(python3 -c "import homeassistant; print(homeassistant.__path__[0])")

echo "Found Home Assistant at: $HA_DIR"

# 1. 拷贝核心逻辑文件
cp ./scripts/provenance.py "$HA_DIR/helpers/"

# 2. 应用 Patch
# -d 指定目录，-p1 忽略一级路径
patch -d "$HA_DIR/.." -p1 < ./patches/provenance_v2024.1.5.patch

echo "Instrumentation complete. Please restart Home Assistant."
