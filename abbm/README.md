ShadowProv-ABBM/
├── input/                  # 输入区
│   └── automations.yaml    # 用户提供的原始规则文件
├── core/                   # 核心解析引擎
│   ├── parser.py           # YAML 逻辑提取器 (Static Analysis)
│   ├── model.py            # ABBM 统一形式化模型 (Canonical Rule)
│   └── translator.py       # tau_map 语义映射表 (Service -> State)
├── tools/                  # 辅助工具
│   ├── profiler.py         # 物理特征采集器 (Offline Profiling)
│   ├── validator.py        # 逻辑一致性检测器 (Consistency Check)
│   └── simulator.py        # 模拟触发器 (Testing)
├── data/                   # 知识库
│   ├── profiles.json       # 存储统计出的 Delta Tau 和包指纹
│   └── logic_graph.json    # 转换后的规则因果图
├── exports/                # 输出区 (供 Logic Engine 调用)
│   └── abbm_oracle.py      # 最终生成的推理接口模块
└── scripts/                # 自动化运行脚本
    └── run_pipeline.sh     # 一键生成脚本