# Web-Security-Learning 🔐

网络安全学习项目，包含内存取证分析工具、课程笔记和安全实验。

## 功能特性

- **内存取证分析**: 使用 Volatility3 框架解析内存镜像
- **进程检测**: 获取进程列表，检测可疑进程
- **网络连接分析**: 扫描网络连接，识别异常外部连接
- **代码注入检测**: 使用 Malfind 插件检测代码注入痕迹
- **命令行分析**: 分析进程命令行参数，发现可疑命令
- **风险评估**: 自动计算风险评分和风险等级

## 技术规格

- **依赖工具**: Volatility3
- **目标平台**: Windows (内存分析)
- **编程语言**: Python 3
- **输出格式**: JSON 报告 + 原始日志

### 内存分析功能

| 功能 | 说明 |
|------|------|
| windows.pstree.PsTree | 获取进程树结构 |
| windows.netscan.NetScan | 扫描网络连接 |
| windows.malfind.Malfind | 检测代码注入 |
| windows.cmdline.CmdLine | 获取进程命令行 |

## 项目结构

```
Web-Security-Learning/
├── memory_analyzer.py    # 内存取证分析工具
├── Level-1-Fundamentals/  # 基础课程
├── Level-2-Advanced/     # 高级课程
├── memory_analysis_*/     # 分析输出目录
├── reports/              # 报告目录
├── LICENSE               # 许可证
└── README.md             # 项目说明文档
```

## 安装与运行

```bash
# 克隆项目
git clone https://github.com/RainmeoX/Web-Security-Learning.git
cd Web-Security-Learning

# 运行分析工具（需要 Volatility3）
python memory_analyzer.py <内存镜像路径>

# 转储指定进程（可选）
python memory_analyzer.py <内存镜像路径> --dump <PID>
```

### 前置依赖

- Python 3.7+
- Volatility3 框架
- 内存镜像文件（.raw, .vmware 等格式）

## 使用说明

### 基本使用

1. 准备内存镜像文件
2. 运行 `memory_analyzer.py <镜像路径>`
3. 分析结果会保存在自动生成的目录中

### 输出内容

- **pstree.txt**: 进程树原始输出
- **netscan.txt**: 网络连接原始输出
- **malfind.txt**: 代码注入检测输出
- **cmdline.txt**: 命令行参数输出
- **analysis_report.json**: 结构化分析报告

## 许可证

本项目采用 MIT License 许可证。详见 [LICENSE](LICENSE) 文件。

### 使用说明

- **个人/非商业用途**: 可以自由使用，保留署名即可
- **商业用途**: 需要联系我获得授权

## 版权声明

**作者**: RainmeoX

Copyright © 2026 RainmeoX. All rights reserved.

本项目采用 [MIT License](LICENSE) 开源许可证。使用、修改或分发本代码时，必须保留原作者署名。
