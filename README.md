# Web-Security-Learning 🔐

> 网络安全学习项目 - 基于 Datawhale 网安课程，包含 Web 安全、应急响应两大方向的完整代码实践

## 📚 课程体系

本项目对应飞书课程文档，分为 Web 安全和应急响应两大方向，共 11 节课。

### Web 安全方向（7 节课）

| 课次 | 主题 | 代码目录 | 学习状态 |
|------|------|----------|----------|
| 第一节课 | HTTP 协议基础、Cookie/Session | `Level-1-Fundamentals/` | ✅ 已完成 |
| 第二节课 | 深度取证与云环境响应 | `Level-2-Advanced/` | ✅ 已完成 |
| 第三课 | CSRF 攻击及防御 | `Level-1-Fundamentals/csrf.html` | ✅ 已完成 |
| 第四课 | XSS 攻击及防御 | `Level-1-Fundamentals/xss_attack.py` | ✅ 已完成 |
| 第五课 | SQL 注入、命令注入、路径穿越 | `Level-1-Fundamentals/` | ✅ 已完成 |
| **第六课** | **文件上传漏洞原理与利用** | **`Level-3-FileUpload/`** | ✅ **本次补充** |
| **第七课** | **代码审计发现文件上传漏洞** | **`Level-4-CodeAudit/`** | ✅ **本次补充** |

### 应急响应方向（4 节课，每课 7 个练习）

| 课次 | 主题 | 代码目录 | 学习状态 |
|------|------|----------|----------|
| **第一课** | **应急响应基础（检测/分析/抑制/取证/清除/报告）** | **`Level-5-EmergencyResponse/Class1/`** | ✅ **本次补充** |
| **第二课** | **深度取证与云环境响应（内存取证/勒索软件/SOAR）** | **`Level-5-EmergencyResponse/Class2/`** | ✅ **本次补充** |
| **第三课** | **高级威胁狩猎与溯源（ATT&CK/威胁情报/EDR）** | **`Level-5-EmergencyResponse/Class3/`** | ✅ **本次补充** |
| **第四课** | **自动化编排与应急响应平台（SOAR）** | **`Level-5-EmergencyResponse/Class4/`** | ✅ **本次补充** |

## 📁 项目结构

```
Web-Security-Learning/
├── Level-1-Fundamentals/          # Web安全基础（第一、三、四、五课）
│   ├── app.py                     # Flask 漏洞演示应用
│   ├── http_basics.py             # HTTP 协议基础
│   ├── sql_injection.py           # SQL 注入攻击
│   ├── login_sqli.py              # 登录绕过
│   ├── xss_attack.py              # XSS 攻击（反射型）
│   ├── stored_xss.py              # XSS 攻击（存储型）
│   ├── csrf.html                  # CSRF 攻击
│   ├── command_injection.py       # 命令注入
│   └── path_traversal.py          # 路径穿越
│
├── Level-2-Advanced/              # 高级课程（第二课）
│   ├── memory_analyzer.py         # 内存取证分析工具
│   └── reports/                   # 分析报告
│
├── Level-3-FileUpload/            # 文件上传漏洞（第六课）⭐ 新增
│   ├── vulnerable_app.py          # 漏洞靶场（4种校验方式）
│   └── attack_upload.py           # 攻击脚本（5种绕过技术）
│
├── Level-4-CodeAudit/             # 代码审计（第七课）⭐ 新增
│   └── audit_upload.py            # 文件上传漏洞审计工具
│
├── Level-5-EmergencyResponse/     # 应急响应（4节课）⭐ 新增
│   ├── Class1/                    # 第一课：应急响应基础
│   │   └── ssh_brute_force_detector.py   # SSH暴力破解检测器
│   ├── Class2/                    # 第二课：深度取证
│   │   └── ransomware_response.py        # 勒索软件模拟与解密
│   ├── Class3/                    # 第三课：威胁狩猎
│   │   └── attack_chain_mapper.py        # ATT&CK攻击链映射器
│   └── Class4/                    # 第四课：SOAR自动化
│       └── soar_engine.py                # SOAR剧本编排引擎
│
├── docs/                          # 课程文档
├── memory_analyzer.py             # 内存分析工具（根目录）
├── README.md
└── LICENSE
```

## 🚀 快速开始

### 环境准备

```bash
# Python 3.8+
pip install flask requests cryptography pyyaml

# 内存取证（可选，Level-2）
pip install volatility3
```

### 运行示例

```bash
# 1. Web 安全基础 - 启动漏洞靶场
cd Level-1-Fundamentals
python app.py
# 访问 http://127.0.0.1:5000

# 2. 文件上传漏洞 - 启动靶场 + 攻击
cd Level-3-FileUpload
python vulnerable_app.py    # 终端1：启动靶场
python attack_upload.py     # 终端2：运行攻击

# 3. 代码审计 - 扫描漏洞
cd Level-4-CodeAudit
python audit_upload.py

# 4. 应急响应 - SSH 暴力破解检测
cd Level-5-EmergencyResponse/Class1
python ssh_brute_force_detector.py

# 5. 应急响应 - 勒索软件演练
cd Level-5-EmergencyResponse/Class2
pip install cryptography
python ransomware_response.py

# 6. 应急响应 - ATT&CK 攻击链分析
cd Level-5-EmergencyResponse/Class3
python attack_chain_mapper.py

# 7. 应急响应 - SOAR 自动化编排
cd Level-5-EmergencyResponse/Class4
pip install pyyaml
python soar_engine.py
```

## 📖 学习路线建议

### 第一阶段：Web 安全基础（1-2 周）

**目标**：理解 Web 漏洞原理，能复现常见攻击

1. **HTTP 协议**（第一节课）
   - 理解请求/响应结构、状态码、Cookie/Session
   - 运行 `http_basics.py`

2. **OWASP Top 10 漏洞**（第三、四、五课）
   - SQL 注入 → `sql_injection.py`、`login_sqli.py`
   - XSS → `xss_attack.py`、`stored_xss.py`
   - CSRF → `csrf.html`
   - 命令注入 → `command_injection.py`
   - 路径穿越 → `path_traversal.py`

3. **文件上传漏洞**（第六课）⭐
   - 运行 `vulnerable_app.py` 理解 4 种校验方式
   - 运行 `attack_upload.py` 学习 5 种绕过技术

### 第二阶段：代码审计（1 周）

**目标**：能从代码层面发现漏洞

1. **代码审计方法**（第七课）⭐
   - 运行 `audit_upload.py` 扫描项目
   - 理解危险模式和安全模式

### 第三阶段：应急响应（2-3 周）

**目标**：掌握安全事件的检测、分析、处置流程

1. **应急响应基础**（第一课）⭐
   - SSH 暴力破解检测 → `ssh_brute_force_detector.py`
   - 理解应急响应 6 阶段：检测→分析→抑制→取证→清除→报告

2. **深度取证**（第二课）⭐
   - 内存取证 → `Level-2-Advanced/memory_analyzer.py`
   - 勒索软件演练 → `ransomware_response.py`

3. **威胁狩猎**（第三课）⭐
   - ATT&CK 框架 → `attack_chain_mapper.py`
   - 理解攻击链重建

4. **SOAR 自动化**（第四课）⭐
   - 剧本编排 → `soar_engine.py`
   - 理解自动化应急响应

## 🎯 重点知识点

### Web 安全核心（必掌握）

| 漏洞类型 | 危害 | 防御方法 |
|---------|------|---------|
| SQL 注入 | 数据泄露/篡改 | 参数化查询、ORM |
| XSS | 窃取 Cookie/会话 | 输出转义、CSP |
| CSRF | 冒充用户操作 | CSRF Token |
| 文件上传 | RCE/GetShell | 白名单+内容检测 |
| 命令注入 | 服务器控制 | 避免拼接系统命令 |
| 路径穿越 | 读取任意文件 | 路径规范化 |

### 应急响应 6 阶段（必掌握）

```
检测(Detection) → 分析(Analysis) → 抑制(Containment) 
    → 取证(Forensics) → 清除(Eradication) → 报告(Reporting)
```

## 📝 学习建议

1. **先跑通代码**：每个脚本都先运行一遍，看输出
2. **改改参数**：修改 payload，观察不同效果
3. **看飞书文档**：代码配合飞书课程文档一起看
4. **做笔记**：记录每个漏洞的原理、利用、防御
5. **实践**：尝试在合法靶场（如 DVWA、WebGoat）练习

## 📄 License

MIT License
