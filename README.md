# Web-Security-Learning 🔐

> 网络安全学习项目 - 基于 Datawhale 网安课程，按课程安排分类，包含 Web 安全、应急响应两大方向

## 📚 课程体系

按飞书课程文档安排，分为 **Web 安全** 和 **应急响应** 两大方向。

### 🌐 Web 安全方向（攻击视角）

| 课次 | 主题 | 代码目录 | 学习状态 |
|------|------|----------|----------|
| 第一课 | HTTP 协议基础、Cookie/Session | `Web安全/01-HTTP协议基础/` | ✅ |
| 第三课 | CSRF 攻击及防御 | `Web安全/03-CSRF攻击/` | ✅ |
| 第四课 | XSS 攻击及防御 | `Web安全/04-XSS攻击/` | ✅ |
| 第五课 | SQL注入、命令注入、路径穿越 | `Web安全/05-漏洞利用(SQL注入-命令注入-路径穿越)/` | ✅ |
| 第六课 | 文件上传漏洞原理与利用 | `Web安全/06-文件上传漏洞/` | ✅ |
| 第七课 | 代码审计发现文件上传漏洞 | `Web安全/07-代码审计/` | ✅ |

### 🛡️ 应急响应方向（防守视角）

| 课次 | 主题 | 代码目录 | 学习状态 |
|------|------|----------|----------|
| 第一课 | 应急响应基础（检测/分析/抑制/取证/清除/报告） | `应急响应/01-应急响应基础/` | ✅ |
| 第二课 | 深度取证与云环境响应（内存取证/勒索软件） | `应急响应/02-深度取证与云环境响应/` | ✅ |
| 第三课 | 高级威胁狩猎与溯源（ATT&CK/威胁情报/EDR） | `应急响应/03-高级威胁狩猎与溯源/` | ✅ |
| 第四课 | 自动化编排与应急响应平台（SOAR） | `应急响应/04-自动化编排与SOAR平台/` | ✅ |

## 📁 项目结构

```
Web-Security-Learning/
├── Web安全/                              # Web安全方向（攻击视角）
│   ├── 01-HTTP协议基础/
│   │   ├── app.py                        # Flask 漏洞演示应用（靶场）
│   │   └── http_basics.py                # HTTP 协议基础
│   ├── 03-CSRF攻击/
│   │   └── csrf.html                     # CSRF 攻击演示页面
│   ├── 04-XSS攻击/
│   │   ├── xss_attack.py                 # 反射型 XSS 攻击
│   │   └── stored_xss.py                 # 存储型 XSS 攻击
│   ├── 05-漏洞利用(SQL注入-命令注入-路径穿越)/
│   │   ├── sql_injection.py              # SQL 注入攻击
│   │   ├── login_sqli.py                 # 登录绕过
│   │   ├── command_injection.py          # 命令注入
│   │   ├── path_traversal.py             # 路径穿越
│   │   └── test.py                       # 测试脚本
│   ├── 06-文件上传漏洞/
│   │   ├── vulnerable_app.py             # 文件上传漏洞靶场（4种校验）
│   │   └── attack_upload.py              # 5种上传绕过攻击
│   └── 07-代码审计/
│       └── audit_upload.py               # 代码审计工具
│
├── 应急响应/                              # 应急响应方向（防守视角）
│   ├── 01-应急响应基础/
│   │   └── ssh_brute_force_detector.py   # SSH 暴力破解检测器
│   ├── 02-深度取证与云环境响应/
│   │   ├── memory_analyzer.py            # 内存取证分析工具
│   │   ├── ransomware_response.py        # 勒索软件模拟与解密
│   │   ├── memory_analysis_*/            # 内存分析报告
│   │   └── reports/                      # 分析报告
│   ├── 03-高级威胁狩猎与溯源/
│   │   └── attack_chain_mapper.py        # ATT&CK 攻击链映射器
│   └── 04-自动化编排与SOAR平台/
│       └── soar_engine.py                # SOAR 剧本编排引擎
│
├── README.md
├── LICENSE
└── .gitignore
```

## 🚀 快速开始

### 环境准备

```bash
pip install flask requests cryptography volatility3
```

### Web 安全学习顺序

1. **启动靶场**：`cd Web安全/01-HTTP协议基础 && python app.py`
2. **HTTP 基础**：`python http_basics.py`
3. **SQL 注入**：`cd ../05-漏洞利用* && python sql_injection.py`
4. **XSS 攻击**：`cd ../04-XSS攻击 && python xss_attack.py`
5. **文件上传**：`cd ../06-文件上传漏洞 && python vulnerable_app.py`（另开终端运行 `attack_upload.py`）
6. **代码审计**：`cd ../07-代码审计 && python audit_upload.py`

### 应急响应学习顺序

1. **暴力破解检测**：`cd 应急响应/01-应急响应基础 && python ssh_brute_force_detector.py`
2. **勒索软件演练**：`cd ../02-深度取证与云环境响应 && python ransomware_response.py`
3. **ATT&CK 映射**：`cd ../03-高级威胁狩猎与溯源 && python attack_chain_mapper.py`
4. **SOAR 编排**：`cd ../04-自动化编排与SOAR平台 && python soar_engine.py`

## 🎯 学习路线建议

### 第一阶段：Web 安全基础（1-2周）

**目标**：理解常见 Web 漏洞原理，能复现攻击

1. **HTTP 协议**（第一课）→ 理解请求/响应、Cookie/Session
2. **OWASP Top 10**（第三、四、五课）→ SQL注入、XSS、CSRF、命令注入、路径穿越
3. **文件上传漏洞**（第六课）→ 4种校验 + 5种绕过

### 第二阶段：代码审计（1周）

**目标**：能从代码层面发现漏洞

1. **代码审计方法**（第七课）→ 运行 `audit_upload.py` 扫描项目

### 第三阶段：应急响应（2-3周）

**目标**：掌握安全事件的检测、分析、处置流程

1. **应急响应基础**（第一课）→ SSH 暴力破解检测，理解 6 阶段
2. **深度取证**（第二课）→ 内存取证、勒索软件演练
3. **威胁狩猎**（第三课）→ ATT&CK 框架、攻击链重建
4. **SOAR 自动化**（第四课）→ 剧本编排、自动化响应

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

1. **先跑通代码**：每个脚本先运行一遍，看输出
2. **改改参数**：修改 payload，观察不同效果
3. **看飞书文档**：代码配合飞书课程文档一起看
4. **做笔记**：记录每个漏洞的原理、利用、防御
5. **实践**：尝试在合法靶场（如 DVWA、WebGoat）练习

## 📄 License

MIT License
