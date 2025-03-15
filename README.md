# Adaptive Recon - 自适应信息收集工具

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 项目简介

Adaptive Recon 是一个智能化的网络信息收集工具，能够根据目标系统的反应自动调整扫描策略。该工具采用先进的AI引擎，在保持高效信息收集的同时，能够有效降低被检测和阻止的风险。

### 主要特点

- **自适应扫描策略**: 根据目标反应实时调整扫描的激进性和隐蔽性
- **多种扫描模式**: 从激进到极度隐蔽的多种预设模式
- **AI决策引擎**: 智能分析目标反应并做出最佳决策
- **模块化设计**: 可扩展的模块系统，支持自定义扫描功能
- **全面的信息收集**: 端口扫描、服务检测、Web应用分析、漏洞识别等多种功能
- **交互式界面**: 提供命令行交互界面，方便操作和结果查看
- **详细报告生成**: 支持多种格式的扫描报告输出

## 安装指南

### 依赖要求

- Python 3.6+
- 相关Python库 (见requirements.txt)

### 安装步骤

1. 克隆代码库
```bash
git clone https://github.com/wavec99112/adaptive_recon.git
cd adaptive_recon
```

2. 安装依赖
```bash
pip install -r requirements.txt
```

3. 验证安装
```bash
python system_check.py
```

### Linux系统上的安装和运行

在Linux系统上，某些扫描功能（如SYN扫描）需要root权限，可以通过以下方式安装和运行：

1. 安装依赖（Ubuntu/Debian系统）
```bash
sudo apt-get update
sudo apt-get install python3-pip python3-dev libpcap-dev
sudo pip3 install -r requirements.txt
```

2. 使用root权限运行（获取完整功能）
```bash
sudo python3 main.py -t <target> -m <mode> -o <output_file>
```

3. 不使用root权限（部分功能受限）
```bash
python3 main.py -t <target> -m <mode> -o <output_file> 
```

注意：在非root权限下，将无法使用SYN扫描等需要原始套接字访问的功能，工具会自动降级为使用连接扫描等替代方法。

4. 如果使用tor进行匿名扫描，需先安装并启动tor服务
```bash
sudo apt-get install tor
sudo service tor start
python3 main.py -t <target> -m ultra_stealth -o <output_file>
```

## 使用说明

### 命令行模式

#### 基本用法
```bash
python main.py -t <target> -m <mode> -o <output_file>
```

#### 参数说明
- `-t, --target`: 目标主机或网络 (如: example.com 或 192.168.1.0/24)
- `-m, --mode`: 扫描模式，可选值:
  - `aggressive`: 激进模式，速度快但易被检测
  - `stealth`: 隐蔽模式，采取更谨慎的扫描方式
  - `smart`: 智能模式(默认)，自动平衡速度和隐蔽性
  - `low_noise`: 低噪音模式，主要针对Web应用进行轻量级扫描
  - `ultra_stealth`: 极度隐蔽模式，牺牲速度和深度换取最低检测率
  - `custom`: 自定义模式，在交互式界面中可配置
- `-o, --output`: 输出结果文件路径
- `-v, --verbose`: 显示详细信息
- `-s, --summary-interval`: 结果总结显示间隔(秒)，默认120秒
- `-p, --passive`: 启用被动信息收集模式，不进行主动探测
- `-i, --interactive`: 显式启动交互式界面
- `--log-file`: 指定日志文件路径

### 交互式模式

启动交互界面:
```bash
python main.py -i
```

或者直接运行(无参数会默认启动交互界面):
```bash
python main.py
```

#### 交互式界面功能

1. **主菜单**
   - 开始新扫描
   - 查看扫描结果
   - 设置
   - 关于
   - 退出

2. **扫描设置**
   - 选择扫描目标
   - 选择扫描模式
   - 配置自定义扫描模块
   - 启用/禁用被动模式

3. **扫描结果查看**
   - 端口详细信息
   - Web服务详细信息
   - 漏洞详细信息
   - 导出扫描结果

### 扫描模式详解

1. **激进模式 (aggressive)**
   - 使用SYN扫描和多种主动扫描技术
   - 扫描范围广，速度快
   - 容易被IDS/IPS检测
   - 适合非敏感环境

2. **隐蔽模式 (stealth)**
   - 使用NULL扫描等更难被检测的方法
   - 较长的扫描延迟和随机化
   - 减少触发IDS/IPS的可能性
   - 适合对安全敏感的环境

3. **智能模式 (smart)**
   - 平衡速度和隐蔽性
   - 根据目标反应自动调整策略
   - 适合大多数场景

4. **低噪音模式 (low_noise)**
   - 仅扫描Web相关端口和服务
   - 尝试模拟合法用户流量
   - 适合Web应用测试

5. **极度隐蔽模式 (ultra_stealth)**
   - 最小化被检测风险
   - 速度非常慢，扫描范围有限
   - 适合高度安全的环境

### 可用扫描模块

1. **端口扫描 (port_scan)**
   - 检测目标开放的网络端口

2. **服务检测 (service_detection)**
   - 识别端口上运行的服务和版本

3. **操作系统检测 (os_detection)**
   - 推测目标系统的操作系统类型

4. **Web服务探测 (web_discovery)**
   - 识别和分析Web应用

5. **主机发现 (host_discovery)**
   - 在网络中发现活跃主机

6. **漏洞扫描 (vuln_scan)**
   - 检测可能的安全漏洞

7. **SSL/TLS扫描 (ssl_scan)**
   - 分析SSL/TLS配置和证书

8. **DNS枚举 (dns_enum)**
   - 发现子域名和DNS信息

9. **防火墙检测 (firewall_detection)**
   - 分析是否存在防火墙或WAF

10. **Web目录扫描 (web_directory_scan)**
    - 发现Web服务器上的目录和文件

11. **CMS识别 (cms_scan)**
    - 识别内容管理系统及其版本

12. **子域名枚举 (subdomain_enum)**
    - 发现与目标相关的子域名

13. **技术栈识别 (tech_detection)**
    - 识别Web应用使用的技术栈

14. **信息泄露检测 (info_disclosure)**
    - 发现可能泄露敏感信息的内容

### 常见使用场景

#### 1. 基本信息收集
```bash
python main.py -t example.com -m smart -o results.txt
```

#### 2. Web应用安全测试
```bash
python main.py -t example.com -m low_noise -o web_results.txt
```

#### 3. 隐蔽模式扫描
```bash
python main.py -t 192.168.1.1 -m stealth -v
```

#### 4. 被动信息收集
```bash
python main.py -t example.com -p -o passive_results.txt
```

#### 5. 内网扫描
```bash
python main.py -t 192.168.1.0/24 -m aggressive -o network_scan.txt
```

#### 6. 自动生成HTML报告
```bash
python main.py -t example.com -o report.txt
```
此命令会同时生成report.txt(文本报告)、report.json(JSON格式数据)和report.html(HTML格式报告)

## 系统检查

运行系统检查工具来验证所有组件是否正常工作:
```bash
python system_check.py
```

## 贡献指南

欢迎贡献代码、报告问题或提出改进建议。请遵循以下步骤:

1. Fork 项目仓库
2. 创建功能分支 (git checkout -b feature/amazing-feature)
3. 提交更改 (git commit -m 'Add amazing feature')
4. 推送到分支 (git push origin feature/amazing-feature)
5. 创建 Pull Request

## 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE.md) 文件

## 联系方式

- 作者: Wave-C9
- GitHub: [https://github.com/wavec99112](https://github.com/wavec99112)

## 免责声明

本工具仅供安全研究和授权渗透测试使用。使用本工具进行未经授权的扫描或测试是违法的，可能导致法律责任。使用者需自行承担使用本工具的一切后果。
