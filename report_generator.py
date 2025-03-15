import os
import json
from datetime import datetime
import logging

logger = logging.getLogger("adaptive_recon")

# HTML报告模板
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>信息收集报告: {{TARGET}}</title>
    <style>
        body {
            font-family: 'Arial', sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            border-radius: 5px;
        }
        .header {
            background: #2C3E50;
            color: white;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 5px 5px 0 0;
        }
        h1, h2, h3 {
            margin-top: 0;
        }
        .section {
            margin-bottom: 30px;
            border-bottom: 1px solid #eee;
            padding-bottom: 20px;
        }
        .footer {
            text-align: center;
            margin-top: 30px;
            font-size: 0.8em;
            color: #777;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #2C3E50;
            color: white;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .badge {
            padding: 5px 10px;
            border-radius: 3px;
            color: white;
            font-size: 0.8em;
            font-weight: bold;
        }
        .badge-high {
            background-color: #e74c3c;
        }
        .badge-medium {
            background-color: #f39c12;
        }
        .badge-low {
            background-color: #3498db;
        }
        .badge-info {
            background-color: #2ecc71;
        }
        .chart-container {
            width: 100%;
            height: 400px;
        }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>自适应信息收集报告</h1>
            <p>目标: {{TARGET}}</p>
        </div>
        
        <div class="section">
            <h2>扫描概览</h2>
            <p>开始时间: {{START_TIME}}</p>
            <p>结束时间: {{END_TIME}}</p>
            <p>总扫描时长: {{DURATION}}</p>
            <p>目标操作系统: {{OS_INFO}}</p>
        </div>
        
        <div class="section">
            <h2>开放端口与服务</h2>
            <p>共发现 {{PORT_COUNT}} 个开放端口</p>
            <table>
                <thead>
                    <tr>
                        <th>端口</th>
                        <th>状态</th>
                        <th>服务</th>
                    </tr>
                </thead>
                <tbody>
                    {{PORT_SERVICES_ROWS}}
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>Web服务信息</h2>
            <table>
                <thead>
                    <tr>
                        <th>端口</th>
                        <th>协议</th>
                        <th>标题</th>
                        <th>服务器</th>
                        <th>WAF/防护</th>
                    </tr>
                </thead>
                <tbody>
                    {{WEB_SERVICES_ROWS}}
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>SSL/TLS 信息</h2>
            <table>
                <thead>
                    <tr>
                        <th>端口</th>
                        <th>版本</th>
                        <th>通用名称</th>
                        <th>问题</th>
                    </tr>
                </thead>
                <tbody>
                    {{SSL_INFO_ROWS}}
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>漏洞信息</h2>
            <canvas id="vulnChart" style="height:300px;"></canvas>
            <table>
                <thead>
                    <tr>
                        <th>漏洞类型</th>
                        <th>严重性</th>
                        <th>描述</th>
                    </tr>
                </thead>
                <tbody>
                    {{VULNERABILITY_ROWS}}
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>网络主机</h2>
            <p>共发现 {{HOST_COUNT}} 个网络主机</p>
            <table>
                <thead>
                    <tr>
                        <th>IP地址</th>
                    </tr>
                </thead>
                <tbody>
                    {{HOSTS_ROWS}}
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            <p>由自适应信息收集工具生成 - {{GENERATION_TIME}}</p>
        </div>
    </div>
    
    <script>
        // 漏洞分布饼图
        var ctx = document.getElementById('vulnChart').getContext('2d');
        var vulnChart = new Chart(ctx, {
            type: 'pie',
            data: {
                labels: {{VULN_TYPES}},
                datasets: [{
                    label: '漏洞类型',
                    data: {{VULN_COUNTS}},
                    backgroundColor: [
                        '#e74c3c',  // 高危
                        '#f39c12',  // 中危
                        '#3498db',  // 低危
                        '#2ecc71',  // 信息
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'top',
                    },
                    title: {
                        display: true,
                        text: '漏洞严重性分布'
                    }
                }
            }
        });
    </script>
</body>
</html>
"""

def generate_html_report(data, output_file):
    """生成HTML格式的报告"""
    try:
        # 计算扫描时长
        start_time = datetime.strptime(data["start_time"], "%Y-%m-%d %H:%M:%S")
        end_time = datetime.strptime(data["end_time"], "%Y-%m-%d %H:%M:%S")
        duration = end_time - start_time
        hours, remainder = divmod(duration.total_seconds(), 3600)
        minutes, seconds = divmod(remainder, 60)
        duration_str = f"{int(hours)}小时 {int(minutes)}分钟 {int(seconds)}秒"
        
        # 准备端口和服务表格内容
        port_services_rows = ""
        for port, status in sorted(data["ports"].items(), key=lambda x: int(x[0]) if isinstance(x[0], (int, str)) else 0):
            service = data["services"].get(str(port), "未知")
            port_services_rows += f"<tr><td>{port}</td><td>{status}</td><td>{service}</td></tr>"
            
        # 准备Web服务表格内容
        web_services_rows = ""
        for port, info in sorted(data["web_info"].items(), key=lambda x: int(x[0]) if isinstance(x[0], (int, str)) else 0):
            protocol = info.get("protocol", "http")
            title = info.get("title", "未知")
            server = info.get("server", "未知")
            waf = info.get("waf", "未检测到")
            web_services_rows += f"<tr><td>{port}</td><td>{protocol}</td><td>{title}</td><td>{server}</td><td>{waf}</td></tr>"
            
        # 准备SSL/TLS信息表格内容
        ssl_info_rows = ""
        if data.get("ssl_info"):
            for port, info in sorted(data["ssl_info"].items(), key=lambda x: int(x[0]) if isinstance(x[0], (int, str)) else 0):
                version = info.get("version", "未知")
                cn = info.get("cn", "未知")
                issues = ", ".join(info.get("issues", [])) if info.get("issues") else "无问题"
                ssl_info_rows += f"<tr><td>{port}</td><td>{version}</td><td>{cn}</td><td>{issues}</td></tr>"
        
        if not ssl_info_rows:
            ssl_info_rows = "<tr><td colspan='4'>未检测到SSL/TLS信息</td></tr>"
            
        # 准备漏洞信息表格内容
        vulnerability_rows = ""
        vuln_types = []
        vuln_counts = []
        
        # 漏洞统计
        vuln_severity_count = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
        
        if data.get("vulnerabilities"):
            for vuln in data.get("vulnerabilities", []):
                severity = vuln.get("severity", "Medium")
                vuln_severity_count[severity] = vuln_severity_count.get(severity, 0) + 1
                
                badge_class = ""
                if severity == "High" or severity == "Critical":
                    badge_class = "badge-high"
                elif severity == "Medium":
                    badge_class = "badge-medium"
                elif severity == "Low":
                    badge_class = "badge-low"
                else:
                    badge_class = "badge-info"
                    
                vuln_type = vuln.get("type", "未知")
                description = vuln.get("description", vuln.get("details", "未知"))
                
                vulnerability_rows += f"""
                <tr>
                    <td>{vuln_type}</td>
                    <td><span class="badge {badge_class}">{severity}</span></td>
                    <td>{description}</td>
                </tr>
                """
        
        if not vulnerability_rows:
            vulnerability_rows = "<tr><td colspan='3'>未发现漏洞</td></tr>"
            
        # 准备漏洞图表数据
        for severity, count in sorted(vuln_severity_count.items()):
            if count > 0:
                vuln_types.append(f"'{severity}'")
                vuln_counts.append(count)
                
        if not vuln_types:
            vuln_types = ["'无漏洞'"]
            vuln_counts = [1]
                
        # 准备主机列表
        hosts_rows = ""
        if data.get("hosts"):
            for host in sorted(data.get("hosts", [])):
                hosts_rows += f"<tr><td>{host}</td></tr>"
        
        if not hosts_rows:
            hosts_rows = "<tr><td>未发现其他主机</td></tr>"
            
        # 替换模板变量，确保所有替换值都是字符串
        html_content = HTML_TEMPLATE
        replacements = {
            "{{TARGET}}": str(data["target"]),
            "{{START_TIME}}": str(data["start_time"]),
            "{{END_TIME}}": str(data["end_time"]),
            "{{DURATION}}": str(duration_str),
            "{{OS_INFO}}": str(data.get("os_info", "未知")),
            "{{PORT_COUNT}}": str(len(data["ports"])),
            "{{PORT_SERVICES_ROWS}}": str(port_services_rows),
            "{{WEB_SERVICES_ROWS}}": str(web_services_rows),
            "{{SSL_INFO_ROWS}}": str(ssl_info_rows),
            "{{VULNERABILITY_ROWS}}": str(vulnerability_rows),
            "{{HOST_COUNT}}": str(len(data.get("hosts", []))),
            "{{HOSTS_ROWS}}": str(hosts_rows),
            "{{GENERATION_TIME}}": str(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            "{{VULN_TYPES}}": "[" + ", ".join(vuln_types) + "]",
            "{{VULN_COUNTS}}": str(vuln_counts)
        }
        
        for key, value in replacements.items():
            if value is None:
                html_content = html_content.replace(key, "未知")
            else:
                html_content = html_content.replace(key, value)
            
        # 写入HTML文件
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        logger.info(f"已生成HTML报告: {output_file}")
        return True
    except Exception as e:
        logger.error(f"生成HTML报告时出错: {str(e)}")
        return False

def generate_pdf_report(data, output_file):
    """生成PDF格式的报告（需要额外依赖）"""
    try:
        import pdfkit
        
        # 首先生成HTML报告
        html_file = output_file.replace('.pdf', '.html')
        if generate_html_report(data, html_file):
            # 使用pdfkit将HTML转换为PDF
            pdfkit.from_file(html_file, output_file)
            logger.info(f"已生成PDF报告: {output_file}")
            return True
        return False
    except ImportError:
        logger.warning("未安装pdfkit，无法生成PDF报告。请安装: pip install pdfkit")
        return False
    except Exception as e:
        logger.error(f"生成PDF报告时出错: {str(e)}")
        return False
