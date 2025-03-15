import json
import os
import time
import re
from datetime import datetime
import logging
from collections import Counter

logger = logging.getLogger("adaptive_recon")

class ResultManager:
    def __init__(self, target, output_file=None):
        self.target = target
        self.output_file = output_file
        self.start_time = datetime.now()
        self.results = {
            "target": target,
            "start_time": self.start_time.strftime("%Y-%m-%d %H:%M:%S"),
            "ports": {},       # 端口 -> 状态
            "services": {},    # 端口 -> 服务
            "os_info": None,   # 操作系统信息
            "web_info": {},    # 端口 -> web信息
            "ssl_info": {},    # SSL/TLS信息
            "hosts": set(),    # 发现的主机列表
            "vulnerabilities": [],  # 发现的潜在漏洞
            "network_map": {}, # 网络映射信息
            "raw_results": []  # 原始扫描结果
        }
        
    def process_results(self, scan_results):
        """处理扫描结果，返回新发现的信息数量"""
        if not scan_results:
            return 0
            
        new_findings = 0
        for result in scan_results:
            # 保存原始结果
            if result not in self.results["raw_results"]:
                self.results["raw_results"].append(result)
                
            # 解析端口信息
            port_match = re.search(r'Port (\d+) is open', str(result))
            if port_match:
                port = int(port_match.group(1))
                if port not in self.results["ports"]:
                    self.results["ports"][port] = "open"
                    new_findings += 1
                    
            # 解析服务信息
            service_match = re.search(r'Service on port (\d+): (.+)', str(result))
            if service_match:
                port = int(service_match.group(1))
                service = service_match.group(2)
                if port not in self.results["services"] or self.results["services"][port] != service:
                    self.results["services"][port] = service
                    new_findings += 1
                    
            # 解析操作系统信息
            os_match = re.search(r'操作系统推测: (.+) \(基于TTL值: (.+)\)', str(result))
            if os_match:
                os_type = os_match.group(1)
                ttl = os_match.group(2)
                if self.results["os_info"] != os_type:
                    self.results["os_info"] = os_type
                    new_findings += 1
                    
            # 解析Web服务信息
            web_match = re.search(r'Web服务 \((\w+)\):(\d+) - 标题: (.+), 服务器: (.+)', str(result))
            if web_match:
                protocol = web_match.group(1)
                port = int(web_match.group(2))
                title = web_match.group(3)
                server = web_match.group(4)
                
                if port not in self.results["web_info"]:
                    self.results["web_info"][port] = {
                        "protocol": protocol,
                        "title": title,
                        "server": server
                    }
                    new_findings += 1
                    
            # 解析主机发现信息
            host_match = re.search(r'发现网络主机: (.+) \(MAC: (.+)\)', str(result))
            if host_match:
                host = host_match.group(1)
                mac = host_match.group(2)
                if host not in self.results["hosts"]:
                    self.results["hosts"].add(host)
                    new_findings += 1
                    
            # 解析SSL/TLS信息
            ssl_match = re.search(r'SSL\/TLS \((\d+)\): 版本 (.+), CN=(.+)', str(result))
            if ssl_match:
                port = int(ssl_match.group(1))
                version = ssl_match.group(2)
                cn = ssl_match.group(3)
                
                if port not in self.results["ssl_info"]:
                    self.results["ssl_info"][port] = {
                        "version": version,
                        "cn": cn,
                        "issues": []
                    }
                    new_findings += 1
                    
            # 检查SSL证书问题
            ssl_issue_match = re.search(r'SSL\/TLS \((\d+)\): (.+)', str(result))
            if ssl_issue_match and "版本" not in str(result):
                port = int(ssl_issue_match.group(1))
                issue = ssl_issue_match.group(2)
                
                if port in self.results["ssl_info"] and issue not in self.results["ssl_info"][port].get("issues", []):
                    if "issues" not in self.results["ssl_info"][port]:
                        self.results["ssl_info"][port]["issues"] = []
                    self.results["ssl_info"][port]["issues"].append(issue)
                    new_findings += 1
                    
            # 解析漏洞信息
            vuln_match = re.search(r'潜在漏洞: (.+)', str(result))
            if vuln_match:
                vuln = vuln_match.group(1)
                if vuln not in [v.get("description") for v in self.results["vulnerabilities"]]:
                    self.results["vulnerabilities"].append({
                        "description": vuln,
                        "detected_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    })
                    new_findings += 1
                    
            # 解析防火墙/WAF信息
            waf_match = re.search(r'检测到WAF: (.+) \((.+)\)', str(result))
            if waf_match:
                url = waf_match.group(1)
                waf_type = waf_match.group(2)
                
                # 添加到结果中
                found = False
                for web_info in self.results["web_info"].values():
                    if "waf" not in web_info and url.startswith(f"{web_info.get('protocol')}://"):
                        web_info["waf"] = waf_type
                        new_findings += 1
                        found = True
                        break
                
                if not found:
                    # 如果在现有Web信息中找不到对应的URL，创建一个新条目
                    port_match = re.search(r':(\d+)', url)
                    if port_match:
                        port = int(port_match.group(1))
                        if port not in self.results["web_info"]:
                            protocol = "https" if port == 443 else "http"
                            self.results["web_info"][port] = {
                                "protocol": protocol,
                                "title": "未知",
                                "server": "未知",
                                "waf": waf_type
                            }
                            new_findings += 1
        
        return new_findings
        
    def get_summary(self):
        """返回已收集信息的摘要"""
        duration = datetime.now() - self.start_time
        hours, remainder = divmod(duration.total_seconds(), 3600)
        minutes, seconds = divmod(remainder, 60)
        
        summary = [
            f"目标: {self.target}",
            f"扫描时长: {int(hours)}小时 {int(minutes)}分钟 {int(seconds)}秒",
            f"发现开放端口: {len(self.results['ports'])} 个"
        ]
        
        if self.results["ports"]:
            port_list = sorted(self.results["ports"].keys())
            summary.append(f"开放端口列表: {', '.join(map(str, port_list))}")
            
        if self.results["services"]:
            summary.append("服务检测结果:")
            for port, service in sorted(self.results["services"].items()):
                summary.append(f"  - 端口 {port}: {service}")
                
        if self.results["os_info"]:
            summary.append(f"操作系统: {self.results['os_info']}")
            
        if self.results["web_info"]:
            summary.append("Web服务:")
            for port, info in sorted(self.results["web_info"].items()):
                waf_info = f" [WAF: {info.get('waf')}]" if "waf" in info else ""
                summary.append(f"  - {info['protocol']}://{self.target}:{port} - {info['title']} ({info['server']}){waf_info}")
        
        if self.results["ssl_info"]:
            summary.append("SSL/TLS信息:")
            for port, info in sorted(self.results["ssl_info"].items()):
                issues = ", ".join(info.get("issues", [])) if info.get("issues") else "无问题"
                summary.append(f"  - 端口 {port}: {info['version']}, CN={info.get('cn', '未知')}, 问题: {issues}")
                
        if self.results["hosts"]:
            summary.append(f"发现网络主机: {len(self.results['hosts'])} 个")
            if len(self.results["hosts"]) <= 10:  # 只在主机数量不多时列出
                for host in sorted(self.results["hosts"]):
                    summary.append(f"  - {host}")
                    
        if self.results["vulnerabilities"]:
            summary.append(f"发现潜在漏洞: {len(self.results['vulnerabilities'])} 个")
            for vuln in self.results["vulnerabilities"][:5]:  # 只显示前5个
                summary.append(f"  - {vuln['description']}")
            
            if len(self.results["vulnerabilities"]) > 5:
                summary.append(f"  - ... 还有 {len(self.results['vulnerabilities']) - 5} 个漏洞 ...")
            
        return "\n".join(summary)
        
    def save_to_file(self):
        """保存结果到文件"""
        if not self.output_file:
            return
            
        # 将集合转换为列表以便序列化为JSON
        hosts_list = list(self.results["hosts"])
        
        # 创建可序列化的结果字典
        serializable_results = {
            "target": self.results["target"],
            "start_time": self.results["start_time"],
            "end_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ports": self.results["ports"],
            "services": self.results["services"],
            "os_info": self.results["os_info"],
            "web_info": self.results["web_info"],
            "ssl_info": self.results["ssl_info"],
            "hosts": hosts_list,
            "vulnerabilities": self.results["vulnerabilities"],
            "network_map": self.results["network_map"],
            "raw_results": self.results["raw_results"]
        }
        
        try:
            # 确保输出目录存在
            output_dir = os.path.dirname(os.path.abspath(self.output_file))
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
            
            # 保存摘要文本
            with open(self.output_file, 'w', encoding='utf-8') as f:
                f.write(self.get_summary())
                f.write("\n\n--- 原始扫描结果 ---\n")
                for result in self.results["raw_results"]:
                    f.write(f"{result}\n")
                
            # 同时保存一个JSON格式的详细结果
            json_file = f"{os.path.splitext(self.output_file)[0]}.json"
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(serializable_results, f, indent=2, ensure_ascii=False)
            
            # 尝试生成HTML报告    
            try:
                from report_generator import generate_html_report
                html_file = f"{os.path.splitext(self.output_file)[0]}.html"
                generate_html_report(serializable_results, html_file)
                logger.info(f"结果已保存至 {self.output_file}, {json_file} 和 {html_file}")
            except ImportError:
                logger.info(f"结果已保存至 {self.output_file} 和 {json_file}")
            except Exception as e:
                logger.warning(f"生成HTML报告时出错: {str(e)}")
                logger.info(f"结果已保存至 {self.output_file} 和 {json_file}")
                
        except Exception as e:
            logger.error(f"保存结果到文件时出错: {str(e)}")
