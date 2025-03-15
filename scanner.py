import socket
import subprocess
import random
import logging
import time
import re
import requests
import ssl
import struct
import threading
import warnings
from urllib.parse import urlparse

# 抑制scapy的警告信息
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import IP, TCP, UDP, ICMP, sr1, send, RandShort, ARP, Ether, srp, fragment, conf
from concurrent.futures import ThreadPoolExecutor
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# 禁用SSL警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger("adaptive_recon")

# 导入模块监视器
try:
    from module_monitor import ModuleMonitor
    HAS_MODULE_MONITOR = True
except ImportError:
    HAS_MODULE_MONITOR = False
    logger.warning("模块监视器不可用，无法监控模块使用情况")

# 导入 OpenSSL 库
try:
    import OpenSSL
    HAS_OPENSSL = True
except ImportError:
    HAS_OPENSSL = False
    logger.warning("未安装pyOpenSSL库，SSL扫描功能受限")

class Scanner:
    def __init__(self, target, strategy_manager, passive_mode=False):
        self.target = target
        self.strategy_manager = strategy_manager
        self.passive_mode = passive_mode  # 添加被动模式参数
        self.discovered_ports = set()
        self.discovered_services = {}
        self.os_info = None
        self.detection_count = 0
        self.web_info = {}  # 存储Web服务相关信息
        self.hosts_in_network = set()  # 存储网络中的主机
        self.vulnerabilities = []  # 存储发现的漏洞
        self.ssl_info = {}  # 存储SSL/TLS信息
        self.max_workers = 5  # 最大线程数
        self.evasion_techniques = {
            "packet_fragmentation": False,
            "decoys": [],
            "timing_control": "normal",
            "ip_spoofing": False
        }
        self.wordlists = {
            "directories": ["admin", "wp-admin", "admin_area", "backend", "cms", "panel", 
                           "config", "backup", "bak", "old", "db", "sql", "test", "dev", "temp",
                           "upload", "uploads", "files", "private", "admin_panel", "administrator",
                           "login", "manager", "management", "user", "users", "account", "auth", 
                           "dashboard", "cp", "portal", "site", "blog", "webmail", "mail", "email",
                           "api", "v1", "v2", "console", "phpmyadmin", "mysql", "myadmin", "pma"],
            "subdomains": ["www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", 
                          "smtp", "secure", "vpn", "m", "shop", "ftp", "api", "dev", "staging",
                          "app", "test", "portal", "admin", "cdn", "cloud", "images", "img"]
        }
        self.cve_database = self._load_cve_database()
        self.common_passwords = ["password", "123456", "admin", "root", "qwerty"]
        
        # 配置scapy默认不显示警告
        conf.verb = 0  # 禁止scapy显示详细输出
        
        # 初始化模块监视器
        self.module_monitor = ModuleMonitor() if HAS_MODULE_MONITOR else None
        self.scan_count = 0
        
    def scan(self):
        """执行扫描并返回结果"""
        strategy = self.strategy_manager.current_strategy
        results = []
        unsuccessful_modules = []
        
        try:
            # 如果启用了被动模式，则禁用主动扫描模块
            active_modules = strategy["enabled_modules"] if not self.passive_mode else [
                m for m in strategy["enabled_modules"] 
                if m in ["web_discovery", "ssl_scan", "tech_detection"]
            ]
            
            # 检查target是否可用
            if not self._check_target_availability():
                logger.warning(f"目标 {self.target} 不可达，部分模块可能无法执行")
                
            # 使用模块监控，初始化扫描计数
            if not hasattr(self, 'scan_count'):
                self.scan_count = 0
            self.scan_count += 1
            
            # 端口扫描模块
            if "port_scan" in active_modules:
                start_time = time.time()
                try:
                    port_results = self._port_scan(
                        strategy["port_scan_type"],
                        strategy["port_range"],
                        strategy["scan_delay"]
                    )
                    execution_time = time.time() - start_time
                    
                    # 记录模块执行情况
                    if self.module_monitor:
                        self.module_monitor.register_module_call(
                            "port_scan", 
                            success=len(port_results) > 0, 
                            execution_time=execution_time
                        )
                    
                    results.extend(port_results)
                except Exception as e:
                    logger.debug(f"端口扫描模块执行失败: {str(e)}")
                    unsuccessful_modules.append("port_scan")
                    if self.module_monitor:
                        self.module_monitor.register_module_call("port_scan", success=False, execution_time=0)
                    
            # 服务检测模块
            if "service_detection" in active_modules:
                start_time = time.time()
                try:
                    service_results = self._service_detection(strategy["probe_timeout"])
                    execution_time = time.time() - start_time
                    
                    if self.module_monitor:
                        self.module_monitor.register_module_call(
                            "service_detection", 
                            success=len(service_results) > 0, 
                            execution_time=execution_time
                        )
                        
                    results.extend(service_results)
                except Exception as e:
                    logger.debug(f"服务检测模块执行失败: {str(e)}")
                    unsuccessful_modules.append("service_detection")
                    if self.module_monitor:
                        self.module_monitor.register_module_call("service_detection", success=False, execution_time=0)
                    
            # 操作系统检测模块
            if "os_detection" in active_modules:
                start_time = time.time()
                try:
                    os_results = self._os_detection(strategy["ttl_probe_count"])
                    execution_time = time.time() - start_time
                    
                    if self.module_monitor:
                        self.module_monitor.register_module_call(
                            "os_detection", 
                            success=os_results is not None, 
                            execution_time=execution_time
                        )
                        
                    if os_results:
                        results.append(os_results)
                except Exception as e:
                    logger.debug(f"操作系统检测模块执行失败: {str(e)}")
                    unsuccessful_modules.append("os_detection")
                    if self.module_monitor:
                        self.module_monitor.register_module_call("os_detection", success=False, execution_time=0)
                        
            # 添加Web服务探测模块监控
            if "web_discovery" in active_modules:
                start_time = time.time()
                try:
                    web_results = self._web_discovery()
                    execution_time = time.time() - start_time
                    
                    if self.module_monitor:
                        self.module_monitor.register_module_call(
                            "web_discovery", 
                            success=len(web_results) > 0, 
                            execution_time=execution_time
                        )
                        
                    results.extend(web_results)
                except Exception as e:
                    logger.debug(f"Web服务探测模块执行失败: {str(e)}")
                    unsuccessful_modules.append("web_discovery")
                    if self.module_monitor:
                        self.module_monitor.register_module_call("web_discovery", success=False, execution_time=0)
                        
            # 其他模块也添加类似的监控代码...
            # 例如:
            if "host_discovery" in active_modules:
                start_time = time.time()
                try:
                    host_results = self._host_discovery()
                    execution_time = time.time() - start_time
                    
                    if self.module_monitor:
                        self.module_monitor.register_module_call(
                            "host_discovery", 
                            success=len(host_results) > 0, 
                            execution_time=execution_time
                        )
                        
                    results.extend(host_results)
                except Exception as e:
                    logger.debug(f"主机发现模块执行失败: {str(e)}")
                    unsuccessful_modules.append("host_discovery")
                    if self.module_monitor:
                        self.module_monitor.register_module_call("host_discovery", success=False, execution_time=0)
                        
            # 确保XSS和SQL注入扫描正确集成
            if "vuln_scan" in active_modules:
                start_time = time.time()
                try:
                    vuln_results = self._vuln_scan()
                    execution_time = time.time() - start_time
                    
                    if self.module_monitor:
                        self.module_monitor.register_module_call(
                            "vuln_scan", 
                            success=len(vuln_results) > 0, 
                            execution_time=execution_time
                        )
                        
                    results.extend(vuln_results)
                except Exception as e:
                    logger.debug(f"漏洞扫描模块执行失败: {str(e)}")
                    unsuccessful_modules.append("vuln_scan")
                    if self.module_monitor:
                        self.module_monitor.register_module_call("vuln_scan", success=False, execution_time=0)
                
            # 定期检查模块集成情况
            if self.module_monitor:
                if self.scan_count % 10 == 0:  # 每10次扫描检查一次
                    unsuccessful_count = len(unsuccessful_modules)
                    if unsuccessful_count > 0:
                        logger.warning(f"本次扫描中 {unsuccessful_count} 个模块执行失败: {', '.join(unsuccessful_modules)}")
                    self.module_monitor.check_module_integration(strategy, self.passive_mode)
                    logger.debug(self.module_monitor.generate_report())
            
        except Exception as e:
            logger.debug(f"扫描过程中出现异常: {str(e)}")
            self.detection_count += 1
            # 记录可能被检测的事件
            self.strategy_manager.register_detection_event()
            
        return results
    
    def _check_target_availability(self):
        """检查目标是否可达"""
        try:
            # 简单的连接测试
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            
            # 尝试连接常用端口
            for port in [80, 443]:
                result = s.connect_ex((self.target, port))
                if result == 0:
                    s.close()
                    return True
                    
            # 如果常用端口都连不上，尝试ping
            try:
                from scapy.all import IP, ICMP, sr1
                packet = IP(dst=self.target)/ICMP()
                response = sr1(packet, timeout=2, verbose=0)
                if response:
                    return True
            except:
                pass
                
            return False
        except:
            return False

    def _port_scan(self, scan_type, port_range, delay):
        results = []
        logger.debug(f"使用{scan_type}方式扫描端口")
        
        ports_to_scan = self._get_ports_to_scan(port_range)
        
        for port in ports_to_scan:
            try:
                # 根据不同扫描类型执行不同的扫描方法
                if scan_type == "syn":
                    result = self._syn_scan(port)
                elif scan_type == "connect":
                    result = self._connect_scan(port)
                elif scan_type == "null":
                    result = self._null_scan(port)
                else:
                    result = self._connect_scan(port)  # 默认使用connect扫描
                
                if result and port not in self.discovered_ports:
                    self.discovered_ports.add(port)
                    results.append(f"Port {port} is open")
                
                # 按策略添加延迟
                time.sleep(delay)
                
            except Exception as e:
                logger.debug(f"扫描端口 {port} 时出错: {str(e)}")
                
        return results
    
    def _syn_scan(self, port):
        """SYN扫描 - 发送SYN包，如果收到SYN/ACK则端口开放"""
        try:
            packet = IP(dst=self.target)/TCP(dport=port, flags="S", seq=RandShort())
            response = sr1(packet, timeout=1, verbose=0)
            if response and response.haslayer(TCP) and response.getlayer(TCP).flags & 0x12:
                return True
            return False
        except:
            return False
    
    def _connect_scan(self, port):
        """Connect扫描 - 尝试建立完整TCP连接"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((self.target, port))
            s.close()
            return result == 0
        except:
            return False
    
    def _null_scan(self, port):
        """NULL扫描 - 发送不带任何标志的TCP包"""
        try:
            packet = IP(dst=self.target)/TCP(dport=port, flags="")
            response = sr1(packet, timeout=1, verbose=0)
            # 如果没有回应或收到RST，则可能端口是开放的
            return response is None
        except:
            return False
    
    def _service_detection(self, timeout):
        results = []
        for port in self.discovered_ports:
            if port in self.discovered_services:
                continue
                
            try:
                service = self._identify_service(port, timeout)
                if service:
                    self.discovered_services[port] = service
                    results.append(f"Service on port {port}: {service}")
            except Exception as e:
                logger.debug(f"识别端口 {port} 上的服务时出错: {str(e)}")
                
        return results
    
    def _identify_service(self, port, timeout):
        """尝试识别端口上运行的服务"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((self.target, port))
            
            # 发送一些常见协议的问询
            probes = [
                b"\r\n",  # HTTP, SMTP等
                b"HEAD / HTTP/1.0\r\n\r\n",  # HTTP
                b"SSH-2.0-OpenSSH_7.6p1\r\n",  # SSH
            ]
            
            for probe in probes:
                try:
                    s.send(probe)
                    banner = s.recv(1024)
                    s.close()
                    
                    banner_str = banner.decode('utf-8', errors='ignore').strip()
                    
                    # 简单的服务识别逻辑
                    if "HTTP" in banner_str:
                        return "HTTP"
                    elif "SSH" in banner_str:
                        return "SSH"
                    elif "FTP" in banner_str:
                        return "FTP"
                    elif "SMTP" in banner_str:
                        return "SMTP"
                    else:
                        return f"Unknown ({banner_str[:20]})"
                except:
                    continue
                    
            return "Unknown"
        except:
            return None
    
    def _os_detection(self, probe_count):
        if self.os_info:
            return None
            
        ttl_values = []
        
        # 发送ICMP echo请求，分析TTL值推断操作系统
        for _ in range(probe_count):
            try:
                packet = IP(dst=self.target)/ICMP()
                response = sr1(packet, timeout=1, verbose=0)
                if response and response.haslayer(IP):
                    ttl_values.append(response.ttl)
                    
                # 添加随机延迟，避免触发IDS/IPS
                time.sleep(random.uniform(0.1, 0.3))
            except Exception as e:
                logger.debug(f"OS探测过程中出错: {str(e)}")
        
        if ttl_values:
            avg_ttl = sum(ttl_values) / len(ttl_values)
            os_guess = self._guess_os_from_ttl(avg_ttl)
            self.os_info = os_guess
            return f"操作系统推测: {os_guess} (基于TTL值: {avg_ttl})"
            
        return None
    
    def _guess_os_from_ttl(self, ttl):
        """根据TTL值推测操作系统类型"""
        if ttl <= 64:
            return "Linux/Unix类系统"
        elif ttl <= 128:
            return "Windows系统"
        else:
            return "其他系统(可能为网络设备)"
            
    def _get_ports_to_scan(self, port_range):
        """根据策略决定要扫描的端口"""
        if isinstance(port_range, list) and len(port_range) == 2:
            start, end = port_range
            # 随机选择部分端口扫描，减少被检测几率
            port_count = min(100, end - start + 1)  # 最多扫描100个端口
            return random.sample(range(start, end + 1), port_count)
        elif isinstance(port_range, list):
            # 如果是具体的端口列表，则使用这个列表
            return port_range
        else:
            # 默认扫描常用端口
            return [21, 22, 23, 25, 80, 443, 445, 3389, 8080]
    
    def _web_discovery(self):
        """探测Web服务并获取基本信息"""
        results = []
        
        web_ports = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000]
        discovered_web_ports = [p for p in self.discovered_ports if p in web_ports]
        
        # 如果没有已发现的Web端口但有其他开放端口，尝试检查前五个开放端口的Web服务
        if not discovered_web_ports and len(self.discovered_ports) > 0:
            top_ports = sorted(list(self.discovered_ports))[:5]
            discovered_web_ports = top_ports
        
        for port in discovered_web_ports:
            # 确定协议
            protocol = "https" if port in [443, 8443] else "http"
            url = f"{protocol}://{self.target}:{port}"
            
            try:
                user_agents = [
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15"
                ]
                
                # 设置超时和禁用证书验证以避免阻塞
                response = requests.get(
                    url, 
                    timeout=5, 
                    verify=False,
                    headers={"User-Agent": random.choice(user_agents)}
                )
                
                # 设置正确的编码，尝试从响应头或HTML中检测
                if response.encoding == 'ISO-8859-1':
                    # 尝试从响应内容检测编码
                    detected_encoding = None
                    content_type = response.headers.get('Content-Type', '')
                    charset_match = re.search(r'charset=(\S+)', content_type)
                    if charset_match:
                        detected_encoding = charset_match.group(1)
                    else:
                        # 从HTML内容检测
                        meta_match = re.search(r'<meta\s+charset=[\'"](.*?)[\'"]', response.text, re.IGNORECASE)
                        if meta_match:
                            detected_encoding = meta_match.group(1)
                        else:
                            meta_http_match = re.search(r'<meta\s+http-equiv=[\'"]Content-Type[\'"].*?charset=(.*?)[\'"]', 
                                                     response.text, re.IGNORECASE)
                            if meta_http_match:
                                detected_encoding = meta_http_match.group(1)
                    
                    if detected_encoding:
                        try:
                            response.encoding = detected_encoding
                        except:
                            # 如果设置失败，尝试通用编码
                            response.encoding = 'utf-8'
                    else:
                        # 默认尝试UTF-8
                        response.encoding = 'utf-8'
                
                # 提取标题和服务器类型
                title = self._extract_title(response.text)
                server = response.headers.get("Server", "Unknown")
                powered_by = response.headers.get("X-Powered-By", "")
                
                # 获取网站指纹
                fingerprint = self._get_web_fingerprint(response)
                
                # 检测网站技术栈
                tech_stack = self._detect_tech_stack(response)
                
                # 检测可能的登录页面
                login_pages = self._detect_login_pages(response.text, protocol, port)
                
                # 检测表单和可能的注入点
                forms = self._extract_forms(response.text, url)
                
                # 检测JavaScript文件并分析
                js_files = self._extract_js_files(response.text, url)
                
                # 存储结果
                self.web_info[port] = {
                    "protocol": protocol,
                    "title": title,
                    "server": server,
                    "powered_by": powered_by,
                    "status_code": response.status_code,
                    "fingerprint": fingerprint,
                    "headers": dict(response.headers),
                    "encoding": response.encoding,
                    "tech_stack": tech_stack,
                    "login_pages": login_pages,
                    "forms": forms,
                    "js_files": js_files
                }
                
                result_str = f"Web服务 ({protocol}):{port} - 标题: {title}, 服务器: {server}"
                if powered_by:
                    result_str += f", 技术: {powered_by}"
                results.append(result_str)
                
                # 检查常见路径
                path_results = self._check_common_paths(protocol, port)
                results.extend(path_results)
                
            except requests.exceptions.RequestException as e:
                logger.debug(f"请求Web服务 {url} 时出错: {str(e)}")
                continue
                
        return results

    def _extract_title(self, html):
        """从HTML中提取标题"""
        title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        if title_match:
            title = title_match.group(1).strip()
            # 限制标题长度，避免过长
            if len(title) > 50:
                title = title[:47] + "..."
            return title
        return "无标题"
    
    def _get_web_fingerprint(self, response):
        """获取Web应用指纹"""
        fingerprint = {}
        
        # 检查常见CMS指纹
        html = response.text.lower()
        
        # WordPress指纹
        if "wp-content" in html or "wp-includes" in html:
            fingerprint["cms"] = "WordPress"
            
        # Joomla指纹
        elif "joomla" in html or "/component/content/" in html:  # 修复语法错误
            fingerprint["cms"] = "Joomla"  # 修复错误标识为Drupal
            
        # Drupal指纹
        elif "drupal" in html or "drupal.org" in html:
            fingerprint["cms"] = "Drupal"
            
        # 检查JavaScript框架
        if "react" in html and "reactjs" in html:
            fingerprint["framework"] = "React"
        elif "angular" in html:
            fingerprint["framework"] = "Angular"
        elif "vue" in html and "vuejs" in html:
            fingerprint["framework"] = "Vue.js"
            
        return fingerprint
    
    def _detect_tech_stack(self, response=None):
        """检测网站的技术栈"""
        tech_stack = {}
        
        if not response:
            return tech_stack
            
        # 检查服务器类型
        server = response.headers.get('Server', '')
        if server:
            tech_stack['server'] = server
            
        # 检查Web框架
        powered_by = response.headers.get('X-Powered-By', '')
        if powered_by:
            tech_stack['powered_by'] = powered_by
            
        # 检查常见框架特征
        html = response.text.lower()
        
        # 检查前端框架
        frameworks = []
        if 'react' in html or 'reactjs' in html:
            frameworks.append('React')
        if 'vue' in html or 'vue.js' in html:
            frameworks.append('Vue.js')
        if 'ng-app' in html or 'ng-controller' in html or 'angular' in html:
            frameworks.append('Angular')
        if 'jquery' in html:
            frameworks.append('jQuery')
        if frameworks:
            tech_stack['frontend'] = frameworks
            
        # 检查后端技术
        backend = []
        if 'php' in html or '.php' in html:
            backend.append('PHP')
        if 'asp.net' in html or '.aspx' in html:
            backend.append('ASP.NET')
        if 'nodejs' in html or 'node.js' in html:
            backend.append('Node.js')
        if 'django' in html or 'csrftoken' in html:
            backend.append('Django')
        if 'laravel' in html:
            backend.append('Laravel')
        if 'ruby on rails' in html or 'rails' in html:
            backend.append('Ruby on Rails')
        if backend:
            tech_stack['backend'] = backend
            
        return tech_stack
        
    def _detect_login_pages(self, html, protocol, port):
        """检测可能的登录页面"""
        login_pages = []
        
        # 查找可能的登录表单
        login_keywords = ['login', 'log in', 'sign in', 'signin', 'admin', 'user', 
                          'username', 'password', '登录', '用户名', '密码']
        
        for keyword in login_keywords:
            if keyword in html.lower():
                login_regex = r'<form\s+[^>]*action=[\'"](.*?)[\'"].*?>.*?' + keyword + '.*?</form>'
                matches = re.findall(login_regex, html, re.IGNORECASE | re.DOTALL)
                
                for match in matches:
                    # 转换为完整URL
                    if match.startswith('/'):
                        login_url = f"{protocol}://{self.target}:{port}{match}"
                    elif match.startswith('http'):
                        login_url = match
                    else:
                        login_url = f"{protocol}://{self.target}:{port}/{match}"
                        
                    if login_url not in login_pages:
                        login_pages.append(login_url)
                        
        return login_pages
        
    def _extract_forms(self, html, base_url):
        """提取页面中的表单及其参数"""
        forms = []
        
        # 使用正则表达式查找所有表单
        form_regex = r'<form\s+[^>]*>(.*?)</form>'
        form_matches = re.findall(form_regex, html, re.IGNORECASE | re.DOTALL)
        
        for i, form_content in enumerate(form_matches):
            form_info = {'id': i, 'inputs': []}
            
            # 提取表单的action和method
            action_match = re.search(r'action=[\'"](.*?)[\'"]', form_content, re.IGNORECASE)
            if action_match:
                action = action_match.group(1)
                # 如果是相对URL，转换为绝对URL
                if action.startswith('/'):
                    action = base_url.rsplit('/', 1)[0] + action
                elif not action.startswith('http'):
                    action = base_url + action
                form_info['action'] = action
            else:
                form_info['action'] = base_url
                
            # 提取表单的方法
            method_match = re.search(r'method=[\'"](.*?)[\'"]', form_content, re.IGNORECASE)
            form_info['method'] = method_match.group(1) if method_match else "GET"
            
            # 提取所有输入字段
            input_regex = r'<input\s+[^>]*>'
            input_matches = re.findall(input_regex, form_content, re.IGNORECASE)
            
            for input_tag in input_matches:
                input_info = {}
                
                # 提取输入类型
                type_match = re.search(r'type=[\'"](.*?)[\'"]', input_tag, re.IGNORECASE)
                input_info['type'] = type_match.group(1) if type_match else "text"
                
                # 提取输入名称
                name_match = re.search(r'name=[\'"](.*?)[\'"]', input_tag, re.IGNORECASE)
                if name_match:
                    input_info['name'] = name_match.group(1)
                    
                # 提取输入值
                value_match = re.search(r'value=[\'"](.*?)[\'"]', input_tag, re.IGNORECASE)
                if value_match:
                    input_info['value'] = value_match.group(1)
                    
                # 检查是否为密码字段
                if input_info.get('type') == 'password':
                    form_info['has_password'] = True
                    
                form_info['inputs'].append(input_info)
                
            forms.append(form_info)
            
        return forms
        
    def _extract_js_files(self, html, base_url):
        """提取页面中的JavaScript文件"""
        js_files = []
        
        # 查找所有script标签
        script_regex = r'<script\s+[^>]*src=[\'"](.*?)[\'"]'
        script_matches = re.findall(script_regex, html, re.IGNORECASE)
        
        for src in script_matches:
            # 转换为完整URL
            if src.startswith('//'):
                js_url = 'https:' + src
            elif src.startswith('/'):
                js_url = base_url.split('://', 1)[0] + '://' + base_url.split('://', 1)[1].split('/', 1)[0] + src
            elif not src.startswith('http'):
                js_url = base_url.rsplit('/', 1)[0] + '/' + src
            else:
                js_url = src
                
            js_files.append(js_url)
            
        return js_files
        
    def _check_common_paths(self, protocol, port):
        """检查常见路径"""
        results = []
        common_paths = [
            "/admin", "/login", "/wp-admin", "/phpmyadmin",
            "/administrator", "/robots.txt", "/api", "/v1",
            "/console", "/dashboard"
        ]
        
        for path in common_paths:
            url = f"{protocol}://{self.target}:{port}{path}"
            try:
                response = requests.get(url, timeout=2, verify=False,
                                       headers={"User-Agent": "Mozilla/5.0"})
                if response.status_code not in [404, 403, 401]:
                    results.append(f"发现路径: {url} (状态码: {response.status_code})")
                    
                    # 如果是robots.txt，解析并检查路径
                    if path == "/robots.txt" and response.status_code == 200:
                        disallowed = re.findall(r"Disallow:\s*(\S+)", response.text)
                        for path in disallowed[:5]:  # 最多只报告前5个
                            results.append(f"robots.txt禁止路径: {path}")
                    
            except:
                continue
                
        return results
    
    def _host_discovery(self):
        """发现本地网络中的其他主机"""
        results = []
        
        # 检查目标是否为网络
        if '/' in self.target:  # CIDR表示法，如 192.168.1.0/24
            try:
                # 使用ARP扫描发现本地网络中的主机（抑制警告信息）
                old_verb = conf.verb
                conf.verb = 0  # 完全静默模式
                
                arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=self.target)
                try:
                    ans, _ = srp(arp_request, timeout=2, verbose=0, retry=1)
                    
                    for _, rcv in ans:
                        host = rcv.psrc
                        mac = rcv.hwsrc
                        
                        if host not in self.hosts_in_network:
                            self.hosts_in_network.add(host)
                            results.append(f"发现网络主机: {host} (MAC: {mac})")
                            
                except Exception as e:
                    logger.debug(f"ARP扫描出错: {str(e)}")
                    # 尝试使用ping扫描作为备选方案
                    self._ping_sweep_discovery()
                
                # 恢复之前的详细级别
                conf.verb = old_verb
                
            except Exception as e:
                logger.debug(f"主机发现过程中出现错误: {str(e)}")
                
        return results
    
    def _ping_sweep_discovery(self):
        """使用ping扫描发现主机（替代方法）"""
        try:
            # 解析CIDR格式地址
            network = self.target.split('/')[0]
            prefix = int(self.target.split('/')[1])
            
            # 计算网络地址范围
            ip_parts = network.split('.')
            base_ip = '.'.join(ip_parts[:3]) + '.'
            
            # 确定要扫描的主机数量（最多256个）
            host_count = min(256, 2**(32-prefix))
            
            # 随机选择部分主机进行扫描，降低网络流量
            start_ip = int(ip_parts[3])
            hosts_to_scan = random.sample(range(start_ip, start_ip + host_count), min(50, host_count))
            
            for host_suffix in hosts_to_scan:
                if host_suffix > 255:  # 确保IP有效
                    continue
                    
                target_ip = f"{base_ip}{host_suffix}"
                # 使用ICMP ping检测主机是否在线
                packet = IP(dst=target_ip)/ICMP()
                response = sr1(packet, timeout=1, verbose=0)
                
                if response:
                    self.hosts_in_network.add(target_ip)
                    
        except Exception as e:
            logger.debug(f"Ping扫描出错: {str(e)}")
    
    def _ssl_scan(self):
        """扫描SSL/TLS配置和证书信息"""
        results = []
        ssl_ports = [443, 8443]
        ssl_ports.extend([p for p in self.discovered_ports if p not in ssl_ports and p in [465, 636, 993, 995]])
        
        if not HAS_OPENSSL:
            logger.warning("SSL扫描需要OpenSSL支持，请安装: pip install pyopenssl")
            return results
            
        for port in ssl_ports:
            if port not in self.discovered_ports:
                continue
                
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((self.target, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                        cert = ssock.getpeercert(binary_form=True)
                        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
                        
                        # 获取证书详情
                        subject = dict(x509.get_subject().get_components())
                        issuer = dict(x509.get_issuer().get_components())
                        not_before = x509.get_notBefore().decode('ascii')
                        not_after = x509.get_notAfter().decode('ascii')
                        
                        # 获取SSL/TLS版本
                        version = ssock.version()
                        
                        # 保存SSL/TLS信息
                        self.ssl_info[port] = {
                            "version": version,
                            "subject": {k.decode('utf-8'): v.decode('utf-8') for k, v in subject.items()},
                            "issuer": {k.decode('utf-8'): v.decode('utf-8') for k, v in issuer.items()},
                            "valid_from": not_before,
                            "valid_to": not_after
                        }
                        
                        # 检查常见SSL/TLS问题
                        results.append(f"SSL/TLS ({port}): 版本 {version}, CN={subject.get(b'CN', b'').decode('utf-8')}")
                        
                        # 检查证书过期
                        import time
                        current_time = time.time()
                        expire_time = time.mktime(time.strptime(not_after, '%Y%m%d%H%M%SZ'))
                        if expire_time < current_time:
                            results.append(f"SSL/TLS ({port}): 证书已过期")
                        elif expire_time - current_time < 30 * 24 * 3600:
                            results.append(f"SSL/TLS ({port}): 证书即将过期")
            except Exception as e:
                logger.debug(f"SSL/TLS扫描错误 ({port}): {str(e)}")
                
        return results
    
    def _vuln_scan(self):
        """基本漏洞扫描"""
        results = []
        
        # 检查Web服务漏洞
        for port, web_info in self.web_info.items():
            # 检查可能的XSS漏洞测试点
            if self._xss_scan(port, web_info):
                results.append(f"潜在XSS漏洞: {web_info['protocol']}://{self.target}:{port}")
                self.vulnerabilities.append({
                    "type": "XSS",
                    "service": f"{web_info['protocol']}://{self.target}:{port}",
                    "severity": "High",
                    "details": "表单或URL参数可能存在XSS漏洞"
                })
            
            # 检查可能的SQL注入点
            if self._sqli_scan(port, web_info):
                results.append(f"潜在SQL注入漏洞: {web_info['protocol']}://{self.target}:{port}")
                self.vulnerabilities.append({
                    "type": "SQL Injection",
                    "service": f"{web_info['protocol']}://{self.target}:{port}",
                    "severity": "High",
                    "details": "表单或URL参数可能存在SQL注入漏洞"
                })
            
            # 检查服务器信息泄露
            if web_info.get("server", "") and web_info.get("server") != "Unknown":
                results.append(f"信息泄露: 服务器头部泄露版本 {web_info['server']}")
                self.vulnerabilities.append({
                    "type": "Information Disclosure",
                    "service": f"{web_info['protocol']}://{self.target}:{port}",
                    "severity": "Low",
                    "details": f"服务器标头泄露: {web_info['server']}"
                })
        
        # 检查开放的危险服务
        dangerous_ports = {
            21: "FTP",
            23: "Telnet",
            25: "SMTP",
            137: "NetBIOS",
            139: "NetBIOS",
            445: "SMB",
            1433: "MSSQL",
            3306: "MySQL",
            5432: "PostgreSQL"
        }
        
        for port in self.discovered_ports:
            if port in dangerous_ports:
                results.append(f"发现潜在危险服务: {port}/{dangerous_ports[port]}")
                self.vulnerabilities.append({
                    "type": "Exposed Service",
                    "service": f"{self.target}:{port} ({dangerous_ports[port]})",
                    "severity": "Medium",
                    "details": f"发现开放的{dangerous_ports[port]}服务，该服务如配置不当可能导致未授权访问"
                })
        
        # 添加高级漏洞检测代码
        # 检查服务特定漏洞
        service_vulns = self._check_service_vulnerabilities()
        if service_vulns:
            results.extend(service_vulns)
        
        # 检测默认凭证
        default_cred_results = self._check_default_credentials()
        if default_cred_results:
            results.extend(default_cred_results)
            
        # 检查弱加密算法
        weak_crypto_results = self._check_weak_crypto()
        if weak_crypto_results:
            results.extend(weak_crypto_results)
            
        return results
    
    def _check_service_vulnerabilities(self):
        """检查特定服务的已知漏洞"""
        results = []
        
        # 检查特定版本的服务是否存在已知漏洞
        for port, service in self.discovered_services.items():
            if "Apache" in service and "2.4.49" in service:
                vuln = f"潜在漏洞: Apache 2.4.49 路径遍历漏洞 (CVE-2021-41773) 端口:{port}"
                results.append(vuln)
                self.vulnerabilities.append({
                    "type": "Path Traversal",
                    "service": f"{self.target}:{port} (Apache 2.4.49)",
                    "severity": "Critical",
                    "cve": "CVE-2021-41773",
                    "details": "Apache HTTP Server 2.4.49版本存在路径遍历漏洞"
                })
                
            if "OpenSSH" in service and any(v in service for v in ["7.2", "7.3", "7.4", "7.5", "7.6"]):
                vuln = f"潜在漏洞: OpenSSH 用户枚举漏洞 (CVE-2018-15473) 端口:{port}"
                results.append(vuln)
                self.vulnerabilities.append({
                    "type": "User Enumeration",
                    "service": f"{self.target}:{port} ({service})",
                    "severity": "Medium",
                    "cve": "CVE-2018-15473",
                    "details": "OpenSSH 7.7之前版本存在用户枚举漏洞"
                })
                
        return results
    
    def _check_default_credentials(self):
        """检查是否使用默认凭据"""
        results = []
        default_creds = {
            "tomcat": [("tomcat", "tomcat"), ("admin", "admin")],
            "jenkins": [("admin", "admin")],
            "jboss": [("admin", "admin")],
            "weblogic": [("weblogic", "weblogic"), ("system", "manager")]
        }
        
        # 检查Web应用是否使用默认凭据
        for port, web_info in self.web_info.items():
            title = web_info.get("title", "").lower()
            server = web_info.get("server", "").lower()
            
            app_type = None
            if "tomcat" in title or "tomcat" in server:
                app_type = "tomcat"
            elif "jenkins" in title:
                app_type = "jenkins"
            elif "jboss" in title or "jboss" in server:
                app_type = "jboss"
            elif "weblogic" in title or "weblogic" in server:
                app_type = "weblogic"
                
            if app_type and app_type in default_creds:
                for username, password in default_creds[app_type]:
                    if self._try_login(web_info["protocol"], port, app_type, username, password):
                        vuln = f"默认凭据漏洞: {app_type.title()}在端口{port}使用默认凭据 ({username}:{password})"
                        results.append(vuln)
                        self.vulnerabilities.append({
                            "type": "Default Credentials",
                            "service": f"{web_info['protocol']}://{self.target}:{port} ({app_type.title()})",
                            "severity": "Critical",
                            "details": f"成功使用默认凭据登录: {username}:{password}"
                        })
                        break
                        
        return results
    
    def _try_login(self, protocol, port, app_type, username, password):
        """尝试使用用户名和密码登录应用"""
        try:
            url = f"{protocol}://{self.target}:{port}"
            
            if app_type == "tomcat":
                url += "/manager/html"
                
            elif app_type == "jenkins":
                url += "/login"
                
            # 构建认证头
            import base64
            auth = base64.b64encode(f"{username}:{password}".encode()).decode()
            headers = {
                "Authorization": f"Basic {auth}",
                "User-Agent": "Mozilla/5.0"
            }
            
            response = requests.get(url, headers=headers, timeout=3, verify=False)
            
            # 检查是否登录成功
            if response.status_code == 200 and "login" not in response.url.lower():
                return True
                
        except Exception as e:
            logger.debug(f"尝试登录失败: {str(e)}")
            
        return False
    
    def _check_weak_crypto(self):
        """检查弱加密算法"""
        results = []
        
        for port, ssl_data in self.ssl_info.items():
            # 检查SSL/TLS版本
            version = ssl_data.get("version", "")
            if "SSLv2" in version or "SSLv3" in version:
                vuln = f"弱加密: 端口{port}使用过时的{version}协议"
                results.append(vuln)
                self.vulnerabilities.append({
                    "type": "Weak Encryption",
                    "service": f"{self.target}:{port}",
                    "severity": "High",
                    "details": f"使用过时的加密协议: {version}"
                })
                
            # 这里可以添加更多加密算法检查...
                
        return results
    
    def _dns_enum(self):
        """DNS枚举"""
        results = []
        
        try:
            # 检查常见子域名
            common_subdomains = [
                "www", "mail", "remote", "blog", "webmail", "server",
                "ns1", "ns2", "smtp", "secure", "vpn", "m", "shop",
                "ftp", "api", "dev", "staging", "app", "test"
            ]
            
            domain_parts = self.target.split('.')
            if len(domain_parts) < 2 or domain_parts[-1].isdigit():
                # 不像是域名，可能是IP地址
                return results
                
            # 提取基本域名
            if len(domain_parts) > 2:
                base_domain = f"{domain_parts[-2]}.{domain_parts[-1]}"
            else:
                base_domain = self.target
                
            discovered_domains = []
            
            for subdomain in common_subdomains:
                try:
                    domain = f"{subdomain}.{base_domain}"
                    ip = socket.gethostbyname(domain)
                    discovered_domains.append((domain, ip))
                    results.append(f"发现子域名: {domain} ({ip})")
                except:
                    pass
                    
            # 尝试反向DNS查询
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", self.target):
                try:
                    hostname, _, _ = socket.gethostbyaddr(self.target)
                    results.append(f"反向DNS: {self.target} -> {hostname}")
                except:
                    pass
                    
        except Exception as e:
            logger.debug(f"DNS枚举错误: {str(e)}")
            
        return results
    
    def _detect_firewall(self):
        """检测防火墙和WAF"""
        results = []
        
        # 检查HTTP WAF特征
        for port, web_info in self.web_info.items():
            protocol = web_info['protocol']
            url = f"{protocol}://{self.target}:{port}"
            
            # 检查WAF特征
            waf_detected = self._check_waf(url)
            if waf_detected:
                results.append(f"检测到WAF: {url} ({waf_detected})")
            
        # 检查通用防火墙特征
        try:
            # 发送一些异常的TCP包，检查响应模式
            for port in [80, 443] if not self.discovered_ports else list(self.discovered_ports)[:2]:
                # 发送带有异常标志的TCP包
                packet = IP(dst=self.target)/TCP(dport=port, flags="FSRPAU")
                resp = sr1(packet, timeout=2, verbose=0)
                
                # 分析响应，检测防火墙特征
                if resp:
                    if resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x14:
                        # RST-ACK响应，可能有防火墙
                        results.append("检测到可能的状态检测防火墙")
                        break
        except:
            pass
            
        return results
    
    def _check_waf(self, url):
        """检测Web应用防火墙"""
        waf_signatures = {
            "CloudFlare": ["cloudflare-nginx", "__cfduid", "cf-ray"],
            "ModSecurity": ["mod_security", "modsecurity"],
            "F5 BIG-IP": ["F5", "BIG-IP"],
            "Akamai": ["akamai"],
            "Imperva": ["incapsula"],
            "Fortinet": ["fortigate", "fortiweb"],
            "Barracuda": ["barracuda"],
        }
        
        try:
            # 发送一个正常请求
            resp = requests.get(url, verify=False, timeout=5)
            headers = resp.headers
            
            # 检查响应头部中的WAF特征
            for waf, signatures in waf_signatures.items():
                for signature in signatures:
                    for header, value in headers.items():
                        if signature.lower() in header.lower() or signature.lower() in value.lower():
                            return waf
                            
            # 发送一个带有明显攻击特征的请求
            attack_url = f"{url}?id=1' OR '1'='1"
            resp = requests.get(attack_url, verify=False, timeout=5)
            
            # 检查是否被阻止
            if resp.status_code in [403, 406, 501] or "blocked" in resp.text.lower():
                return "Unknown WAF"
        except:
            pass
            
        return None
    
    def get_discovered_info(self):
        """返回所有已发现的信息"""
        info = {
            "ports": list(self.discovered_ports),
            "services": self.discovered_services,
            "os_info": self.os_info,
            "web_info": self.web_info,
            "ssl_info": self.ssl_info,
            "network_hosts": list(self.hosts_in_network),
            "vulnerabilities": self.vulnerabilities
        }
        return info
    
    def setup_evasion_techniques(self, strategy):
        """根据策略配置隐蔽技术"""
        self.evasion_techniques = {
            "packet_fragmentation": strategy.get("fragment_packets", False),
            "decoys": self._generate_decoys(strategy.get("use_decoys", False)),
            "timing_control": strategy.get("traffic_pattern", "normal"),
            "ip_spoofing": strategy.get("ip_spoofing", False)
        }
    
    def _generate_decoys(self, use_decoys):
        """生成诱饵IP地址"""
        if not use_decoys:
            return []
            
        # 生成5个随机IP作为诱饵
        decoys = []
        for _ in range(5):
            decoy_ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
            decoys.append(decoy_ip)
            
        return decoys
    
    def map_network(self):
        """创建目标网络的映射"""
        network_map = {
            "target": self.target,
            "hosts": {},
            "routes": []
        }
        
        # 将已发现的主机添加到映射
        for host in self.hosts_in_network:
            network_map["hosts"][host] = {"ports": []}
        
        # 追踪到目标的路由
        try:
            for ttl in range(1, 16):  # 最多15跳
                pkt = IP(dst=self.target, ttl=ttl) / ICMP()
                reply = sr1(pkt, timeout=2, verbose=0)
                
                if reply is None:
                    # 未收到回应
                    network_map["routes"].append({"hop": ttl, "ip": "*", "rtt": 0})
                elif reply.src == self.target:
                    # 到达目标
                    rtt = reply.time - pkt.time if hasattr(reply, 'time') else 0
                    network_map["routes"].append({"hop": ttl, "ip": reply.src, "rtt": rtt})
                    break
                else:
                    # 中间路由器
                    rtt = reply.time - pkt.time if hasattr(reply, 'time') else 0
                    network_map["routes"].append({"hop": ttl, "ip": reply.src, "rtt": rtt})
        except:
            pass
            
        return network_map

    def _web_directory_scan(self):
        """扫描Web目录"""
        results = []
        
        for port, web_info in self.web_info.items():
            protocol = web_info.get('protocol', 'http')
            base_url = f"{protocol}://{self.target}:{port}"
            
            # 创建要扫描的目录列表
            dirs_to_scan = self.wordlists["directories"]
            
            # 如果检测到CMS，添加CMS特定目录
            cms_type = web_info.get('fingerprint', {}).get('cms')
            if cms_type:
                cms_dirs = self._get_cms_specific_dirs(cms_type)
                dirs_to_scan.extend(cms_dirs)
            
            # 并发扫描
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = {}
                for directory in dirs_to_scan:
                    url = f"{base_url}/{directory}"
                    future = executor.submit(self._check_url, url)
                    futures[future] = url
                    
                for future in futures:
                    try:
                        status_code, server_response = future.result()
                        if status_code not in [404, 403, 401]:  # 非404/403/401状态码，可能是有效路径
                            url = futures[future]
                            results.append(f"发现Web目录: {url} (状态码: {status_code})")
                            
                            # 检查是否是敏感信息泄露
                            if self._check_sensitive_info(server_response, url):
                                results.append(f"[警告] 可能的敏感信息泄露: {url}")
                                self.vulnerabilities.append({
                                    "type": "Information Disclosure",
                                    "service": url,
                                    "severity": "Medium",
                                    "details": f"发现可能包含敏感信息的目录: {url.split('/')[-1]}"
                                })
                    except Exception as e:
                        logger.debug(f"检查URL时出错: {str(e)}")
                        
        return results
        
    def _check_url(self, url):
        """检查URL是否存在并返回状态码和响应内容"""
        try:
            response = requests.get(url, timeout=3, verify=False,
                                   headers={"User-Agent": "Mozilla/5.0"})
            return response.status_code, response.text
        except requests.exceptions.RequestException:
            return 404, ""
            
    def _check_sensitive_info(self, content, url):
        """检查响应内容是否包含敏感信息"""
        sensitive_patterns = [
            r'password', r'passwd', r'pwd', r'pass', r'admin', r'administrator',
            r'root', r'mysql', r'database', r'config', r'configuration',
            r'api_key', r'apikey', r'api-key', r'access_key', r'secret_key',
            r'token', r'password=', r'user=', r'username=', r'pass=', r'pwd='
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
                
        # 检查URL路径是否包含敏感关键词
        sensitive_paths = [
            'backup', 'bak', 'old', 'config', 'db', 'sql', 'admin', 'conf',
            'test', 'dev', 'debug', 'private', 'secret'
        ]
        
        path = url.split('/')[-1]
        if path.lower() in sensitive_paths:
            return True
            
        return False
        
    def _get_cms_specific_dirs(self, cms_type):
        """根据CMS类型返回特定的目录列表"""
        cms_dirs = []
        
        if cms_type.lower() == 'wordpress':
            cms_dirs = [
                'wp-admin', 'wp-content', 'wp-includes', 'wp-config.php', 
                'wp-login.php', 'wp-json', 'wp-content/uploads', 'wp-content/plugins',
                'wp-content/themes'
            ]
        elif cms_type.lower() == 'joomla':
            cms_dirs = [
                'administrator', 'components', 'modules', 'templates', 'cache',
                'configuration.php', 'htaccess.txt', 'language', 'plugins'
            ]
        elif cms_type.lower() == 'drupal':
            cms_dirs = [
                'admin', 'modules', 'themes', 'misc', 'sites', 'includes',
                'sites/default/settings.php', 'sites/default/files'
            ]
        
        return cms_dirs
        
    def _cms_scan(self):
        """识别和扫描内容管理系统漏洞"""
        results = []
        
        for port, web_info in self.web_info.items():
            protocol = web_info.get('protocol', 'http')
            base_url = f"{protocol}://{self.target}:{port}"
            
            # 获取CMS类型
            cms_type = web_info.get('fingerprint', {}).get('cms')
            
            # 如果未发现CMS，尝试进一步识别
            if not cms_type:
                cms_type = self._detect_cms(base_url)
                
            if cms_type:
                results.append(f"检测到CMS: {base_url} 使用 {cms_type}")
                
                # 如果是WordPress，检查常见插件
                if cms_type.lower() == 'wordpress':
                    wp_results = self._scan_wordpress(base_url)
                    results.extend(wp_results)
                    
                # 如果是Joomla，检查组件
                elif cms_type.lower() == 'joomla':
                    joomla_results = self._scan_joomla(base_url)
                    results.extend(joomla_results)
                    
                # 如果是Drupal，检查模块
                elif cms_type.lower() == 'drupal':
                    drupal_results = self._scan_drupal(base_url)
                    results.extend(drupal_results)
                    
        return results
        
    def _detect_cms(self, url):
        """尝试识别CMS类型"""
        try:
            response = requests.get(url, timeout=5, verify=False,
                                  headers={"User-Agent": "Mozilla/5.0"})
            content = response.text.lower()
            
            # WordPress 特征
            if 'wp-content' in content or 'wp-includes' in content or 'wordpress' in content:
                return "WordPress"
                
            # Joomla 特征
            elif 'joomla' in content or '/administrator' in content or 'option=com_' in content:
                return "Joomla"
                
            # Drupal 特征
            elif 'drupal' in content or 'drupal.org' in content:
                return "Drupal"
                
            # Magento 特征
            elif 'magento' in content or 'skin/frontend' in content:
                return "Magento"
                
            # PrestaShop 特征
            elif 'prestashop' in content or '/modules/homeslider' in content:
                return "PrestaShop"
                
        except Exception as e:
            logger.debug(f"CMS检测出错: {str(e)}")
            
        return None
        
    def _scan_wordpress(self, base_url):
        """扫描WordPress特定漏洞"""
        results = []
        
        # 检查WordPress版本
        try:
            # 获取readme.html文件
            readme_url = f"{base_url}/readme.html"
            response = requests.get(readme_url, timeout=3, verify=False)
            
            if response.status_code == 200:
                # 尝试提取版本
                version_match = re.search(r'Version (\d+\.\d+(\.\d+)?)', response.text)
                if version_match:
                    version = version_match.group(1)
                    results.append(f"WordPress版本: {version}")
            
            # 检查常用插件
            common_plugins = [
                'woocommerce', 'jetpack', 'contact-form-7', 'yoast-seo', 
                'wordfence', 'akismet', 'elementor', 'admin-ajax', 
                'advanced-custom-fields', 'wp-super-cache'
            ]
            
            for plugin in common_plugins:
                plugin_url = f"{base_url}/wp-content/plugins/{plugin}/"
                response = requests.get(plugin_url, timeout=2, verify=False)
                
                if response.status_code != 404:
                    results.append(f"发现WordPress插件: {plugin}")
                    
        except Exception as e:
            logger.debug(f"WordPress扫描错误: {str(e)}")
            
        return results
        
    def _scan_joomla(self, base_url):
        """扫描Joomla特定漏洞"""
        results = []
        
        # 检查Joomla版本
        try:
            # 尝试从管理员登录页面提取版本
            admin_url = f"{base_url}/administrator/manifests/files/joomla.xml"
            response = requests.get(admin_url, timeout=3, verify=False)
            
            if response.status_code == 200:
                # 尝试提取版本
                version_match = re.search(r'<version>(\d+\.\d+(\.\d+)?)</version>', response.text)
                if version_match:
                    version = version_match.group(1)
                    results.append(f"Joomla版本: {version}")
                    
            # 检查常用组件
            common_components = [
                'com_content', 'com_users', 'com_banners', 'com_contact',
                'com_newsfeeds', 'com_weblinks', 'com_mailto', 'com_media'
            ]
            
            for component in common_components:
                component_url = f"{base_url}/index.php?option={component}"
                response = requests.get(component_url, timeout=2, verify=False)
                
                if "404" not in response.text and "not found" not in response.text.lower():
                    results.append(f"发现Joomla组件: {component}")
                    
        except Exception as e:
            logger.debug(f"Joomla扫描错误: {str(e)}")
            
        return results
        
    def _scan_drupal(self, base_url):
        """扫描Drupal特定漏洞"""
        results = []
        
        # 检查Drupal版本
        try:
            # 尝试从CHANGELOG.txt提取版本
            changelog_url = f"{base_url}/CHANGELOG.txt"
            response = requests.get(changelog_url, timeout=3, verify=False)
            
            if response.status_code == 200:
                # 尝试提取版本
                version_match = re.search(r'Drupal (\d+\.\d+(\.\d+)?)', response.text)
                if version_match:
                    version = version_match.group(1)
                    results.append(f"Drupal版本: {version}")
                    
        except Exception as e:
            logger.debug(f"Drupal扫描错误: {str(e)}")
            
        return results
        
    def _subdomain_enumeration(self):
        """执行子域名枚举"""
        results = []
        
        try:
            import dns.resolver
        except ImportError:
            logger.warning("未找到dnspython库，无法执行子域名枚举")
            return results
            
        # 确认目标是域名而不是IP
        if not re.match(r'^[\d\.]+$', self.target):
            # 尝试对常见子域名执行DNS查询
            for subdomain in self.wordlists['subdomains']:
                try:
                    domain = f"{subdomain}.{self.target}"
                    answers = dns.resolver.resolve(domain, 'A')
                    for answer in answers:
                        ip = answer.to_text()
                        results.append(f"发现子域名: {domain} -> {ip}")
                except Exception:
                    pass
                    
        return results
        
    def _check_info_disclosure(self):
        """检查信息泄露"""
        results = []
        
        # 检查敏感文件
        sensitive_files = [
            'robots.txt', '.git/HEAD', '.svn/entries', '.DS_Store', 
            'web.config', '.htaccess', 'backup.zip', 'backup.sql', 
            'config.php', 'phpinfo.php', 'info.php', 'test.php'
        ]
        
        # 检查Web服务器上的敏感文件
        for port, web_info in self.web_info.items():
            protocol = web_info.get('protocol', 'http')
            base_url = f"{protocol}://{self.target}:{port}"
            
            for file in sensitive_files:
                url = f"{base_url}/{file}"
                try:
                    response = requests.get(url, timeout=3, verify=False,
                                        headers={"User-Agent": "Mozilla/5.0"})
                    
                    if response.status_code == 200:
                        results.append(f"发现敏感文件: {url}")
                        
                        if file in ['.git/HEAD', '.svn/entries']:
                            self.vulnerabilities.append({
                                "type": "Source Code Disclosure",
                                "service": url,
                                "severity": "Critical",
                                "details": f"源代码管理文件泄露: {file}"
                            })
                        elif file in ['phpinfo.php', 'info.php']:
                            self.vulnerabilities.append({
                                "type": "Information Disclosure",
                                "service": url,
                                "severity": "High",
                                "details": f"PHP信息泄露: {file}"
                            })
                            
                except Exception:
                    pass
                    
        return results
        
    def _load_cve_database(self):
        """加载CVE数据库"""
        # 简单的本地CVE数据库示例
        return [
            {
                "id": "CVE-2021-41773",
                "software": "apache",
                "affects_version": "<=2.4.49",
                "title": "Apache 2.4.49 Path Traversal Vulnerability"
            },
            {
                "id": "CVE-2018-15473",
                "software": "openssh",
                "affects_version": "<7.7",
                "title": "OpenSSH User Enumeration Vulnerability"
            },
            {
                "id": "CVE-2017-5638",
                "software": "struts2",
                "affects_version": "<2.5.10",
                "title": "Apache Struts Remote Code Execution Vulnerability"
            },
            {
                "id": "CVE-2020-0796",
                "software": "windows",
                "affects_version": "10",
                "title": "SMBGhost Remote Code Execution Vulnerability"
            }
        ]
    
    def _xss_scan(self, port, web_info):
        """检测XSS漏洞点"""
        try:
            # 获取表单信息
            forms = web_info.get("forms", [])
            if not forms:
                return False
                
            # 简单的XSS测试负载
            xss_payloads = [
                "<script>alert(1)</script>",
                "\"><script>alert(1)</script>",
                "'><script>alert(1)</script>"
            ]
            
            protocol = web_info.get("protocol", "http")
            base_url = f"{protocol}://{self.target}:{port}"
            
            # 检查每个表单是否存在XSS漏洞
            for form in forms:
                action = form.get("action", base_url)
                method = form.get("method", "GET").upper()
                inputs = form.get("inputs", [])
                
                # 跳过没有输入字段的表单
                if not inputs:
                    continue
                    
                # 准备表单数据
                for payload in xss_payloads:
                    form_data = {}
                    
                    # 填充所有输入字段
                    for input_field in inputs:
                        field_name = input_field.get("name", "")
                        if not field_name:
                            continue
                            
                        # 针对文本字段尝试XSS注入
                        if input_field.get("type", "") in ["text", "search", "url", "email"]:
                            form_data[field_name] = payload
                        else:
                            # 其他字段填写有效值
                            form_data[field_name] = "test"
                            
                    try:
                        # 发送请求测试XSS漏洞
                        if method == "GET":
                            response = requests.get(action, params=form_data, 
                                                  timeout=3, verify=False,
                                                  headers={"User-Agent": "Mozilla/5.0"})
                        else:
                            response = requests.post(action, data=form_data,
                                                   timeout=3, verify=False,
                                                   headers={"User-Agent": "Mozilla/5.0"})
                        
                        # 检查响应是否包含XSS payload
                        if payload in response.text:
                            return True
                            
                    except Exception as e:
                        logger.debug(f"XSS测试出错: {str(e)}")
                        continue
                        
            return False
        except Exception as e:
            logger.debug(f"XSS扫描时出错: {str(e)}")
            return False

    def _sqli_scan(self, port, web_info):
        """检测SQL注入漏洞点"""
        try:
            # 获取表单信息
            forms = web_info.get("forms", [])
            if not forms:
                return False
                
            # 简单的SQL注入测试负载
            sqli_payloads = [
                "' OR '1'='1",
                "\" OR \"1\"=\"1",
                "1' OR '1'='1' --",
                "1\" OR \"1\"=\"1\" --",
                "' OR 1=1 --",
                "admin'--"
            ]
            
            # 检查SQL注入错误响应模式
            sql_errors = [
                "SQL syntax", "mysql_fetch_array", "mysql_result",
                "mysql_num_rows", "mysql_query", "PostgreSQL.*ERROR", 
                "ORA-[0-9][0-9][0-9]", "Microsoft SQL Server",
                "SQLITE_ERROR", "SQLSTATE", "syntax error"
            ]
            
            protocol = web_info.get("protocol", "http")
            base_url = f"{protocol}://{self.target}:{port}"
            
            # 检查每个表单是否存在SQL注入漏洞
            for form in forms:
                action = form.get("action", base_url)
                method = form.get("method", "GET").upper()
                inputs = form.get("inputs", [])
                
                # 跳过没有输入字段的表单
                if not inputs:
                    continue
                    
                # 准备表单数据
                for payload in sqli_payloads:
                    form_data = {}
                    inject_point = False
                    
                    # 填充所有输入字段
                    for input_field in inputs:
                        field_name = input_field.get("name", "")
                        if not field_name:
                            continue
                            
                        # 针对文本字段尝试注入
                        if input_field.get("type", "") in ["text", "search"] or "id" in field_name.lower() or "user" in field_name.lower():
                            form_data[field_name] = payload
                            inject_point = True
                        else:
                            # 其他字段填写有效值
                            form_data[field_name] = "test"
                            
                    if not inject_point:
                        continue
                        
                    try:
                        # 发送请求测试SQL注入
                        if method == "GET":
                            response = requests.get(action, params=form_data, 
                                                  timeout=3, verify=False,
                                                  headers={"User-Agent": "Mozilla/5.0"})
                        else:
                            response = requests.post(action, data=form_data,
                                                   timeout=3, verify=False,
                                                   headers={"User-Agent": "Mozilla/5.0"})
                        
                        # 检查响应是否包含SQL错误
                        for error in sql_errors:
                            if re.search(error, response.text, re.IGNORECASE):
                                return True
                                
                    except Exception as e:
                        logger.debug(f"SQL注入测试出错: {str(e)}")
                        continue
                        
            return False
        except Exception as e:
            logger.debug(f"SQL注入扫描时出错: {str(e)}")
            return False