import os
import sys
import time
import logging
import warnings
from datetime import datetime

# 检查是否安装了colorama, rich, pyfiglet, terminaltables
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False

try:
    from rich.console import Console
    from rich.table import Table
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

try:
    from pyfiglet import Figlet
    HAS_PYFIGLET = True
except ImportError:
    HAS_PYFIGLET = False

try:
    from terminaltables import SingleTable
    HAS_TERMINALTABLES = True
except ImportError:
    HAS_TERMINALTABLES = False

# 定义颜色和样式
if HAS_COLORAMA:
    RED = Fore.RED
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    CYAN = Fore.CYAN
    WHITE = Fore.WHITE
    MAGENTA = Fore.MAGENTA
    RESET = Style.RESET_ALL
    BOLD = Style.BRIGHT
    CYAN_BRIGHT = Fore.CYAN + Style.BRIGHT
else:
    RED = GREEN = YELLOW = CYAN = WHITE = MAGENTA = RESET = BOLD = CYAN_BRIGHT = ""

# 获取终端宽度
TERM_WIDTH = os.get_terminal_size().columns

# 禁用scapy等库的警告输出
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# 如果需要，也可以禁用其他库的警告
warnings_to_suppress = ["scapy.runtime", "urllib3.connectionpool"]
for warning in warnings_to_suppress:
    logging.getLogger(warning).setLevel(logging.ERROR)

class CyberReconCLI:
    def __init__(self):
        self.logger = logging.getLogger("adaptive_recon")
        self.console = Console() if HAS_RICH else None
        self.current_menu = "main"
        self.scan_settings = {
            "target": None,
            "mode": "smart",
            "output_file": None,
            "summary_interval": 120,
            "passive_mode": False
        }
        self.results = None
        # 重定向标准错误流以捕获警告
        self.original_stderr = sys.stderr
        self.warning_buffer = None

    def print_header(self):
        """打印界面头部"""
        # 清屏前保存当前的标准错误流
        old_stderr = sys.stderr
        # 使用空设备作为临时标准错误流，避免清屏时显示警告
        sys.stderr = open(os.devnull, 'w')
        
        try:
            os.system('cls' if os.name == 'nt' else 'clear')
        finally:
            # 恢复标准错误流
            sys.stderr.close()
            sys.stderr = old_stderr
            
        if HAS_PYFIGLET:
            f = Figlet(font='slant')
            print(CYAN_BRIGHT + f.renderText('CyberRecon') + RESET)
        else:
            print(CYAN_BRIGHT + "CyberRecon" + RESET)
        print(CYAN_BRIGHT + "-"*TERM_WIDTH + RESET)

    def show_splash_screen(self):
        """显示启动画面"""
        self.print_header()
        print(f"\n{CYAN_BRIGHT}欢迎使用自适应信息收集工具 (CyberRecon){RESET}\n")
        print(f"{WHITE}版本: 1.0.0{RESET}")
        print(f"{WHITE}作者: 你的名字{RESET}")
        print(f"{WHITE}GitHub: https://github.com/你的仓库{RESET}")
        print("\n" + CYAN_BRIGHT + "-"*TERM_WIDTH + RESET)
        time.sleep(2)

    def show_main_menu(self):
        """显示主菜单"""
        self.print_header()
        print(f"\n{BOLD}{WHITE}【主菜单】{RESET}\n")
        print(f"{CYAN}1{RESET}. 开始新扫描")
        print(f"{CYAN}2{RESET}. 查看扫描结果")
        print(f"{CYAN}3{RESET}. 设置")
        print(f"{CYAN}4{RESET}. 关于")
        print(f"{CYAN}0{RESET}. 退出")
        
        choice = input(f"\n{CYAN}请选择操作 [0-4]: {RESET}")
        
        if choice == '1':
            self.current_menu = "scan"
        elif choice == '2':
            self.current_menu = "results"
        elif choice == '3':
            self.current_menu = "settings"
        elif choice == '4':
            self.current_menu = "about"
        elif choice == '0':
            self.current_menu = "exit"

    def show_scan_menu(self):
        """显示扫描菜单"""
        self.print_header()
        print(f"\n{BOLD}{WHITE}【开始新扫描】{RESET}\n")
        
        target = input(f"{CYAN}请输入目标主机或网络: {RESET}")
        if not target:
            print(f"{YELLOW}目标不能为空。{RESET}")
            time.sleep(1)
            return
        
        print(f"\n{BOLD}{WHITE}选择扫描模式:{RESET}")
        print(f"{CYAN}1{RESET}. 激进模式 (aggressive) - 完整扫描，速度快但易被检测")
        print(f"{CYAN}2{RESET}. 隐蔽模式 (stealth) - 仅进行基本扫描，不易被检测") 
        print(f"{CYAN}3{RESET}. 智能模式 (smart) - 平衡速度和隐蔽性")
        print(f"{CYAN}4{RESET}. 低噪音模式 (low_noise) - 仅Web相关扫描")
        print(f"{CYAN}5{RESET}. 极度隐蔽模式 (ultra_stealth) - 仅最基本的端口扫描")
        print(f"{CYAN}6{RESET}. 自定义模式 (custom) - 选择扫描模块")
        
        mode_choice = input(f"\n{CYAN}请选择扫描模式 [1-6]: {RESET}")
        mode_map = {
            '1': 'aggressive',
            '2': 'stealth', 
            '3': 'smart',
            '4': 'low_noise',
            '5': 'ultra_stealth',
            '6': 'custom'
        }
        mode = mode_map.get(mode_choice, 'smart')
        
        self.scan_settings["target"] = target
        self.scan_settings["mode"] = mode
        
        # 如果选择自定义模式，允许用户选择扫描模块
        if mode == 'custom':
            self._configure_custom_scan()
        
        # 询问是否使用被动模式
        passive = input(f"\n{CYAN}是否启用被动模式(只收集不进行主动扫描)? (y/n): {RESET}")
        self.scan_settings["passive_mode"] = (passive.lower() == 'y')
        
        print(f"\n{GREEN}目标: {target}{RESET}")
        print(f"{GREEN}模式: {mode}{RESET}")
        print(f"{GREEN}被动模式: {'是' if self.scan_settings['passive_mode'] else '否'}{RESET}")
        
        confirm = input(f"\n{CYAN}确认开始扫描? (y/n): {RESET}")
        if confirm.lower() != 'y':
            print(f"{YELLOW}扫描已取消。{RESET}")
            time.sleep(1)
            return
        
        # 开始扫描
        self.start_scan()

    def _configure_custom_scan(self):
        """配置自定义扫描选项"""
        self.print_header()
        print(f"\n{BOLD}{WHITE}【配置自定义扫描】{RESET}\n")
        print(f"{YELLOW}请选择要启用的扫描模块 (输入对应数字，多个模块用逗号分隔):{RESET}\n")
        
        modules = [
            ("port_scan", "端口扫描", True),
            ("service_detection", "服务检测", True),
            ("os_detection", "操作系统检测", False),
            ("web_discovery", "Web服务探测", True),
            ("host_discovery", "主机发现", False),
            ("vuln_scan", "漏洞扫描", False),
            ("ssl_scan", "SSL/TLS扫描", False),
            ("dns_enum", "DNS枚举", False),
            ("firewall_detection", "防火墙检测", False),
            ("web_directory_scan", "Web目录扫描", False),
            ("cms_scan", "CMS识别", False),
            ("subdomain_enum", "子域名枚举", False),
            ("tech_detection", "技术栈识别", False),
            ("info_disclosure", "敏感信息检测", False)
        ]
        
        for i, (module_id, module_name, default) in enumerate(modules, 1):
            status = "默认启用" if default else "默认禁用"
            print(f"{CYAN}{i}{RESET}. {module_name} ({status})")
        
        choice = input(f"\n{CYAN}请选择要启用的模块 (例如: 1,3,5): {RESET}")
        
        try:
            # 解析用户选择
            if choice.strip():
                selected_indices = [int(x.strip()) for x in choice.split(',') if x.strip()]
                enabled_modules = [modules[i-1][0] for i in selected_indices if 0 < i <= len(modules)]
                
                # 确保至少有端口扫描模块
                if "port_scan" not in enabled_modules:
                    enabled_modules.append("port_scan")
                    print(f"{YELLOW}已自动添加必要的端口扫描模块。{RESET}")
            else:
                # 如果用户未选择，使用默认模块
                enabled_modules = [m[0] for m in modules if m[2]]
                print(f"{YELLOW}使用默认扫描模块。{RESET}")
                
            # 存储自定义配置
            from strategy import StrategyManager
            strat_mgr = StrategyManager()
            self.scan_settings["custom_strategy"] = strat_mgr.create_custom_strategy(
                base_mode="smart",
                enabled_modules=enabled_modules
            )
            
            print(f"\n{GREEN}已启用 {len(enabled_modules)} 个模块: {', '.join(enabled_modules)}{RESET}")
            time.sleep(2)
            
        except Exception as e:
            print(f"{RED}解析选择时出错: {str(e)}，使用默认模块。{RESET}")

    def start_scan(self):
        """开始扫描"""
        from main import run_scan_loop
        import threading
        
        target = self.scan_settings["target"]
        mode = self.scan_settings["mode"]
        output_file = self.scan_settings["output_file"]
        summary_interval = self.scan_settings["summary_interval"]
        passive_mode = self.scan_settings["passive_mode"]
        
        # 显示扫描开始信息
        self.print_header()
        print(f"\n{BOLD}{GREEN}【扫描进行中】{RESET}")
        print(f"\n{CYAN}目标: {RESET}{target}")
        print(f"{CYAN}模式: {RESET}{mode}")
        print(f"{CYAN}开始时间: {RESET}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"\n{YELLOW}按 Ctrl+C 停止扫描{RESET}")
        print("\n" + CYAN_BRIGHT + "-"*TERM_WIDTH + RESET + "\n")
        
        # 创建一个事件用于停止扫描
        stop_event = threading.Event()
        
        # 创建扫描结果容器
        self.results = None
        
        # 重定向标准错误以捕获警告消息
        class WarningBuffer:
            def __init__(self):
                self.content = []
                
            def write(self, text):
                if "WARNING:" in text and ("MAC address" in text or "broadcast" in text):
                    # 忽略这些特定的警告，不显示
                    pass
                else:
                    # 其他错误/警告信息仍然向用户显示
                    sys.stdout.write(f"{RED}{text}{RESET}")
                    
            def flush(self):
                pass
                
        self.warning_buffer = WarningBuffer()
        sys.stderr = self.warning_buffer
        
        # 定义扫描线程函数
        def scan_thread_func():
            try:
                # 导入这些模块只在线程内部，避免循环导入问题
                from strategy import StrategyManager
                from analyzer import ResponseAnalyzer
                from ai_engine import AdaptiveEngine
                from results import ResultManager
                from scanner import Scanner
                
                # 初始化各模块
                strategy_manager = StrategyManager(initial_mode=mode)
                
                # 如果是自定义模式并且有自定义策略配置
                if mode == "custom" and "custom_strategy" in self.scan_settings:
                    strategy_manager.current_strategy = self.scan_settings["custom_strategy"]
                    
                # 添加目标信息到策略
                strategy_manager.current_strategy["target"] = target
                strategy_manager.current_strategy["passive_mode"] = passive_mode
                
                analyzer = ResponseAnalyzer()
                ai_engine = AdaptiveEngine(strategy_manager)
                result_manager = ResultManager(target, output_file)
                
                # 正确传递passive_mode参数
                scanner = Scanner(target, strategy_manager, passive_mode)
                
                # 显示已启用的模块
                enabled_modules = strategy_manager.current_strategy["enabled_modules"]
                sys.stdout.write(f"\n{YELLOW}[*] 已启用的扫描模块: {', '.join(enabled_modules)}{RESET}\n\n")
                
                last_summary_time = time.time()
                scan_count = 0
                
                # 避免在终端界面中显示警告
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    
                    # 扫描循环
                    while not stop_event.is_set():
                        scan_count += 1
                        # 执行扫描
                        scan_results = scanner.scan()
                        
                        # 分析目标响应
                        response_data = analyzer.analyze(scan_results)
                        
                        # AI引擎评估和调整策略
                        ai_engine.evaluate_and_adapt(response_data)
                        
                        # 处理结果
                        new_findings = result_manager.process_results(scan_results)
                        
                        # 输出结果
                        if new_findings > 0:
                            sys.stdout.write(f"\r{GREEN}[+] 收集到新信息: {new_findings} 条{RESET}                 \n")
                        
                        # 定期显示总结
                        current_time = time.time()
                        if current_time - last_summary_time >= summary_interval:
                            summary = result_manager.get_summary()
                            sys.stdout.write("\n" + CYAN_BRIGHT + "-"*TERM_WIDTH + RESET + "\n")
                            sys.stdout.write(f"{YELLOW}【扫描摘要 - 已执行{scan_count}次】{RESET}\n\n")
                            for line in summary.split('\n'):
                                if line.strip():
                                    sys.stdout.write(f"{line}\n")
                            sys.stdout.write("\n" + CYAN_BRIGHT + "-"*TERM_WIDTH + RESET + "\n\n")
                            last_summary_time = current_time
                        
                        # 显示扫描状态
                        sys.stdout.write(f"\r{CYAN}[*] 正在扫描... 当前进度: {scan_count} 次{RESET}")
                        sys.stdout.flush()
                        
                        # 等待下一次扫描
                        time.sleep(strategy_manager.get_scan_interval())
                
                # 保存最终结果
                self.results = result_manager
                if output_file:
                    result_manager.save_to_file()
                    
            except KeyboardInterrupt:
                pass
            except Exception as e:
                sys.stdout.write(f"\n{RED}[!] 扫描过程中出错: {str(e)}{RESET}\n")
        
        # 创建并启动扫描线程
        scan_thread = threading.Thread(target=scan_thread_func)
        scan_thread.daemon = True
        scan_thread.start()
        
        try:
            # 主线程等待用户输入中断
            while scan_thread.is_alive():
                time.sleep(0.5)
        except KeyboardInterrupt:
            sys.stdout.write(f"\n\n{YELLOW}[!] 用户中断，正在停止扫描...{RESET}\n")
            stop_event.set()
            scan_thread.join(timeout=3.0)  # 等待线程结束
        finally:
            # 恢复标准错误流
            sys.stderr = self.original_stderr
        
        print(f"\n{GREEN}扫描完成。{RESET}")
        input(f"\n{CYAN}按任意键返回主菜单...{RESET}")
        self.current_menu = "main"

    def show_results_menu(self):
        """显示扫描结果菜单"""
        if not self.results:
            self.print_header()
            print(f"\n{YELLOW}没有扫描结果。请先进行扫描。{RESET}")
            input(f"\n{CYAN}按任意键返回主菜单...{RESET}")
            self.current_menu = "main"
            return
            
        self.print_header()
        print(f"\n{BOLD}{WHITE}【扫描结果】{RESET}\n")
        
        # 显示结果摘要
        summary = self.results.get_summary()
        if HAS_RICH:
            from rich.markdown import Markdown
            self.console.print(Markdown(summary))
        else:
            print(summary)
            
        print("\n" + CYAN_BRIGHT + "-"*TERM_WIDTH + RESET)
        print(f"\n{BOLD}{WHITE}选择操作:{RESET}\n")
        print(f"{CYAN}1{RESET}. 显示详细端口信息")
        print(f"{CYAN}2{RESET}. 显示详细Web服务信息")
        print(f"{CYAN}3{RESET}. 显示详细漏洞信息")
        print(f"{CYAN}4{RESET}. 导出结果")
        print(f"{CYAN}0{RESET}. 返回主菜单")
        
        choice = input(f"\n{CYAN}请选择操作 [0-4]: {RESET}")
        
        if choice == '1':
            self.show_port_details()
        elif choice == '2':
            self.show_web_details()
        elif choice == '3':
            self.show_vuln_details()
        elif choice == '4':
            self.export_results()
        elif choice == '0':
            self.current_menu = "main"
    
    def show_port_details(self):
        """显示详细端口信息"""
        if not self.results:
            return
            
        self.print_header()
        print(f"\n{BOLD}{WHITE}【端口详细信息】{RESET}\n")
        
        ports = self.results.results.get("ports", {})
        services = self.results.results.get("services", {})
        
        if not ports:
            print(f"{YELLOW}未发现开放端口。{RESET}")
            input(f"\n{CYAN}按任意键返回...{RESET}")
            return
        
        if HAS_RICH:
            table = Table(title="端口扫描结果")
            table.add_column("端口", style="cyan")
            table.add_column("状态", style="green")
            table.add_column("服务", style="yellow")
            
            for port in sorted(ports.keys(), key=lambda x: int(x) if isinstance(x, (int, str)) else 0):
                status = ports.get(port, "未知")
                service = services.get(str(port), "未知")
                table.add_row(str(port), status, service)
                
            self.console.print(table)
        elif HAS_TERMINALTABLES:
            data = [["端口", "状态", "服务"]]
            
            for port in sorted(ports.keys(), key=lambda x: int(x) if isinstance(x, (int, str)) else 0):
                status = ports.get(port, "未知")
                service = services.get(str(port), "未知")
                data.append([str(port), status, service])
                
            table = SingleTable(data)
            table.title = "端口扫描结果"
            print(table.table)
        else:
            print(f"{CYAN_BRIGHT}端口扫描结果:{RESET}")
            for port in sorted(ports.keys(), key=lambda x: int(x) if isinstance(x, (int, str)) else 0):
                status = ports.get(port, "未知")
                service = services.get(str(port), "未知")
                print(f"  {CYAN}端口 {port}{RESET}: {GREEN}{status}{RESET} - {YELLOW}{service}{RESET}")
        
        input(f"\n{CYAN}按任意键返回...{RESET}")
    
    def show_web_details(self):
        """显示详细Web服务信息"""
        if not self.results:
            return
            
        self.print_header()
        print(f"\n{BOLD}{WHITE}【Web服务详细信息】{RESET}\n")
        
        web_info = self.results.results.get("web_info", {})
        
        if not web_info:
            print(f"{YELLOW}未发现Web服务。{RESET}")
            input(f"\n{CYAN}按任意键返回...{RESET}")
            return
            
        if HAS_RICH:
            table = Table(title="Web服务信息")
            table.add_column("端口", style="cyan")
            table.add_column("协议", style="green")
            table.add_column("标题", style="yellow")
            table.add_column("服务器", style="magenta")
            table.add_column("WAF", style="red")
            
            for port, info in sorted(web_info.items(), key=lambda x: int(x[0]) if isinstance(x[0], (int, str)) else 0):
                protocol = info.get("protocol", "http")
                title = info.get("title", "未知")
                server = info.get("server", "未知")
                waf = info.get("waf", "未检测到")
                table.add_row(str(port), protocol, title, server, waf)
                
            self.console.print(table)
        elif HAS_TERMINALTABLES:
            data = [["端口", "协议", "标题", "服务器", "WAF"]]
            
            for port, info in sorted(web_info.items(), key=lambda x: int(x[0]) if isinstance(x[0], (int, str)) else 0):
                protocol = info.get("protocol", "http")
                title = info.get("title", "未知")
                server = info.get("server", "未知")
                waf = info.get("waf", "未检测到")
                data.append([str(port), protocol, title, server, waf])
                
            table = SingleTable(data)
            table.title = "Web服务信息"
            print(table.table)
        else:
            print(f"{CYAN_BRIGHT}Web服务信息:{RESET}")
            for port, info in sorted(web_info.items(), key=lambda x: int(x[0]) if isinstance(x[0], (int, str)) else 0):
                protocol = info.get("protocol", "http")
                title = info.get("title", "未知")
                server = info.get("server", "未知")
                waf = info.get("waf", "未检测到")
                print(f"  {CYAN}端口 {port}{RESET} - {GREEN}{protocol}{RESET}")
                print(f"    {YELLOW}标题: {title}{RESET}")
                print(f"    {MAGENTA}服务器: {server}{RESET}")
                print(f"    {RED}WAF: {waf}{RESET}")
                print("")
        
        input(f"\n{CYAN}按任意键返回...{RESET}")
    
    def show_vuln_details(self):
        """显示详细漏洞信息"""
        if not self.results:
            return
            
        self.print_header()
        print(f"\n{BOLD}{WHITE}【漏洞详细信息】{RESET}\n")
        
        vulns = self.results.results.get("vulnerabilities", [])
        
        if not vulns:
            print(f"{YELLOW}未发现漏洞。{RESET}")
            input(f"\n{CYAN}按任意键返回...{RESET}")
            return
            
        if HAS_RICH:
            table = Table(title="漏洞信息")
            table.add_column("描述", style="yellow")
            table.add_column("发现时间", style="cyan")
            
            for vuln in vulns:
                description = vuln.get("description", "未知")
                detected_at = vuln.get("detected_at", "未知")
                table.add_row(description, detected_at)
                
            self.console.print(table)
        elif HAS_TERMINALTABLES:
            data = [["描述", "发现时间"]]
            
            for vuln in vulns:
                description = vuln.get("description", "未知")
                detected_at = vuln.get("detected_at", "未知")
                data.append([description, detected_at])
                
            table = SingleTable(data)
            table.title = "漏洞信息"
            print(table.table)
        else:
            print(f"{CYAN_BRIGHT}漏洞信息:{RESET}")
            for i, vuln in enumerate(vulns):
                description = vuln.get("description", "未知")
                detected_at = vuln.get("detected_at", "未知")
                print(f"  {CYAN}{i+1}.{RESET} {YELLOW}{description}{RESET}")
                print(f"     {CYAN}发现时间: {detected_at}{RESET}")
                print("")
        
        input(f"\n{CYAN}按任意键返回...{RESET}")
    
    def export_results(self):
        """导出扫描结果"""
        if not self.results:
            return
            
        self.print_header()
        print(f"\n{BOLD}{WHITE}【导出结果】{RESET}\n")
        
        file_path = input(f"{CYAN}请输入导出文件路径: {RESET}")
        if not file_path:
            print(f"{YELLOW}导出取消。{RESET}")
            time.sleep(1)
            return
            
        self.results.output_file = file_path
        self.results.save_to_file()
        
        print(f"\n{GREEN}结果已保存到: {file_path}{RESET}")
        json_file = f"{os.path.splitext(file_path)[0]}.json"
        html_file = f"{os.path.splitext(file_path)[0]}.html"
        print(f"{GREEN}JSON格式: {json_file}{RESET}")
        print(f"{GREEN}HTML格式: {html_file}{RESET}")
        
        input(f"\n{CYAN}按任意键返回主菜单...{RESET}")

    def show_about_menu(self):
        """显示关于菜单"""
        self.print_header()
        print(f"\n{BOLD}{WHITE}【关于自适应信息收集工具】{RESET}\n")
        
        about_text = [
            "自适应信息收集工具 (CyberRecon)",
            "版本: 1.0.0",
            "",
            "这是一款高级的信息收集工具，能够根据目标反应自动调整扫描策略。",
            "主要特点:",
            "  - 多种扫描模式: 从激进到极度隐蔽",
            "  - 自适应策略调整: 基于AI引擎对目标反应的分析",
            "  - 全面的信息收集: 端口扫描、服务检测、Web服务探测、漏洞检测等",
            "  - 详细的报告生成: 文本、JSON和HTML格式",
            "",
            "使用说明:",
            "  1. 从主菜单选择'开始新扫描'",
            "  2. 设置目标和扫描模式",
            "  3. 等待扫描完成，查看结果",
            "",
            "注意: 请遵守相关法律法规，仅对授权的系统进行扫描。"
        ]
        
        if HAS_RICH:
            for line in about_text:
                if not line:
                    self.console.print()
                elif line.startswith("自适应信息"):
                    self.console.print(f"[bold cyan]{line}[/bold cyan]")
                elif line.startswith("版本:"):
                    self.console.print(f"[yellow]{line}[/yellow]")
                elif line.startswith("  -"):
                    self.console.print(f"[green]{line}[/green]")
                elif line.startswith("注意:"):
                    self.console.print(f"[bold red]{line}[/bold red]")
                else:
                    self.console.print(line)
        else:
            for line in about_text:
                if not line:
                    print()
                elif line.startswith("自适应信息"):
                    print(f"{CYAN_BRIGHT}{line}{RESET}")
                elif line.startswith("版本:"):
                    print(f"{YELLOW}{line}{RESET}")
                elif line.startswith("  -"):
                    print(f"{GREEN}{line}{RESET}")
                elif line.startswith("注意:"):
                    print(f"{RED}{BOLD}{line}{RESET}")
                else:
                    print(line)
        
        print("\n" + CYAN_BRIGHT + "-"*TERM_WIDTH + RESET)
        input(f"\n{CYAN}按任意键返回主菜单...{RESET}")
        self.current_menu = "main"
    
    def run(self):
        """运行交互式界面主循环"""
        # 显示启动画面
        self.show_splash_screen()
        
        # 主菜单循环
        while self.current_menu != "exit":
            if self.current_menu == "main":
                self.show_main_menu()
            elif self.current_menu == "scan":
                self.show_scan_menu()
            elif self.current_menu == "results":
                self.show_results_menu()
            elif self.current_menu == "settings":
                self.show_settings_menu()
            elif self.current_menu == "about":
                self.show_about_menu()
            else:
                # 未知菜单，返回主菜单
                self.current_menu = "main"
        
        # 退出前清屏
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"\n{CYAN_BRIGHT}感谢使用自适应信息收集工具！{RESET}\n")
        
    def show_settings_menu(self):
        """显示设置菜单"""
        self.print_header()
        print(f"\n{BOLD}{WHITE}【扫描设置】{RESET}\n")
        
        print(f"{CYAN}1{RESET}. 设置摘要间隔 (当前: {self.scan_settings['summary_interval']}秒)")
        print(f"{CYAN}2{RESET}. 导出路径设置")
        print(f"{CYAN}0{RESET}. 返回主菜单")
        
        choice = input(f"\n{CYAN}请选择操作 [0-2]: {RESET}")
        
        if choice == '1':
            try:
                interval = int(input(f"{CYAN}请输入新的摘要间隔(秒): {RESET}"))
                if interval > 0:
                    self.scan_settings["summary_interval"] = interval
                    print(f"{GREEN}已设置摘要间隔为 {interval} 秒{RESET}")
                else:
                    print(f"{YELLOW}间隔必须大于0{RESET}")
            except ValueError:
                print(f"{RED}输入无效，请输入整数{RESET}")
        elif choice == '2':
            output_file = input(f"{CYAN}请输入默认导出文件路径 (留空则不设置): {RESET}")
            self.scan_settings["output_file"] = output_file if output_file else None
            if output_file:
                print(f"{GREEN}已设置导出路径为: {output_file}{RESET}")
            else:
                print(f"{YELLOW}未设置导出路径{RESET}")
        elif choice == '0':
            self.current_menu = "main"
        
        # 如果不是返回主菜单，停留在设置菜单
        if choice != '0':
            time.sleep(1)

def launch_cli_interface():
    """启动命令行交互式界面"""
    try:
        cli = CyberReconCLI()
        cli.run()
        return 0
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}用户中断，正在退出...{RESET}")
        return 0
    except Exception as e:
        logger = logging.getLogger("adaptive_recon")
        logger.error(f"交互式界面出错: {str(e)}")
        print(f"{RED}发生错误: {str(e)}{RESET}")
        return 1

if __name__ == "__main__":
    sys.exit(launch_cli_interface())