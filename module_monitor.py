import logging
import time
from collections import defaultdict

logger = logging.getLogger("adaptive_recon")

class ModuleMonitor:
    """监控功能模块的使用情况并提供反馈"""
    
    def __init__(self):
        # 模块调用次数统计
        self.module_calls = defaultdict(int)
        # 模块成功率统计
        self.module_success = defaultdict(int)
        # 模块执行时间统计
        self.module_execution_time = defaultdict(list)
        # 初始化时间
        self.start_time = time.time()
        # 可用模块列表
        self.available_modules = [
            "port_scan", "service_detection", "os_detection", 
            "web_discovery", "host_discovery", "vuln_scan",
            "ssl_scan", "dns_enum", "firewall_detection",
            "web_directory_scan", "cms_scan", "subdomain_enum", 
            "tech_detection", "info_disclosure"
        ]
        
        # 添加被动模式下允许的模块列表
        self.passive_mode_modules = ["web_discovery", "ssl_scan", "tech_detection"]
        # 添加每个环境的必要模块
        self.essential_modules = {
            "default": ["port_scan"],
            "passive": []  # 被动模式下没有必要模块
        }
        # 添加模块跳过次数计数
        self.module_skips = defaultdict(int)
        
    def register_module_call(self, module_name, success=True, execution_time=0):
        """注册一次模块调用"""
        self.module_calls[module_name] += 1
        if success:
            self.module_success[module_name] += 1
        self.module_execution_time[module_name].append(execution_time)
        
    def get_unused_modules(self):
        """获取未被使用过的模块列表"""
        return [module for module in self.available_modules if self.module_calls.get(module, 0) == 0]
        
    def get_module_success_rates(self):
        """获取各模块的成功率"""
        success_rates = {}
        for module, calls in self.module_calls.items():
            if calls > 0:
                success_rates[module] = self.module_success[module] / calls
        return success_rates
        
    def get_average_execution_times(self):
        """获取各模块的平均执行时间"""
        avg_times = {}
        for module, times in self.module_execution_time.items():
            if times:
                avg_times[module] = sum(times) / len(times)
        return avg_times
        
    def generate_report(self):
        """生成模块使用情况报告"""
        # 计算运行时间
        run_time = time.time() - self.start_time
        hours, remainder = divmod(run_time, 3600)
        minutes, seconds = divmod(remainder, 60)
        
        # 生成报告
        report = ["模块监控报告:"]
        report.append(f"总运行时间: {int(hours)}小时 {int(minutes)}分钟 {int(seconds)}秒\n")
        
        # 添加模块调用统计
        report.append("模块调用统计:")
        for module in self.available_modules:
            calls = self.module_calls.get(module, 0)
            if calls > 0:
                success_rate = self.module_success[module] / calls * 100
                avg_time = sum(self.module_execution_time.get(module, [0])) / len(self.module_execution_time.get(module, [1]))
                report.append(f"  - {module}: 调用{calls}次, 成功率: {success_rate:.1f}%, 平均执行时间: {avg_time:.2f}秒")
            else:
                report.append(f"  - {module}: 未调用")
        
        # 添加未使用模块警告
        unused_modules = self.get_unused_modules()
        if unused_modules:
            report.append("\n未使用的模块:")
            for module in unused_modules:
                report.append(f"  - {module}")
        
        # 在报告中添加跳过计数信息
        skipped_modules = {m: count for m, count in self.module_skips.items() if count > 0}
        if skipped_modules:
            report.append("\n模块跳过统计:")
            for module, count in sorted(skipped_modules.items(), key=lambda x: x[1], reverse=True):
                report.append(f"  - {module}: 连续跳过 {count} 次")
        
        # 返回报告文本
        return "\n".join(report)
        
    def check_module_integration(self, strategy, passive_mode=False):
        """检查模块集成状态，确保关键模块被正确使用"""
        enabled_modules = strategy.get("enabled_modules", [])
        unused_modules = self.get_unused_modules()
        
        # 如果在被动模式下，只检查被动模式允许的模块
        if passive_mode:
            enabled_modules = [m for m in enabled_modules if m in self.passive_mode_modules]
            
        # 查找已启用但未使用的模块
        enabled_but_unused = [m for m in enabled_modules if m in unused_modules]
        
        if enabled_but_unused:
            # 增加这些模块的跳过计数
            for module in enabled_but_unused:
                self.module_skips[module] += 1
                
            # 如果模块被连续多次跳过，才发出警告
            persistent_unused = [m for m in enabled_but_unused if self.module_skips[m] >= 3]
            if persistent_unused:
                logger.warning(f"以下模块已启用但连续多次未被使用: {', '.join(persistent_unused)}")
                return False
        return True
    
    def reset_skip_count(self, module):
        """重置模块跳过计数"""
        if module in self.module_skips:
            self.module_skips[module] = 0
