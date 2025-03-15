import logging
import random
import re
import time
import numpy as np
from collections import deque

logger = logging.getLogger("adaptive_recon")

class AdaptiveEngine:
    def __init__(self, strategy_manager):
        self.strategy_manager = strategy_manager
        self.learning_rate = 0.1  # AI学习率
        self.exploration_rate = 0.2  # 探索率 - 随机尝试新策略的概率
        self.history = deque(maxlen=100)  # 存储历史决策和结果
        self.success_threshold = 0.6  # 成功阈值
        self.last_decision_time = time.time()
        self.decision_interval = 60  # 最小决策间隔(秒)
        
        # 各种策略模式的权重
        self.strategy_weights = {
            "aggressive": 0.2,
            "smart": 0.5,
            "stealth": 0.7,
            "low_noise": 0.8,
            "ultra_stealth": 0.9
        }
        
        # 模块使用历史记录
        self.module_usage_history = {}
        # 模块有效性评估
        self.module_effectiveness = {}
        # 初始化所有可用模块
        self.available_modules = [
            "port_scan", "service_detection", "os_detection", 
            "web_discovery", "host_discovery", "vuln_scan",
            "ssl_scan", "dns_enum", "firewall_detection",
            "web_directory_scan", "cms_scan", "subdomain_enum", 
            "tech_detection", "info_disclosure"
        ]
        
        # 初始化模块有效性评分
        for module in self.available_modules:
            self.module_effectiveness[module] = 0.5  # 初始平均评分
            
        # 模块依赖关系
        self.module_dependencies = {
            "service_detection": ["port_scan"],  # 服务检测依赖于端口扫描
            "web_discovery": ["port_scan"],      # Web服务发现依赖于端口扫描
            "vuln_scan": ["port_scan", "service_detection"],  # 漏洞扫描依赖于服务检测
            "ssl_scan": ["port_scan"],           # SSL扫描依赖于端口扫描
            "web_directory_scan": ["web_discovery"], # Web目录扫描依赖于Web服务发现
            "cms_scan": ["web_discovery"]        # CMS扫描依赖于Web服务发现
        }
        
        # 模块消耗资源评级 (1-10, 10为最高)
        self.module_resource_usage = {
            "port_scan": 5,
            "service_detection": 3,
            "os_detection": 6,
            "web_discovery": 4,
            "host_discovery": 7,
            "vuln_scan": 8,
            "ssl_scan": 3,
            "dns_enum": 4,
            "firewall_detection": 6,
            "web_directory_scan": 9,
            "cms_scan": 7,
            "subdomain_enum": 5,
            "tech_detection": 2,
            "info_disclosure": 7
        }
        
    def evaluate_and_adapt(self, response_data):
        """评估目标响应并适当调整策略，返回是否改变了策略"""
        if not response_data:
            return False
            
        current_time = time.time()
        if current_time - self.last_decision_time < self.decision_interval:
            return False  # 决策间隔内不做新决策
            
        self.last_decision_time = current_time
        
        # 将分析结果存入历史记录
        self.history.append({
            'time': current_time,
            'data': response_data,
            'current_strategy': self._get_current_strategy_name(),
            'active_modules': self.strategy_manager.current_strategy.get("enabled_modules", [])
        })
        
        # 分析目标系统反应
        target_response = self._analyze_target_response(response_data)
        
        # 更新模块有效性
        self._update_module_effectiveness()
        
        # 根据探索率决定是否随机尝试新策略
        if random.random() < self.exploration_rate:
            return self._try_random_strategy()
            
        # 根据目标反应调整策略
        strategy_changed = False
        if target_response['detection_risk'] > 0.7:
            # 高风险情况
            if not self._is_using_ultra_stealth():
                logger.info("AI决策: 检测风险高, 切换到极度隐蔽模式")
                self._apply_strategy("ultra_stealth")
                strategy_changed = True
        elif target_response['detection_risk'] > 0.4:
            # 中等风险情况
            if not self._is_using_low_noise():
                logger.info("AI决策: 检测风险中等, 切换到低噪音模式")
                self._apply_strategy("low_noise")
                strategy_changed = True
        elif target_response['detection_risk'] < 0.2 and "security_system_detected" not in response_data.get('recommendations', []):
            # 低风险且未检测到安全系统，可以考虑更积极的策略
            if self._is_using_ultra_stealth():
                logger.info("AI决策: 检测风险降低, 从极度隐蔽模式提升到低噪音模式")
                self._apply_strategy("low_noise")
                strategy_changed = True
            elif self._is_using_low_noise():
                logger.info("AI决策: 检测风险低, 从低噪音模式提升到智能模式")
                self._apply_strategy("smart")
                strategy_changed = True
        
        # 如果策略未变更，则优化当前策略的模块配置
        if not strategy_changed:
            modules_changed = self._optimize_module_selection()
            if modules_changed:
                logger.info("AI决策: 已优化模块选择，启用最有效的模块组合")
                return True
                
        # 根据学习结果优化策略参数
        self._optimize_strategy_parameters()
        
        return strategy_changed
    
    def _get_current_strategy_name(self):
        """确定当前使用的策略名称"""
        strategy = self.strategy_manager.current_strategy
        scan_delay = strategy.get("scan_delay", 0)
        
        if scan_delay >= 10.0:
            return "ultra_stealth"
        elif scan_delay >= 3.0:
            return "low_noise"
        elif strategy["port_scan_type"] == "null":
            return "stealth"
        elif strategy["port_scan_type"] == "syn" and len(strategy["enabled_modules"]) > 2:
            return "aggressive"
        else:
            return "smart"
    
    def _update_module_effectiveness(self):
        """根据历史结果更新各模块的有效性评分"""
        if len(self.history) < 3:
            return
            
        # 获取最近3条记录
        recent_history = list(self.history)[-3:]
        
        # 统计每个模块的使用次数和发现的新信息数量
        module_stats = {}
        for record in recent_history:
            active_modules = record.get('active_modules', [])
            for module in active_modules:
                if module not in module_stats:
                    module_stats[module] = {"uses": 0, "findings": 0}
                module_stats[module]["uses"] += 1
                
                # 使用record中的new_findings字段，表示该次扫描发现的新信息
                findings = record.get('data', {}).get('new_findings', 1)
                module_stats[module]["findings"] += findings
        
        # 更新每个模块的有效性评分
        for module, stats in module_stats.items():
            if stats["uses"] > 0:
                effectiveness = stats["findings"] / stats["uses"]
                # 使用指数移动平均更新评分
                old_score = self.module_effectiveness.get(module, 0.5)
                self.module_effectiveness[module] = old_score * (1 - self.learning_rate) + effectiveness * self.learning_rate
    
    def _optimize_module_selection(self):
        """智能优化扫描模块选择，确保最佳效率和安全"""
        # 获取当前策略允许的最大模块数
        current_mode = self._get_current_strategy_name()
        max_modules = {
            "aggressive": 14,  # 可以使用所有模块
            "smart": 9, 
            "stealth": 4,
            "low_noise": 5,
            "ultra_stealth": 2
        }.get(current_mode, 5)
        
        # 获取当前启用的模块
        current_modules = self.strategy_manager.current_strategy.get("enabled_modules", [])
        
        # 确保关键模块始终启用
        essential_modules = ["port_scan", "web_discovery"]
        
        # 获取当前环境和目标条件
        target_has_web = self._target_has_web_services()
        target_has_ssl = self._target_has_ssl_services()
        high_risk = self._is_high_risk_target()
        
        # 根据目标条件调整模块选择
        conditional_modules = []
        if target_has_web:
            conditional_modules.extend(["tech_detection", "web_directory_scan", "cms_scan"])
            if not high_risk:
                conditional_modules.append("info_disclosure")
                
        if target_has_ssl:
            conditional_modules.append("ssl_scan")
            
        if not high_risk:
            conditional_modules.extend(["service_detection", "os_detection"])
            if '/' in self.strategy_manager.current_strategy.get("target", ""):  # 有CIDR表示，可能是网络
                conditional_modules.append("host_discovery")
                
        # 如果是非高风险环境，添加DNS枚举和更多扫描
        if not high_risk and current_mode in ["aggressive", "smart"]:
            conditional_modules.append("dns_enum")
            conditional_modules.append("vuln_scan")
            
        # 确保加入防火墙检测
        if not high_risk or self._get_current_strategy_name() == "aggressive":
            conditional_modules.append("firewall_detection")
            
        # 按有效性排序模块
        sorted_modules = sorted(
            [(m, self.module_effectiveness.get(m, 0)) for m in self.available_modules 
             if m not in essential_modules],
            key=lambda x: x[1],
            reverse=True
        )
        
        # 首先添加必要模块
        selected_modules = essential_modules.copy()
        
        # 然后添加条件模块（根据目标环境决定的）
        for module in conditional_modules:
            if module not in selected_modules and module in self.available_modules:
                # 检查是否需要添加依赖
                dependencies = self._get_module_dependencies(module)
                for dep in dependencies:
                    if dep not in selected_modules:
                        selected_modules.append(dep)
                        
                selected_modules.append(module)
                
                # 检查是否达到当前模式的最大模块数量
                if len(selected_modules) >= max_modules:
                    break
        
        # 如果还有空间，按有效性添加其他模块
        remaining_slots = max_modules - len(selected_modules)
        if remaining_slots > 0:
            for module, score in sorted_modules:
                if module not in selected_modules and score > 0.3:
                    # 检查是否需要添加依赖
                    dependencies = self._get_module_dependencies(module)
                    deps_to_add = [d for d in dependencies if d not in selected_modules]
                    
                    # 确保添加所有依赖后不超过限制
                    if len(deps_to_add) + 1 <= remaining_slots:
                        for dep in deps_to_add:
                            selected_modules.append(dep)
                            remaining_slots -= 1
                            
                        selected_modules.append(module)
                        remaining_slots -= 1
                
                if remaining_slots <= 0:
                    break
        
        # 如果是被动模式，过滤掉所有主动模块，只保留被动模块
        if self.strategy_manager.current_strategy.get("passive_mode", False):
            passive_modules = ["web_discovery", "ssl_scan", "tech_detection"]
            selected_modules = [m for m in selected_modules if m in passive_modules]
            if not selected_modules:  # 确保至少有一个模块被启用
                selected_modules = ["web_discovery"]
                logger.info("被动模式下至少启用一个模块: web_discovery")
        
        # 检查是否有变化，并记录当前使用情况
        current_modules_set = set(current_modules)
        selected_modules_set = set(selected_modules)
        
        if current_modules_set != selected_modules_set:
            # 增加日志记录，方便调试
            removed_modules = current_modules_set - selected_modules_set
            added_modules = selected_modules_set - current_modules_set
            
            if removed_modules:
                logger.debug(f"AI优化: 移除模块: {', '.join(removed_modules)}")
            if added_modules:
                logger.debug(f"AI优化: 添加模块: {', '.join(added_modules)}")
                
            # 更新策略
            self.strategy_manager.current_strategy["enabled_modules"] = selected_modules
            logger.info(f"AI优化: 已选择最佳模块组合: {', '.join(selected_modules)}")
            return True
        
        return False
    
    def _get_module_dependencies(self, module):
        """获取模块的所有依赖"""
        dependencies = []
        if module in self.module_dependencies:
            direct_deps = self.module_dependencies.get(module, [])
            for dep in direct_deps:
                if dep not in dependencies:
                    dependencies.append(dep)
                # 递归获取依赖的依赖
                nested_deps = self._get_module_dependencies(dep)
                for nested_dep in nested_deps:
                    if nested_dep not in dependencies:
                        dependencies.append(nested_dep)
        return dependencies
    
    def _target_has_web_services(self):
        """检查目标是否有Web服务"""
        # 分析历史数据，检查是否发现了Web服务
        for entry in self.history:
            data = entry.get('data', {})
            if not data:
                continue
                
            if isinstance(data, dict) and 'raw_results' in data:
                raw_results = data.get('raw_results', [])
                if not raw_results:
                    continue
                    
                for result in raw_results:
                    if isinstance(result, str) and "Web服务" in result:
                        return True
        
        # 检查是否有端口80或443被发现
        for entry in self.history:
            data = entry.get('data', {})
            if isinstance(data, dict) and 'raw_results' in data:
                raw_results = data.get('raw_results', [])
                if not raw_results:
                    continue
                    
                for result in raw_results:
                    if isinstance(result, str) and ("Port 80 is open" in result or "Port 443 is open" in result):
                        return True
                        
        # 默认假设有Web服务，确保不错过它
        return True

    def _target_has_ssl_services(self):
        """检查目标是否有SSL/TLS服务"""
        # 分析历史数据，检查是否发现了SSL服务
        for entry in self.history:
            data = entry.get('data', {})
            if isinstance(data, dict) and 'raw_results' in data:
                raw_results = data['raw_results']
                if not raw_results:
                    continue
                    
                for result in raw_results:
                    if isinstance(result, str) and "SSL/TLS" in result:
                        return True
                        
        # 默认策略，如果发现443或8443端口，假设有SSL服务
        for entry in self.history:
            data = entry.get('data', {})
            if isinstance(data, dict) and 'raw_results' in data:
                raw_results = data['raw_results']
                if not raw_results:
                    continue
                    
                for result in raw_results:
                    if isinstance(result, str) and ("Port 443 is open" in result or "Port 8443 is open" in result):
                        return True
        return False
    
    def _is_high_risk_target(self):
        """判断当前目标是否为高风险环境"""
        if len(self.history) < 2:
            return False
            
        # 获取最近的响应分析结果
        recent = list(self.history)[-2:]
        risks = [entry.get('data', {}).get('detection_risk', 0) for entry in recent]
        
        # 如果最近两次检测风险都高于0.4，认为是高风险环境
        return all(risk > 0.4 for risk in risks)
    
    def _is_using_ultra_stealth(self):
        """检查是否使用极度隐蔽模式"""
        return self._get_current_strategy_name() == "ultra_stealth"
    
    def _is_using_low_noise(self):
        """检查是否使用低噪音模式"""
        return self._get_current_strategy_name() == "low_noise"
    
    def _analyze_target_response(self, response_data):
        """分析目标系统对扫描的反应"""
        result = {
            'detection_risk': response_data.get('detection_risk', 0),
            'has_security_system': "security_system_detected" in response_data.get('recommendations', []),
            'response_pattern': self._identify_response_pattern(),
            'target_type': self._identify_target_type()
        }
        
        return result
    
    def _identify_target_type(self):
        """识别目标系统类型"""
        os_type = "unknown"
        server_types = set()
        is_network = False
        
        # 分析历史数据，查找操作系统和服务器类型的信息
        for entry in self.history:
            data = entry.get('data', {})
            if isinstance(data, dict) and 'raw_results' in data:
                for result in data['raw_results']:
                    # 检查OS信息
                    os_match = re.search(r'操作系统推测: (.+) \(基于TTL值', str(result))
                    if os_match:
                        os_type = os_match.group(1)
                        
                    # 检查Web服务器类型
                    server_match = re.search(r'服务器: ([^,]+)', str(result))
                    if server_match:
                        server = server_match.group(1).strip()
                        if server != "Unknown":
                            server_types.add(server)
                            
                    # 检查是否是网络扫描
                    if "发现网络主机:" in str(result):
                        is_network = True
                        
        return {
            "os_type": os_type,
            "server_types": list(server_types),
            "is_network": is_network
        }
    
    def _identify_response_pattern(self):
        """识别目标反应模式"""
        if len(self.history) < 3:
            return "unknown"
            
        # 获取最近几次响应中的风险评估
        recent_risks = [h['data'].get('detection_risk', 0) for h in list(self.history)[-3:]]
        
        if all(risk > 0.5 for risk in recent_risks):
            return "consistently_defensive"
        elif all(risk < 0.3 for risk in recent_risks):
            return "consistently_permissive"
        elif recent_risks[0] < recent_risks[-1]:
            return "increasing_defense"
        elif recent_risks[0] > recent_risks[-1]:
            return "decreasing_defense"
        else:
            return "fluctuating"
    
    def _try_random_strategy(self):
        """随机尝试不同的策略，用于探索"""
        current = self._get_current_strategy_name()
        
        # 生成备选策略列表
        options = []
        
        # 添加可能的策略调整
        if current == "ultra_stealth":
            options = ["low_noise"]
        elif current == "low_noise":
            options = ["ultra_stealth", "smart"]
        elif current == "smart":
            options = ["low_noise", "stealth"]
        elif current == "stealth":
            options = ["smart", "aggressive"]
        else:  # aggressive
            options = ["smart"]
            
        if not options:
            return False
            
        # 随机选择一个策略
        new_strategy = random.choice(options)
        
        logger.info(f"AI探索: 随机尝试新策略 {new_strategy}")
        self._apply_strategy(new_strategy)
        
        # 同时随机启用/禁用一些模块
        self._randomly_adjust_modules()
        
        return True
    
    def _randomly_adjust_modules(self):
        """随机调整启用的模块，用于探索最优组合"""
        # 获取当前模式下的最大模块数
        current_mode = self._get_current_strategy_name()
        max_modules = {
            "aggressive": 14,  # 可以使用所有模块
            "smart": 9, 
            "stealth": 4,
            "low_noise": 5,
            "ultra_stealth": 2
        }.get(current_mode, 5)
        
        # 确保这些模块始终启用
        essential_modules = ["port_scan"]
        
        # 从非必要模块中随机选择一些
        optional_modules = [m for m in self.available_modules if m not in essential_modules]
        num_to_select = min(max_modules - len(essential_modules), len(optional_modules))
        
        if num_to_select > 0:
            selected_optional = random.sample(optional_modules, num_to_select)
            new_modules = essential_modules + selected_optional
            
            # 更新策略
            self.strategy_manager.current_strategy["enabled_modules"] = new_modules
            logger.info(f"AI探索: 随机选择模块组合: {', '.join(new_modules)}")
    
    def _apply_strategy(self, strategy_name):
        """应用指定的策略"""
        self.strategy_manager.current_strategy = self.strategy_manager._get_strategy_by_mode(strategy_name)
        self.strategy_manager.last_strategy_change = time.time()
        
    def _optimize_strategy_parameters(self):
        """根据历史数据优化当前策略的参数"""
        if len(self.history) < 5:
            return  # 历史数据不足，不进行优化
            
        current_strategy = self.strategy_manager.current_strategy
        strategy_name = self._get_current_strategy_name()
        
        # 计算历史成功率
        success_rate = self._calculate_strategy_success_rate(strategy_name)
        
        # 如果成功率高于阈值，微调当前策略参数
        if success_rate > self.success_threshold:
            # 可能调整的参数
            params_to_adjust = ["scan_delay", "probe_timeout", "ttl_probe_count", "connection_timeout"]
            
            # 随机选择一个参数进行微调
            if random.random() < 0.3:  # 30%几率调整参数
                param = random.choice(params_to_adjust)
                
                if param == "scan_delay":
                    current_value = current_strategy.get(param, 1.0)
                    # 在当前值的基础上微调 ±20%
                    adjustment = current_value * (random.uniform(-0.2, 0.2))
                    
                    # 确保参数在合理范围内
                    min_value = 0.1 if strategy_name == "aggressive" else 0.5
                    max_value = 1.0 if strategy_name == "aggressive" else (
                        3.0 if strategy_name == "smart" else (
                            8.0 if strategy_name == "low_noise" else 30.0
                        )
                    )
                    
                    new_value = max(min_value, min(current_value + adjustment, max_value))
                    current_strategy[param] = new_value
                    logger.debug(f"AI优化: 调整{strategy_name}模式的{param}为 {new_value:.2f}")
                    
                elif param == "probe_timeout":
                    current_value = current_strategy.get(param, 2)
                    # 在当前值的基础上微调 ±1
                    adjustment = random.choice([-1, 0, 1])
                    new_value = max(1, current_value + adjustment)
                    current_strategy[param] = new_value
                    logger.debug(f"AI优化: 调整{strategy_name}模式的{param}为 {new_value}")
                    
                elif param == "ttl_probe_count":
                    current_value = current_strategy.get(param, 3)
                    # 在当前值的基础上微调 ±1
                    adjustment = random.choice([-1, 0, 1])
                    new_value = max(1, current_value + adjustment)
                    current_strategy[param] = new_value
                    logger.debug(f"AI优化: 调整{strategy_name}模式的{param}为 {new_value}")
                    
                elif param == "connection_timeout":
                    current_value = current_strategy.get(param, 3)
                    # 在当前值的基础上微调 ±1
                    adjustment = random.choice([-1, 0, 1])
                    new_value = max(1, current_value + adjustment)
                    current_strategy[param] = new_value
                    logger.debug(f"AI优化: 调整{strategy_name}模式的{param}为 {new_value}")
    
    def _calculate_strategy_success_rate(self, strategy_name):
        """计算特定策略的成功率"""
        # 获取最近使用该策略的历史记录
        strategy_history = [h for h in self.history if h['current_strategy'] == strategy_name]
        
        if not strategy_history:
            return 0.0
            
        # 计算成功次数 (风险评估低于阈值的次数)
        success_count = sum(1 for h in strategy_history 
                         if h['data'].get('detection_risk', 1.0) < 0.4)
                         
        return success_count / len(strategy_history)

    def get_recommendation(self):
        """获取AI对当前扫描的建议"""
        # 分析历史数据
        if len(self.history) < 3:
            return "需要更多数据才能提供准确建议"
            
        # 获取当前模式
        current_mode = self._get_current_strategy_name()
        
        # 检查最近的风险趋势
        risk_trend = self._analyze_risk_trend()
        
        # 基于风险趋势和当前模式提供建议
        if risk_trend == "increasing":
            return "风险趋势上升，建议降低扫描激进性"
        elif risk_trend == "high":
            return "风险持续较高，建议使用更隐蔽的扫描策略或暂停扫描"
        elif risk_trend == "decreasing":
            return "风险趋势下降，可以适当提高扫描效率"
        elif risk_trend == "low":
            return "风险持续较低，可以考虑启用更多功能模块"
        else:
            return "风险波动中，保持当前模式并关注目标反应"
    
    def _analyze_risk_trend(self):
        """分析风险趋势"""
        if len(self.history) < 3:
            return "unknown"
            
        recent = list(self.history)[-3:]
        risks = [entry['data'].get('detection_risk', 0.5) for entry in recent]
        
        avg_risk = sum(risks) / len(risks)
        
        if risks[0] < risks[-1] and (risks[-1] - risks[0]) > 0.1:
            return "increasing"
        elif risks[0] > risks[-1] and (risks[0] - risks[-1]) > 0.1:
            return "decreasing"
        elif avg_risk > 0.6:
            return "high"
        elif avg_risk < 0.3:
            return "low"
        else:
            return "fluctuating"
            
    def get_module_effectiveness_report(self):
        """返回模块有效性评估报告"""
        if not self.module_effectiveness:
            return "尚无模块评估数据"
            
        # 按有效性评分排序
        sorted_modules = sorted(
            self.module_effectiveness.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        report = ["模块有效性评估:"]
        for module, score in sorted_modules:
            status = "高" if score > 0.7 else "中" if score > 0.4 else "低"
            report.append(f"  - {module}: {score:.2f} (有效性: {status})")
            
        return "\n".join(report)
