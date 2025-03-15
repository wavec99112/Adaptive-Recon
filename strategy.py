import logging
import time
import random
import os
from collections import deque

logger = logging.getLogger("adaptive_recon")

class StrategyManager:
    def __init__(self, initial_mode="smart"):
        self.current_strategy = self._get_strategy_by_mode(initial_mode)
        self.previous_strategy = None
        self.detection_events = deque(maxlen=100)  # 记录最近100次检测事件
        self.last_strategy_change = time.time()
        self.min_strategy_change_interval = 60  # 最小策略变更间隔(秒)
        self.last_detection_ratio = 0.0  # 上次计算的检测率
        self.strategies_history = []  # 记录策略历史
        self.effectiveness_map = {}  # 记录每种策略的有效性
        
    def _get_strategy_by_mode(self, mode):
        """根据模式返回相应的策略配置"""
        strategies = {
            # 激进模式 - 快速但容易被检测
            "aggressive": {
                "port_scan_type": "syn",  # SYN扫描速度快但容易被检测
                "port_range": [1, 10000],  # 扫描前10000个端口
                "scan_delay": 0.05,  # 扫描延迟很短
                "enabled_modules": [
                    "port_scan", "service_detection", "os_detection", 
                    "web_discovery", "host_discovery", "vuln_scan",
                    "ssl_scan", "dns_enum", "firewall_detection",
                    "web_directory_scan", "cms_scan", "subdomain_enum", 
                    "tech_detection", "info_disclosure"
                ],
                "probe_timeout": 1,  # 服务探测的超时时间
                "ttl_probe_count": 5,  # OS检测发送的探测包数量
                "randomize_probes": False,  # 不随机化探测
                "traffic_pattern": "burst",  # 集中突发流量
                "use_decoys": False,  # 不使用诱饵
                "fragment_packets": False,  # 不分片数据包
                "ip_spoofing": False,  # 不使用IP欺骗
                "use_tor": False,  # 不使用Tor网络
                "threading": {
                    "enabled": True,
                    "max_workers": 20
                },
                "rotate_user_agent": False,  # 不轮换User-Agent
                "connection_timeout": 2,  # 连接超时时间短
            },
            # 隐蔽模式 - 慢但难以检测
            "stealth": {
                "port_scan_type": "null",  # NULL扫描更隐蔽
                "port_range": [20, 21, 22, 23, 25, 53, 80, 443, 8080, 8443],  # 只扫描常见端口
                "scan_delay": random.uniform(1.5, 3.0),  # 扫描之间有较长延迟
                "enabled_modules": [
                    "port_scan", "service_detection", "web_discovery",
                    "ssl_scan"
                ],  # 增加SSL扫描，保持隐蔽性的同时提高信息收集能力
                "probe_timeout": 3,  # 较长的探测超时
                "ttl_probe_count": 1,  # 最少的OS探测
                "randomize_probes": True,  # 随机化探测
                "traffic_pattern": "random",  # 随机化流量模式
                "use_decoys": True,  # 使用诱饵
                "fragment_packets": True,  # 分片数据包
                "ip_spoofing": False,  # 不使用IP欺骗，避免复杂性
                "use_tor": False,  # 不默认使用Tor
                "threading": {
                    "enabled": True,
                    "max_workers": 3
                },
                "rotate_user_agent": True,  # 轮换User-Agent
                "connection_timeout": 5,  # 连接超时时间长
            },
            # 智能模式 - 平衡的方法
            "smart": {
                "port_scan_type": "connect",  # 连接扫描相对平衡
                "port_range": [21, 22, 23, 25, 53, 80, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443],  # 常用服务端口
                "scan_delay": random.uniform(0.5, 1.0),  # 中等延迟
                "enabled_modules": [
                    "port_scan", "service_detection", "web_discovery", 
                    "ssl_scan", "firewall_detection", "tech_detection",
                    "cms_scan", "os_detection", "subdomain_enum"  # 添加os_detection
                ],  # 平衡的功能集
                "probe_timeout": 2,  # 中等超时
                "ttl_probe_count": 3,  # 中等数量的OS探测
                "randomize_probes": True,  # 随机化探测
                "traffic_pattern": "distributed",  # 分布式流量
                "use_decoys": False,  # 不使用诱饵
                "fragment_packets": False,  # 不分片数据包
                "ip_spoofing": False,
                "use_tor": False,
                "threading": {
                    "enabled": True,
                    "max_workers": 10
                },
                "rotate_user_agent": True,  # 轮换User-Agent
                "connection_timeout": 3,  # 连接超时时间适中
            },
            # 低噪音模式 - 模拟合法流量
            "low_noise": {
                "port_scan_type": "connect",  # 标准连接
                "port_range": [80, 443, 8080],  # 只探测Web服务端口
                "scan_delay": random.uniform(3.0, 8.0),  # 长延迟
                "enabled_modules": [
                    "port_scan", "web_discovery", "ssl_scan", "tech_detection",
                    "info_disclosure"  # 添加信息泄露检测
                ],  # 基本Web相关扫描
                "probe_timeout": 5,  # 长超时
                "ttl_probe_count": 0,  # 不进行OS探测
                "randomize_probes": True,  # 随机化探测
                "traffic_pattern": "mimicry",  # 模拟正常用户流量
                "use_decoys": False,  # 不使用诱饵
                "fragment_packets": False,  # 不分片
                "ip_spoofing": False,
                "use_tor": False,
                "threading": {
                    "enabled": False,
                    "max_workers": 2
                },
                "rotate_user_agent": True,  # 轮换User-Agent
                "connection_timeout": 8,  # 连接超时时间长
            },
            # 极度隐蔽模式 - 最小化检测风险
            "ultra_stealth": {
                "port_scan_type": "connect",  # 标准连接但高度分散
                "port_range": [80, 443],  # 只探测最常见的Web端口
                "scan_delay": random.uniform(10.0, 30.0),  # 极长延迟
                "enabled_modules": ["port_scan", "web_discovery"],  # 添加web_discovery，不仅仅是端口扫描
                "probe_timeout": 10,  # 极长超时
                "ttl_probe_count": 0,  # 不进行OS探测
                "randomize_probes": True,  # 随机化探测
                "traffic_pattern": "mimicry",  # 完全模拟正常流量
                "use_decoys": False,  # 在这种模式下诱饵可能增加检测风险
                "fragment_packets": False,  # 不分片
                "ip_spoofing": False,  # 不使用IP欺骗
                "use_tor": True,  # 使用Tor网络
                "threading": {
                    "enabled": False,
                    "max_workers": 1
                },
                "rotate_user_agent": True,  # 轮换User-Agent
                "connection_timeout": 15,  # 连接超时时间非常长
            },
            # 定制模式 - 自定义模式，允许灵活配置
            "custom": {
                "port_scan_type": "connect",  
                "port_range": [80, 443, 22, 21, 25, 8080, 8443],  
                "scan_delay": 1.0,  
                "enabled_modules": [
                    "port_scan", "service_detection", "web_discovery", 
                    "tech_detection", "ssl_scan"
                ],
                "probe_timeout": 3,  
                "ttl_probe_count": 2,  
                "randomize_probes": True,  
                "traffic_pattern": "distributed",  
                "use_decoys": False,  
                "fragment_packets": False,  
                "ip_spoofing": False,
                "use_tor": False,
                "threading": {
                    "enabled": True,
                    "max_workers": 5
                },
                "rotate_user_agent": True,
                "connection_timeout": 5,
            }
        }
        
        # 确保策略包含passive_mode字段
        strategy = strategies.get(mode, strategies["smart"]).copy()
        if "passive_mode" not in strategy:
            strategy["passive_mode"] = False
        
        return strategy
    
    def register_detection_event(self):
        """记录一次可能的检测事件"""
        self.detection_events.append(time.time())
        logger.debug("记录了一次可能的检测事件")
        
        # 检查是否需要更新策略
        self._check_detection_rate()
    
    def _check_detection_rate(self):
        """检查最近的检测率，必要时调整策略"""
        now = time.time()
        
        # 如果距离上次策略变更不足最小间隔，则不执行
        if now - self.last_strategy_change < self.min_strategy_change_interval:
            return
            
        # 计算最近一分钟内的检测事件数量
        recent_events = sum(1 for t in self.detection_events if now - t <= 60)
        
        # 计算检测率 (每分钟事件数)
        detection_rate = recent_events
        
        # 如果检测率高，切换到更隐蔽的策略
        if detection_rate >= 5:  # 每分钟5次以上检测尝试
            self._switch_to_more_stealthy()
        elif detection_rate >= 3:  # 每分钟3-5次检测尝试
            if not self._is_low_noise_mode():
                self._switch_to_low_noise()
        elif detection_rate <= 1 and self.last_detection_ratio > 2:
            # 如果检测率显著下降，可以考虑稍微提高攻击性
            self._switch_to_more_aggressive()
            
        # 更新上次检测率
        self.last_detection_ratio = detection_rate
    
    def _switch_to_more_stealthy(self):
        """切换到更隐蔽的策略"""
        logger.info("检测到高频率检测事件，切换到极度隐蔽模式")
        self.previous_strategy = self.current_strategy
        self.current_strategy = self._get_strategy_by_mode("ultra_stealth")
        self.last_strategy_change = time.time()
    
    def _switch_to_low_noise(self):
        """切换到低噪音模式"""
        logger.info("检测到中等频率检测事件，切换到低噪音模式")
        self.previous_strategy = self.current_strategy
        self.current_strategy = self._get_strategy_by_mode("low_noise")
        self.last_strategy_change = time.time()
    
    def _switch_to_more_aggressive(self):
        """切换到更激进的策略，但不超过智能模式"""
        # 只有当前在ultra_stealth或low_noise模式时才提升激进性
        if self._is_ultra_stealth_mode():
            logger.info("检测事件减少，从极度隐蔽模式提升到低噪音模式")
            self.previous_strategy = self.current_strategy
            self.current_strategy = self._get_strategy_by_mode("low_noise")
            self.last_strategy_change = time.time()
        elif self._is_low_noise_mode():
            logger.info("检测事件减少，从低噪音模式提升到智能模式")
            self.previous_strategy = self.current_strategy
            self.current_strategy = self._get_strategy_by_mode("smart")
            self.last_strategy_change = time.time()
    
    def _is_ultra_stealth_mode(self):
        """检查当前是否为极度隐蔽模式"""
        return self.current_strategy.get("scan_delay", 0) >= 10.0
    
    def _is_low_noise_mode(self):
        """检查当前是否为低噪音模式"""
        return (not self._is_ultra_stealth_mode() and 
                self.current_strategy.get("scan_delay", 0) >= 3.0)
    
    def get_scan_interval(self):
        """获取两次扫描之间的间隔时间"""
        # 基础间隔时间
        base_interval = 5
        
        # 根据当前策略调整间隔
        if self._is_ultra_stealth_mode():
            # 在极度隐蔽模式下，使用更大的随机间隔
            return base_interval + random.uniform(30, 60)
        elif self._is_low_noise_mode():
            # 在低噪音模式下，使用中等随机间隔
            return base_interval + random.uniform(10, 30)
        else:
            # 在其他模式下，使用较小的随机间隔
            return base_interval + random.uniform(1, 10)
    
    def register_strategy_effectiveness(self, strategy_name, success_rate):
        """记录策略的有效性"""
        if strategy_name not in self.effectiveness_map:
            self.effectiveness_map[strategy_name] = []
            
        self.effectiveness_map[strategy_name].append(success_rate)
        
        # 只保留最近10次测量
        if len(self.effectiveness_map[strategy_name]) > 10:
            self.effectiveness_map[strategy_name] = self.effectiveness_map[strategy_name][-10:]
    
    def get_most_effective_strategy(self):
        """返回历史上最有效的策略"""
        if not self.effectiveness_map:
            return "smart"  # 默认
            
        # 计算每种策略的平均有效性
        avg_effectiveness = {}
        for strategy, rates in self.effectiveness_map.items():
            if rates:
                avg_effectiveness[strategy] = sum(rates) / len(rates)
                
        # 找出最有效的策略
        if avg_effectiveness:
            return max(avg_effectiveness, key=avg_effectiveness.get)
        return "smart"
    
    def create_custom_strategy(self, base_mode="smart", **kwargs):
        """创建自定义策略，基于现有模式，并允许覆盖特定参数"""
        # 获取基础策略
        base_strategy = self._get_strategy_by_mode(base_mode)
        
        # 创建自定义策略的副本
        custom_strategy = base_strategy.copy()
        
        # 应用提供的参数覆盖
        for key, value in kwargs.items():
            if key in custom_strategy:
                custom_strategy[key] = value
        
        return custom_strategy
    
    def use_tor_if_available(self):
        """尝试使用Tor网络，如果可用"""
        try:
            import socks
            import socket
            
            # 检查Tor是否运行（默认端口9050）
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            result = s.connect_ex(('127.0.0.1', 9050))
            s.close()
            
            if result == 0:
                # Tor正在运行
                socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050)
                socket.socket = socks.socksocket
                logger.info("成功配置Tor代理")
                return True
            else:
                logger.warning("未检测到Tor服务，继续使用直接连接")
                return False
        except ImportError:
            logger.warning("未安装PySocks库，无法使用Tor")
            return False
        except Exception as e:
            logger.warning(f"配置Tor时出错: {str(e)}")
            return False

    def save_strategy_history(self, file_path="strategy_history.json"):
        """将策略历史保存到文件"""
        import json
        
        history_data = {
            "strategy_history": self.strategies_history,
            "effectiveness_map": self.effectiveness_map
        }
        
        try:
            with open(file_path, 'w') as f:
                json.dump(history_data, f, indent=2)
            logger.debug(f"策略历史已保存到 {file_path}")
        except Exception as e:
            logger.warning(f"保存策略历史时出错: {str(e)}")
