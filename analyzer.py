import logging
import re
import time
from collections import deque

logger = logging.getLogger("adaptive_recon")

class ResponseAnalyzer:
    def __init__(self):
        self.response_history = deque(maxlen=100)  # 保存最近的100条响应记录
        self.connection_failures = 0
        self.timeout_count = 0
        self.reset_count = 0
        self.last_analysis_time = time.time()
        self.analysis_interval = 30  # 每30秒进行一次综合分析
        
    def analyze(self, scan_results):
        """分析扫描结果和目标响应"""
        current_time = time.time()
        
        # 计算新发现的信息数量
        new_findings = self._count_new_findings(scan_results)
        
        # 记录响应数据
        for result in scan_results:
            self.response_history.append({
                'time': current_time,
                'data': result
            })
        
        # 解析响应中的关键信息
        self._parse_response_data(scan_results)
        
        # 定期进行全面分析
        analysis_result = None
        if current_time - self.last_analysis_time >= self.analysis_interval:
            analysis_result = self._comprehensive_analysis()
            self.last_analysis_time = current_time
            
            # 添加新发现的信息数量和原始结果到分析结果
            if analysis_result:
                analysis_result['new_findings'] = new_findings
                analysis_result['raw_results'] = scan_results
            
        return analysis_result
    
    def _parse_response_data(self, results):
        """解析响应数据中的特定模式"""
        for result in results:
            # 检查连接重置
            if "connection reset" in str(result).lower():
                self.reset_count += 1
                logger.debug("检测到连接重置")
                
            # 检查超时
            if "timeout" in str(result).lower():
                self.timeout_count += 1
                logger.debug("检测到连接超时")
                
            # 检查连接失败
            if "connection refused" in str(result).lower():
                self.connection_failures += 1
                logger.debug("检测到连接被拒绝")
                
            # 检查防火墙特征
            if self._check_firewall_patterns(result):
                logger.debug("检测到可能的防火墙特征")
    
    def _check_firewall_patterns(self, response):
        """检查响应中是否包含防火墙、WAF或IDS/IPS的特征"""
        firewall_patterns = [
            "forbidden", "blocked", "security", 
            "waf", "firewall", "protection",
            "denied", "403", "unauthorized"
        ]
        
        response_str = str(response).lower()
        for pattern in firewall_patterns:
            if pattern in response_str:
                return True
                
        return False
    
    def _comprehensive_analysis(self):
        """定期进行全面分析，判断目标系统的安全状态和反应"""
        # 重置计数清零
        resets_per_minute = (self.reset_count * 60) / self.analysis_interval
        
        # 超时计数清零  
        timeouts_per_minute = (self.timeout_count * 60) / self.analysis_interval
        
        # 连接失败计数清零
        failures_per_minute = (self.connection_failures * 60) / self.analysis_interval
        
        # 清零计数器
        self.reset_count = 0
        self.timeout_count = 0
        self.connection_failures = 0
        
        analysis_result = {
            'time': time.time(),
            'resets_per_minute': resets_per_minute,
            'timeouts_per_minute': timeouts_per_minute,
            'failures_per_minute': failures_per_minute,
            'detection_risk': self._calculate_detection_risk(resets_per_minute, timeouts_per_minute, failures_per_minute),
            'recommendations': []
        }
        
        # 根据分析添加建议
        if analysis_result['detection_risk'] > 0.7:
            analysis_result['recommendations'].append("high_risk")
            logger.warning("检测风险高：建议切换到极度隐蔽模式")
        elif analysis_result['detection_risk'] > 0.4:
            analysis_result['recommendations'].append("medium_risk")
            logger.info("检测风险中等：建议采用更隐蔽的扫描策略")
        else:
            analysis_result['recommendations'].append("low_risk")
            logger.debug("检测风险低：可以维持当前扫描策略")
            
        # 检查是否有防火墙或IDS
        if self._check_security_systems():
            analysis_result['recommendations'].append("security_system_detected")
            logger.info("检测到安全系统：建议模拟合法流量")
            
        return analysis_result
    
    def _calculate_detection_risk(self, resets, timeouts, failures):
        """计算被检测的风险等级 (0-1)"""
        # 计算风险得分
        # 连接重置通常是安全系统明确的拦截信号
        reset_factor = min(resets * 0.2, 0.6)  
        
        # 超时可能意味着数据包被丢弃
        timeout_factor = min(timeouts * 0.1, 0.3)
        
        # 连接失败可能是端口关闭或被过滤
        failure_factor = min(failures * 0.05, 0.1)
        
        risk = reset_factor + timeout_factor + failure_factor
        return min(risk, 1.0)  # 确保风险值不超过1
    
    def _check_security_systems(self):
        """检查目标是否部署了安全系统"""
        # 分析响应历史，寻找安全系统特征
        security_indicators = 0
        
        for response in self.response_history:
            if isinstance(response.get('data'), str):
                response_data = response['data'].lower()
                
                # 检查常见的安全系统响应特征
                if any(x in response_data for x in ["forbidden", "blocked", "waf", "security"]):
                    security_indicators += 1
                    
                # 检查一致的响应模式，可能表示安全系统正在规范化响应
                if re.search(r'(denied|blocked) by (rule|policy) \d+', response_data):
                    security_indicators += 1
        
        # 如果有足够多的安全系统指标，认为目标部署了安全系统
        return security_indicators >= 2

    def _count_new_findings(self, results):
        """估算这次扫描发现的新信息数量"""
        if not results:
            return 0
        
        # 简单统计新发现的端口、服务、漏洞数量
        new_count = 0
        
        # 仅统计明显的新发现
        for result in results:
            # 端口发现
            if "Port" in str(result) and "open" in str(result):
                new_count += 1
            # 服务识别
            if "Service on port" in str(result):
                new_count += 1
            # 漏洞发现
            if "漏洞" in str(result) or "vulnerability" in str(result).lower():
                new_count += 2  # 漏洞发现权重更高
            # Web服务、路径发现
            if "Web服务" in str(result) or "发现路径" in str(result):
                new_count += 1
                
        return new_count
