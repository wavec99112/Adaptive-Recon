#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import logging
import sys
import time
from scanner import Scanner
from analyzer import ResponseAnalyzer
from strategy import StrategyManager
from ai_engine import AdaptiveEngine
from results import ResultManager

def setup_logger(log_file=None, verbose=False):
    logger = logging.getLogger("adaptive_recon")
    
    # 设置日志级别
    if verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    
    # 添加控制台handler
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    
    # 如果提供了日志文件，也添加文件handler
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
    return logger

def parse_arguments():
    parser = argparse.ArgumentParser(description='自适应信息收集工具')
    parser.add_argument('-t', '--target', help='目标主机或网络')
    parser.add_argument('-m', '--mode', default='smart', choices=['aggressive', 'stealth', 'smart', 'low_noise', 'ultra_stealth', 'custom'],
                        help='初始扫描模式: aggressive(激进), stealth(隐蔽), smart(智能), low_noise(低噪音), ultra_stealth(极度隐蔽), custom(自定义)')
    parser.add_argument('-o', '--output', help='输出结果的文件路径')
    parser.add_argument('-v', '--verbose', action='store_true', help='显示详细信息')
    parser.add_argument('-s', '--summary-interval', type=int, default=120, 
                        help='结果总结显示间隔(秒)，默认120秒')
    parser.add_argument('-p', '--passive', action='store_true', help='启用被动信息收集')
    parser.add_argument('-i', '--interactive', action='store_true', help='启动交互式命令行界面')
    parser.add_argument('--log-file', help='日志文件路径')
    return parser.parse_args()

def run_scan_loop(target, mode, output_file, verbose, summary_interval, passive_mode):
    """运行主扫描循环"""
    logger = logging.getLogger("adaptive_recon")
    logger.info(f"开始对 {target} 进行自适应信息收集")
    
    # 初始化各模块
    strategy_manager = StrategyManager(initial_mode=mode)
    
    # 将目标也添加到策略中，使其可被其他模块访问
    strategy_manager.current_strategy["target"] = target
    strategy_manager.current_strategy["passive_mode"] = passive_mode
    
    analyzer = ResponseAnalyzer()
    ai_engine = AdaptiveEngine(strategy_manager)
    result_manager = ResultManager(target, output_file)
    scanner = Scanner(target, strategy_manager, passive_mode)
    
    # 输出当前启用的扫描模块，增加透明度
    enabled_modules = strategy_manager.current_strategy["enabled_modules"]
    logger.info(f"已启用的扫描模块: {', '.join(enabled_modules)}")
    
    last_summary_time = time.time()
    scan_count = 0
    
    try:
        while True:
            scan_count += 1
            # 执行扫描
            scan_results = scanner.scan()
            
            # 分析目标响应
            response_data = analyzer.analyze(scan_results)
            
            # AI引擎评估和调整策略
            strategy_changed = ai_engine.evaluate_and_adapt(response_data)
            
            if strategy_changed:
                logger.info(f"策略已调整为: {strategy_manager.current_strategy}")
            
            # 处理结果
            new_findings = result_manager.process_results(scan_results)
            
            # 输出结果
            if new_findings > 0:
                logger.info(f"收集到新信息: {new_findings} 条")
                if output_file:
                    result_manager.save_to_file()
            
            # 定期显示总结
            current_time = time.time()
            if current_time - last_summary_time >= summary_interval:
                summary = result_manager.get_summary()
                logger.info("--- 信息收集总结 ---")
                for line in summary.split('\n'):
                    if line.strip():
                        logger.info(line)
                logger.info(f"已执行扫描次数: {scan_count}")
                last_summary_time = current_time
            
            # 等待下一次扫描
            time.sleep(strategy_manager.get_scan_interval())
            
    except KeyboardInterrupt:
        logger.info("用户中断，正在退出...")
        # 保存最终结果
        if output_file:
            result_manager.save_to_file()
        # 显示最终总结
        summary = result_manager.get_summary()
        logger.info("--- 最终信息收集总结 ---")
        for line in summary.split('\n'):
            if line.strip():
                logger.info(line)
                
    return result_manager

def main():
    args = parse_arguments()
    
    # 设置日志
    logger = setup_logger(args.log_file, args.verbose)
    
    # 如果没有参数或明确指定交互模式，启动交互式命令行界面
    if args.interactive or len(sys.argv) == 1:
        try:
            from cli_interface import launch_cli_interface
            return launch_cli_interface()
        except ImportError as e:
            logger.error(f"无法启动交互式界面: {str(e)}")
            logger.error("请确保已安装所需依赖: pip install colorama rich pyfiglet terminaltables")
            return 1
    
    # 命令行模式需要提供目标
    if not args.target:
        logger.error("请提供扫描目标 (-t 或 --target)")
        return 1
    
    # 运行扫描循环
    try:
        run_scan_loop(args.target, args.mode, args.output, 
                    args.verbose, args.summary_interval, args.passive)
    except Exception as e:
        logger.error(f"发生错误: {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
