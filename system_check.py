#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import importlib
import logging
import os

def check_module(module_name, required=True):
    """检查模块是否可用"""
    try:
        importlib.import_module(module_name)
        return True
    except ImportError as e:
        if required:
            print(f"[错误] 缺少必要模块: {module_name}")
            print(f"       错误详情: {e}")
            return False
        else:
            print(f"[警告] 可选模块不可用: {module_name}")
            print(f"       错误详情: {e}")
            return True  # 可选模块，继续检查

def check_system():
    """检查系统需求和依赖"""
    print("\n===== 系统自检开始 =====")

    # 检查Python版本
    py_version = sys.version_info
    print(f"Python版本: {py_version.major}.{py_version.minor}.{py_version.micro}")
    if py_version.major < 3 or (py_version.major == 3 and py_version.minor < 6):
        print("[错误] 需要Python 3.6或更高版本")
        return False

    # 检查必需模块
    required_modules = [
        "scapy", "requests", "OpenSSL", "socket", "logging", 
        "time", "re", "json", "os", "sys", "datetime", "threading", 
        "collections"
    ]
    
    optional_modules = [
        "colorama", "rich", "pyfiglet", "terminaltables", "pdfkit", "chardet",
        "numpy", "concurrent.futures"
    ]
    
    # 检查核心模块
    core_modules = [
        "scanner", "analyzer", "strategy", "ai_engine", "results", 
        "report_generator", "cli_interface"
    ]
    
    all_passed = True
    
    # 检查必需模块
    print("\n检查必需系统模块:")
    for module in required_modules:
        if not check_module(module, required=True):
            all_passed = False
    
    # 检查可选模块
    print("\n检查可选系统模块:")
    for module in optional_modules:
        check_module(module, required=False)
    
    # 检查核心模块
    print("\n检查核心模块:")
    for module in core_modules:
        if not check_module(module, required=True):
            all_passed = False
    
    # 检查核心功能
    print("\n检查核心功能关联:")
    try:
        from scanner import Scanner
        from strategy import StrategyManager
        
        # 测试策略管理器
        strategy_manager = StrategyManager(initial_mode="smart")
        print("[通过] 策略管理器初始化")
        
        # 测试扫描器
        scanner = Scanner("127.0.0.1", strategy_manager)
        print("[通过] 扫描器初始化")
        
        # 测试其他核心组件
        from analyzer import ResponseAnalyzer
        analyzer = ResponseAnalyzer()
        print("[通过] 响应分析器初始化")
        
        from ai_engine import AdaptiveEngine
        ai_engine = AdaptiveEngine(strategy_manager)
        print("[通过] AI引擎初始化")
        
        from results import ResultManager
        result_manager = ResultManager("test_target")
        print("[通过] 结果管理器初始化")
        
        # 检查是否可以生成报告
        try:
            from report_generator import generate_html_report
            print("[通过] 报告生成器模块可用")
        except ImportError:
            print("[警告] HTML报告生成器不可用")
        
    except Exception as e:
        print(f"[错误] 核心功能测试失败: {str(e)}")
        all_passed = False
    
    # 检查scapy配置
    print("\n检查Scapy配置:")
    try:
        import scapy.all as scapy
        
        # 设置scapy为静默模式
        scapy.conf.verb = 0
        print("[通过] Scapy已配置为静默模式")
        
        # 检查是否需要root/管理员权限
        if sys.platform.startswith('win'):
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if not is_admin:
                print("[警告] 未以管理员权限运行，某些扫描功能可能受限")
            else:
                print("[通过] 以管理员权限运行")
        else:  # Linux/Mac
            if os.geteuid() != 0:
                print("[警告] 未以root权限运行，某些扫描功能可能受限")
            else:
                print("[通过] 以root权限运行")
                
    except ImportError:
        print("[错误] 无法导入Scapy")
        all_passed = False
    except Exception as e:
        print(f"[警告] Scapy测试出错: {str(e)}")
    
    print("\n===== 系统自检完成 =====")
    if all_passed:
        print("\n[成功] 所有必需组件检查通过")
    else:
        print("\n[警告] 部分组件检查失败，系统可能无法正常工作")
    
    return all_passed

if __name__ == "__main__":
    check_system()
