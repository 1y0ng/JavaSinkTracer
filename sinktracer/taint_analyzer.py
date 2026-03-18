# -*- coding: utf-8 -*-
"""
污点分析模块

本模块负责从 Sink 点反向追溯污点传播路径，包括：
- 从 Sink 点开始反向追溯调用链
- 支持多级调用链展开
- 支持最大追溯深度限制
- 识别程序入口点（Spring MVC、JAX-RS、Struts2）
- 处理调用栈并提取源代码

模块职责：
    实现核心的污点分析算法，发现从 Sink 到 Source 的完整调用链

依赖模块：
    - models: 数据类型定义
    - rule_manager: 规则管理
    - entry_detector: 入口点检测
    - JavaCodeExtract: 代码提取
"""

from collections import deque
import os
import sys
from typing import List, Dict, Set, TYPE_CHECKING

from colorama import Fore

from .models import CallGraph, ClassMethodsMap, VulnerabilityResult, CallChainResult

# 添加项目根目录到路径，以便导入 JavaCodeExtract
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from JavaCodeExtract import extract_method_definition

if TYPE_CHECKING:
    from .rule_manager import RuleManager
    from .entry_detector import EntryDetector


class TaintAnalyzer:
    """
    污点分析器
    
    负责从 Sink 点反向追溯污点传播路径
    
    Attributes:
        project_path: 项目路径
        call_graph: 调用关系图
        class_methods: 类方法映射
        rule_manager: 规则管理器
        entry_detector: 入口点检测器
    """
    
    def __init__(self, project_path: str, call_graph: CallGraph,
                 class_methods: ClassMethodsMap, rule_manager: "RuleManager",
                 entry_detector: "EntryDetector"):
        """
        初始化污点分析器
        
        Args:
            project_path: 项目路径
            call_graph: 调用关系图
            class_methods: 类方法映射
            rule_manager: 规则管理器
            entry_detector: 入口点检测器
        """
        self.project_path = project_path
        self.call_graph = call_graph
        self.class_methods = class_methods
        self.rule_manager = rule_manager
        self.entry_detector = entry_detector
    
    def find_taint_paths(self) -> List[VulnerabilityResult]:
        """
        查找所有污点路径
        
        遍历所有 Sink 点，对每个 Sink 点进行反向追溯
        
        Returns:
            漏洞检测结果列表
        """
        print("-" * 50)
        print(f"[+]正在审计源项目：{self.project_path}")
        
        results: List[VulnerabilityResult] = []
        
        for rule in self.rule_manager.get_sink_rules():
            for sink in rule["sinks"]:
                class_name, methods = sink.split(":")
                for method in methods.split("|"):
                    class_name = class_name.split('.')[-1]
                    sink_point = f"{class_name}:{method}"
                    print(f"[+]正在审计sink点：{sink_point}")
                    
                    paths = self._trace_back(sink_point, self.rule_manager.get_depth())
                    
                    if paths:
                        results.append({
                            "vul_type": rule["sink_name"],
                            "sink_desc": rule["sink_desc"],
                            "severity": rule["severity_level"],
                            "sink": sink_point,
                            "call_chains": paths
                        })
        
        print("-" * 50)
        return results
    
    def _trace_back(self, sink: str, max_depth: int) -> List[List[str]]:
        """
        根据最大追溯深度的限制，回溯污点传播的路径
        
        使用 BFS 算法进行反向追溯，支持多级调用链展开
        
        Args:
            sink: Sink 点（格式：类名:方法名）
            max_depth: 最大追溯深度
            
        Returns:
            找到的所有调用链列表
        """
        paths: List[List[str]] = []
        queue = deque([([sink], 0)])
        
        while queue:
            current_path, current_depth = queue.popleft()
            
            if current_depth >= max_depth:
                continue
            
            current_sink = current_path[0]
            
            # 查找所有调用当前 sink 的方法
            caller_methods = [
                caller
                for caller, callees in self.call_graph.items()
                if current_sink in callees
            ]
            
            if not caller_methods:
                continue
            else:
                print(Fore.MAGENTA + f"[*]需要追溯调用点: {caller_methods}")
                
                # 如果不使用 -f 参数，发现需要追溯调用点就写入规则文件
                if not self.rule_manager.force_default_rules:
                    self.rule_manager.write_rule_file(sink, caller_methods)
            
            for caller in caller_methods:
                new_path = [caller] + current_path
                print(Fore.YELLOW + f"[→]正在追溯的路径: [{' → '.join(new_path)}]")
                
                if self.entry_detector.is_entry_point(caller):
                    paths.append(new_path)
                    print(Fore.LIGHTGREEN_EX + f"[✓]发现完整调用链: {new_path}")
                    
                    # 如果使用 -f 参数，只在发现完整调用链时写入倒数第二个节点
                    if self.rule_manager.force_default_rules and len(new_path) >= 2:
                        caller_to_write = new_path[-2]
                        self.rule_manager.write_rule_file(sink, [caller_to_write])
                else:
                    queue.append((new_path, current_depth + 1))
        
        return paths
    
    @staticmethod
    def process_call_stacks(root_dir: str, call_stacks: List[List[str]]) -> List[CallChainResult]:
        """
        处理调用栈，提取每个调用链的源代码
        
        Args:
            root_dir: 项目根目录
            call_stacks: 调用栈列表
            
        Returns:
            处理后的调用链结果列表
        """
        results: List[CallChainResult] = []
        method_cache: Dict[str, tuple] = {}  # 缓存已提取的方法定义
        
        for stack in call_stacks:
            visited: Set[str] = set()
            chain: List[str] = []
            code_list: List[str] = []
            queue: List[tuple] = []
            
            for item in stack:
                cls, mtd = item.split(':', 1)
                queue.append((cls, mtd))
            
            while queue:
                cls, mtd = queue.pop(0)
                key = f"{cls}:{mtd}"
                
                if key in visited:
                    continue
                visited.add(key)
                
                # 检查缓存
                if key in method_cache:
                    path, code = method_cache[key]
                else:
                    path, code = extract_method_definition(root_dir, cls, mtd)
                    method_cache[key] = (path, code)
                
                if not path or not code:
                    continue
                
                chain.append(f"{path}:{mtd}")
                code_list.append(code)
            
            results.append({"chain": chain, "code": code_list})
        
        return results
