# -*- coding: utf-8 -*-
"""
规则管理模块

本模块负责漏洞检测规则的加载和管理，包括：
- 从 JSON 文件加载规则配置
- 构建 Sink 点到漏洞类型的映射

模块职责：
    集中管理规则相关操作

依赖模块：
    - models: 数据类型定义
"""

import json
from typing import List, Optional

from .models import Rules, SinkRule, SinkMapping, SinkMappingInfo


class RuleManager:
    """
    规则管理器
    
    负责规则的加载、映射构建等功能
    
    Attributes:
        rules: 加载的规则配置
        rule_sink_mapping: Sink 点到漏洞类型的映射
    """
    
    def __init__(self, project_path: str, rules_path: str):
        """
        初始化规则管理器
        
        Args:
            project_path: 项目路径
            rules_path: 规则文件路径
        """
        # 初始化规则相关属性
        self.rules: Optional[Rules] = None
        self.rule_sink_mapping: SinkMapping = {}
        
        # 加载规则
        self.rules = self._load_rules(rules_path)
        
        # 构建 sink 映射
        self._build_sink_mapping()
    
    @staticmethod
    def _load_rules(path: str) -> Rules:
        """
        从本地 JSON 文件加载规则配置
        
        Args:
            path: 规则文件路径
            
        Returns:
            规则配置字典
        """
        with open(path, "r", encoding="utf-8") as f:
            rules = json.load(f)
            print(f"[+]成功加载Rules：{rules}")
            return rules
    
    def _build_sink_mapping(self):
        """
        构建 Sink 点到漏洞类型的映射关系
        
        该映射用于快速查找 Sink 点对应的漏洞类型信息
        """
        for rule in self.rules["sink_rules"]:
            for sink in rule["sinks"]:
                self.rule_sink_mapping[sink] = {
                    "sink_name": rule["sink_name"],
                    "sink_desc": rule["sink_desc"],
                    "severity_level": rule["severity_level"]
                }
    
    def get_path_exclusions(self) -> List[str]:
        """
        获取路径排除列表
        
        Returns:
            排除的目录路径列表
        """
        return self.rules.get("path_exclusions", [])
    
    def get_depth(self) -> int:
        """
        获取回溯深度限制
        
        Returns:
            回溯深度
        """
        return self.rules.get("depth", 5)
    
    def get_sink_rules(self) -> List[SinkRule]:
        """
        获取 Sink 规则列表
        
        Returns:
            Sink 规则列表
        """
        return self.rules.get("sink_rules", [])
    
    def get_sink_info(self, sink: str) -> Optional[SinkMappingInfo]:
        """
        根据 Sink 点获取漏洞类型信息
        
        Args:
            sink: Sink 点（格式：类名:方法名）
            
        Returns:
            漏洞类型信息，如果不存在则返回 None
        """
        return self.rule_sink_mapping.get(sink)
