# -*- coding: utf-8 -*-
"""
规则管理模块

本模块负责漏洞检测规则的加载、管理和生成，包括：
- 从 JSON 文件加载规则配置
- 构建 Sink 点到漏洞类型的映射
- 动态生成和更新规则文件
- 生成包含函数内容的 JSON 文件

模块职责：
    集中管理规则相关操作，支持规则的持久化和增量更新

依赖模块：
    - config: 配置常量
    - models: 数据类型定义
    - JavaCodeExtract: 函数内容提取
"""

import os
import json
import sys
from typing import Dict, List, Optional

from colorama import Fore

from .config import RULE_SUFFIX, FUNC_SUFFIX
from .models import Rules, ExistingRules, SinkRule, SinkMapping, SinkMappingInfo

# 添加项目根目录到路径，以便导入 JavaCodeExtract
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from JavaCodeExtract import extract_method_definition


class RuleManager:
    """
    规则管理器
    
    负责规则的加载、映射构建、规则文件写入等功能
    
    Attributes:
        rules: 加载的规则配置
        rule_file_path: 规则文件保存路径
        rule_sink_mapping: Sink 点到漏洞类型的映射
        existing_rules: 运行时生成的规则配置（用于写入文件）
        project_path: 项目路径
        force_default_rules: 是否强制使用默认规则
        skip_extract: 是否跳过函数内容提取
    """
    
    def __init__(self, project_path: str, rules_path: str, 
                 force_default_rules: bool = False, skip_extract: bool = False):
        """
        初始化规则管理器
        
        Args:
            project_path: 项目路径
            rules_path: 规则文件路径
            force_default_rules: 是否强制使用默认规则（不使用项目规则）
            skip_extract: 是否跳过函数内容提取
        """
        self.project_path = project_path
        self.force_default_rules = force_default_rules
        self.skip_extract = skip_extract
        
        # 初始化规则相关属性
        self.rules: Optional[Rules] = None
        self.rule_file_path: Optional[str] = None
        self.rule_sink_mapping: SinkMapping = {}
        self.existing_rules: ExistingRules = {
            "depth": 0,
            "path_exclusions": [],
            "sink_rules": []
        }
        
        # 初始化规则文件路径和加载规则
        self._init_rule_file(rules_path)
    
    def _init_rule_file(self, rules_path: str):
        """
        初始化规则文件路径，检测并确定使用的规则文件
        
        Args:
            rules_path: 默认规则文件路径
        """
        # 创建结果目录
        project_name = self.project_path.rstrip('/').split('/')[-1]
        result_dir = os.path.join("Result", project_name)
        os.makedirs(result_dir, exist_ok=True)
        
        # 查找项目中已存在的规则文件
        existing_rule_files = []
        if not self.force_default_rules:
            for file in os.listdir(result_dir):
                if file.startswith(f"{project_name}_rule_") and file.endswith(".json"):
                    existing_rule_files.append(file)
        
        # 确定要使用的规则文件
        if existing_rule_files:
            existing_rule_files.sort(key=lambda x: int(x.split('_')[-1].replace('.json', '')))
            latest_rule_file = existing_rule_files[-1]
            rules_path = os.path.join(result_dir, latest_rule_file)
            print(f"[+]检测到项目规则文件，使用：{rules_path}")
        
        # 加载规则
        self.rules = self._load_rules(rules_path)
        
        # 设置输出规则文件的路径（递增数字）
        if self.force_default_rules:
            next_rule_num = 1
        elif existing_rule_files:
            latest_num = int(existing_rule_files[-1].split('_')[-1].replace('.json', ''))
            next_rule_num = latest_num + 1
        else:
            next_rule_num = 1
        
        self.rule_file_path = os.path.join(result_dir, f"{project_name}{RULE_SUFFIX}{next_rule_num}.json")
        print(f"[+]新的规则文件将保存到：{self.rule_file_path}")
        
        # 初始化 existing_rules 的基础配置
        self.existing_rules = {
            "depth": self.rules["depth"],
            "path_exclusions": self.rules["path_exclusions"],
            "sink_rules": []
        }
        
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
    
    def write_rule_file(self, sink: str, caller_methods: List[str]):
        """
        将需要追溯的调用点写入规则文件，并生成包含函数内容的 JSON 文件
        
        Args:
            sink: 当前正在追溯的 Sink 点
            caller_methods: 需要追溯的调用点列表
        """
        if not self.rule_file_path:
            return
        
        # 查找当前 sink 对应的漏洞类型信息
        vul_type_info = self._find_vul_type_info(sink)
        if not vul_type_info:
            return
        
        # 查找或创建对应的 sink_rule
        existing_rule = self._find_or_create_sink_rule(vul_type_info)
        
        # 将调用点添加到对应的 sink_rule 中
        new_sinks = []
        for caller in caller_methods:
            if caller not in existing_rule["sinks"]:
                existing_rule["sinks"].append(caller)
                new_sinks.append(caller)
        
        # 更新 depth 配置
        if self.force_default_rules:
            self.existing_rules["depth"] = 1
        else:
            self.existing_rules["depth"] = self.rules["depth"]
        
        # 写入到文件
        self._save_rule_file()
        
        # 生成函数内容文件
        if new_sinks and not self.skip_extract:
            self._write_func_file(new_sinks, vul_type_info)
    
    def _find_vul_type_info(self, sink: str) -> Optional[SinkMappingInfo]:
        """
        查找 Sink 点对应的漏洞类型信息
        
        Args:
            sink: Sink 点
            
        Returns:
            漏洞类型信息
        """
        for rule in self.rules["sink_rules"]:
            for Rsink in rule["sinks"]:
                if sink in Rsink:
                    return {
                        "sink_name": rule["sink_name"],
                        "sink_desc": rule["sink_desc"],
                        "severity_level": rule["severity_level"]
                    }
        return None
    
    def _find_or_create_sink_rule(self, vul_type_info: SinkMappingInfo) -> SinkRule:
        """
        查找或创建对应的 Sink 规则
        
        Args:
            vul_type_info: 漏洞类型信息
            
        Returns:
            Sink 规则
        """
        for rule in self.existing_rules["sink_rules"]:
            if rule["sink_name"] == vul_type_info["sink_name"]:
                return rule
        
        # 创建新的 sink_rule
        new_rule: SinkRule = {
            "sink_name": vul_type_info["sink_name"],
            "sink_desc": vul_type_info["sink_desc"],
            "severity_level": vul_type_info["severity_level"],
            "sinks": []
        }
        self.existing_rules["sink_rules"].append(new_rule)
        return new_rule
    
    def _save_rule_file(self):
        """
        保存规则文件到磁盘
        """
        try:
            with open(self.rule_file_path, "w", encoding="utf-8") as f:
                json.dump(self.existing_rules, f, indent=4, ensure_ascii=False)
        except Exception as e:
            print(Fore.RED + f"[!]写入规则文件失败：{e}")
    
    def _write_func_file(self, sinks: List[str], vul_type_info: SinkMappingInfo):
        """
        为指定的 Sink 列表生成包含函数内容的 JSON 文件
        
        Args:
            sinks: 需要提取函数内容的 Sink 列表（格式：类名:方法名）
            vul_type_info: 漏洞类型信息
        """
        # 生成函数内容文件路径
        rule_file_name = os.path.basename(self.rule_file_path)
        func_file_name = rule_file_name.replace(RULE_SUFFIX, FUNC_SUFFIX)
        func_file_path = os.path.join(os.path.dirname(self.rule_file_path), func_file_name)
        
        # 初始化函数内容数据结构
        func_data = {"functions": {}}
        
        # 如果文件已存在，先加载已有数据
        if os.path.exists(func_file_path):
            try:
                with open(func_file_path, "r", encoding="utf-8") as f:
                    func_data = json.load(f)
            except Exception as e:
                print(Fore.YELLOW + f"[!]加载已有函数文件失败，将创建新文件：{e}")
        
        # 遍历每个 sink，提取函数内容
        for sink in sinks:
            try:
                class_name, method_name = sink.split(":")
                file_path, method_code = extract_method_definition(
                    self.project_path, class_name, method_name
                )
                
                if file_path and method_code:
                    func_data["functions"][sink] = {
                        "file_path": file_path,
                        "method_code": method_code,
                        "sink_name": vul_type_info["sink_name"],
                        "sink_desc": vul_type_info["sink_desc"],
                        "severity_level": vul_type_info["severity_level"]
                    }
                    print(Fore.CYAN + f"[+]已提取函数内容：{sink}")
                else:
                    print(Fore.YELLOW + f"[!]未能找到函数定义：{sink}")
            except Exception as e:
                print(Fore.RED + f"[!]提取函数内容失败 [{sink}]：{e}")
        
        # 写入到文件
        try:
            with open(func_file_path, "w", encoding="utf-8") as f:
                json.dump(func_data, f, indent=4, ensure_ascii=False)
            print(Fore.GREEN + f"[+]函数内容文件已保存：{func_file_path}")
        except Exception as e:
            print(Fore.RED + f"[!]写入函数内容文件失败：{e}")
