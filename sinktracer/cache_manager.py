# -*- coding: utf-8 -*-
"""
缓存管理模块

本模块负责 AST 数据的缓存管理，包括：
- 将构建的 AST 数据保存到缓存文件
- 从缓存文件加载 AST 数据
- 缓存数据完整性验证
- 项目路径匹配检查

模块职责：
    提供 AST 数据的持久化能力，避免重复解析，提升工具运行效率

依赖模块：
    - models: 数据类型定义
"""

import os
import json
from typing import Optional, TYPE_CHECKING

from colorama import Fore

from .models import (CacheData, CallGraph, ClassMethodsMap, InterfaceImplementations, 
                     ClassInterfaces, ParentChildMap, ChildParentMap, 
                     MethodReturnTypes, ImportMapping, ClassFileMapping)

if TYPE_CHECKING:
    from .ast_builder import ASTBuilder
    from .call_graph import CallGraphBuilder


class CacheManager:
    """
    缓存管理器
    
    负责 AST 数据的保存和加载
    
    Attributes:
        project_path: 项目路径
        cache_file: 缓存文件路径
    """
    
    def __init__(self, project_path: str, cache_file: Optional[str] = None):
        """
        初始化缓存管理器
        
        Args:
            project_path: 项目路径
            cache_file: 缓存文件路径，如果为 None 则自动生成
        """
        self.project_path = project_path
        
        # 自动生成缓存文件路径
        if cache_file is None:
            project_name = self.project_path.rstrip('/').split('/')[-1]
            cache_dir = os.path.join("Result", project_name)
            os.makedirs(cache_dir, exist_ok=True)
            self.cache_file = os.path.join(cache_dir, f"{project_name}_ast.json")
        else:
            self.cache_file = cache_file
    
    def exists(self) -> bool:
        """
        检查缓存文件是否存在
        
        Returns:
            缓存文件是否存在
        """
        return os.path.exists(self.cache_file)
    
    def load(self) -> bool:
        """
        从缓存文件加载 AST 数据
        
        Returns:
            加载是否成功
        """
        try:
            with open(self.cache_file, "r", encoding="utf-8") as f:
                cache_data: CacheData = json.load(f)
            
            # 验证缓存数据完整性
            if not self._validate_cache_data(cache_data):
                print(Fore.RED + f"[!]缓存文件格式不正确，缺少必要字段")
                return False
            
            # 验证缓存的项目路径是否匹配
            if cache_data["project_path"] != self.project_path:
                print(Fore.YELLOW + f"[!]警告：缓存的项目路径 ({cache_data['project_path']}) "
                                    f"与当前项目路径 ({self.project_path}) 不匹配")
                print(Fore.YELLOW + f"[!]仍然尝试加载缓存，但可能导致结果不准确")
            
            print(Fore.GREEN + f"[+]成功从缓存加载 AST 数据：{self.cache_file}")
            print(f"[+]调用图节点数：{len(cache_data['call_graph'])}")
            print(f"[+]类方法数：{len(cache_data['class_methods'])}")
            print(f"[+]接口实现数：{len(cache_data['interface_implementations'])}")
            print(f"[+]继承关系数：{len(cache_data['parent_child_map'])}")
            
            # 显示新数据统计（兼容旧缓存）
            if "method_return_types" in cache_data:
                print(f"[+]方法返回类型数：{len(cache_data['method_return_types'])}")
            if "import_mapping" in cache_data:
                print(f"[+]导入映射数：{len(cache_data['import_mapping'])}")
            
            return True
        
        except FileNotFoundError:
            print(Fore.RED + f"[!]缓存文件不存在：{self.cache_file}")
            return False
        except json.JSONDecodeError as e:
            print(Fore.RED + f"[!]缓存文件格式错误：{e}")
            return False
        except Exception as e:
            print(Fore.RED + f"[!]加载缓存失败：{e}")
            return False
    
    def save(self, ast_builder: "ASTBuilder", call_graph_builder: "CallGraphBuilder"):
        """
        将构建的 AST 数据保存到缓存文件
        
        Args:
            ast_builder: AST 构建器
            call_graph_builder: 调用图构建器
        """
        cache_data: CacheData = {
            "call_graph": call_graph_builder.get_call_graph(),
            "class_methods": ast_builder.get_class_methods(),
            "class_file_mapping": ast_builder.get_class_file_mapping(),
            "interface_implementations": ast_builder.get_interface_implementations(),
            "class_interfaces": ast_builder.get_class_interfaces(),
            "parent_child_map": ast_builder.get_parent_child_map(),
            "child_parent_map": ast_builder.get_child_parent_map(),
            "method_return_types": ast_builder.get_method_return_types(),
            "import_mapping": ast_builder.get_import_mapping(),
            "project_path": self.project_path
        }
        
        try:
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(cache_data, f, indent=4, ensure_ascii=False)
            print(Fore.GREEN + f"[+]缓存已保存到：{self.cache_file}")
        except Exception as e:
            print(Fore.RED + f"[!]保存缓存失败：{e}")
    
    def _validate_cache_data(self, cache_data: dict) -> bool:
        """
        验证缓存数据完整性
        
        Args:
            cache_data: 缓存数据字典
            
        Returns:
            数据是否完整
        """
        # 必需字段
        required_keys = [
            "call_graph", "class_methods", "interface_implementations",
            "class_interfaces", "parent_child_map", "child_parent_map", "project_path"
        ]
        
        # 新增字段（可选，用于向后兼容）
        optional_keys = ["method_return_types", "import_mapping", "class_file_mapping"]
        
        # 检查必需字段
        has_required = all(key in cache_data for key in required_keys)
        
        # 如果缺少新字段，给出提示但不禁用缓存
        if has_required:
            for key in optional_keys:
                if key not in cache_data:
                    print(Fore.YELLOW + f"[!]缓存缺少字段 '{key}'，将使用默认值")
        
        return has_required
    
    def get_cache_file(self) -> str:
        """
        获取缓存文件路径
        
        Returns:
            缓存文件路径
        """
        return self.cache_file
