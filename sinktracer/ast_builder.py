# -*- coding: utf-8 -*-
"""
AST 构建模块

本模块负责 Java 源代码的 AST（抽象语法树）构建和类信息提取，包括：
- 遍历项目中的所有 Java 文件
- 使用 javalang 解析 Java 代码为 AST
- 提取类、方法、继承关系、接口实现关系
- 构建调用关系图的基础数据

模块职责：
    构建 Java 项目的 AST，为后续调用图构建和污点分析提供基础数据

依赖模块：
    - config: 配置常量（注解定义）
    - models: 数据类型定义
"""

import os
from typing import Dict, List, Set

import javalang
from javalang import tree
from javalang.tree import ClassDeclaration
from colorama import Fore

from .config import MAPPING_ANNOTATIONS, STRUTS2_CLASS_ANNOTATIONS, STRUTS2_METHOD_ANNOTATIONS
from .models import (ClassMethodsMap, InterfaceImplementations, ClassInterfaces, 
                     ParentChildMap, ChildParentMap, MethodReturnTypes, ImportMapping)


class ASTBuilder:
    """
    AST 构建器
    
    负责 Java 源代码的 AST 构建和类信息提取
    
    Attributes:
        project_path: 项目路径
        path_exclusions: 排除的目录路径列表
        class_methods: 类方法映射
        interface_implementations: 接口到实现类的映射
        class_interfaces: 类到实现的接口的映射
        parent_child_map: 父类到子类的映射
        child_parent_map: 子类到父类的映射
    """
    
    def __init__(self, project_path: str, path_exclusions: List[str]):
        """
        初始化 AST 构建器
        
        Args:
            project_path: 项目路径
            path_exclusions: 排除的目录路径列表
        """
        self.project_path = project_path
        self.path_exclusions = path_exclusions
        
        # 初始化数据结构
        self.class_methods: ClassMethodsMap = {}
        self.interface_implementations: InterfaceImplementations = {}
        self.class_interfaces: ClassInterfaces = {}
        self.parent_child_map: ParentChildMap = {}
        self.child_parent_map: ChildParentMap = {}
        # 新增：方法返回类型映射和导入映射
        self.method_return_types: MethodReturnTypes = {}
        self.import_mapping: ImportMapping = {}
    
    def build(self) -> Dict[str, tree.CompilationUnit]:
        """
        构建 AST 并收集类、方法、接口、继承关系
        
        Returns:
            文件路径到 AST 树的映射字典，用于后续调用图构建
        """
        code_trees: Dict[str, tree.CompilationUnit] = {}
        
        print(f"[+]第一阶段：收集类、方法、接口、继承关系")
        
        for root, _, files in os.walk(self.project_path):
            for file in files:
                if file.endswith(".java") and not self._is_excluded(root):
                    try:
                        print(f"[+]正在分析的文件：{file}")
                        file_path = os.path.join(root, file)
                        with open(file_path, "r", encoding="utf-8") as f:
                            code_tree = javalang.parse.parse(f.read())
                            print(Fore.GREEN + f"[+]已成功解析文件：{file_path}")
                            self._extract_class_info(code_tree, file_path)
                            code_trees[file_path] = code_tree
                    except javalang.parser.JavaSyntaxError as e:
                        print(f"Syntax error in {file_path}: {e}")
                    except Exception:
                        continue
        
        # 输出收集结果
        self._print_collection_results()
        
        return code_trees
    
    def _is_excluded(self, file_path: str) -> bool:
        """
        判断当前的代码路径是否在排除的白名单路径中
        
        Args:
            file_path: 文件路径
            
        Returns:
            是否被排除
        """
        rel_path = os.path.relpath(file_path, self.project_path)
        return any(p in rel_path.split(os.sep) for p in self.path_exclusions)
    
    def _extract_class_info(self, code_tree: tree.CompilationUnit, file_path: str):
        """
        从 Java 代码的 AST 树中提取类和方法信息，并记录继承关系与接口实现关系
        
        该方法遍历给定的代码树（code_tree），识别所有类声明，收集每个类的方法信息
        （包括是否需要参数、是否包含 Web 映射注解），并建立映射关系
        
        Args:
            code_tree: Java 代码解析后的抽象语法树（AST）
            file_path: 当前处理的 Java 源文件的完整路径
        """
        # 提取当前文件的 import 语句
        self._extract_imports(code_tree)
        
        # 遍历所有类声明节点
        for path, node in code_tree.filter(ClassDeclaration):
            class_name = node.name
            methods_info: Dict = {}
            
            # 判断是否是 Struts2 Action 类
            is_struts2_action = self._is_struts2_action_class(node, class_name)
            
            # 提取当前类中每个方法的关键属性
            for method_node in node.methods:
                method_name = method_node.name
                requires_params = len(method_node.parameters) > 0
                has_mapping_annotation = False
                is_struts2_entry = False
                
                # 检查方法级别注解
                if method_node.annotations:
                    for annotation in method_node.annotations:
                        annotation_name = annotation.name.lstrip("@")
                        if annotation_name in MAPPING_ANNOTATIONS:
                            has_mapping_annotation = True
                        if annotation_name in STRUTS2_METHOD_ANNOTATIONS:
                            is_struts2_entry = True
                
                # 如果类是 Struts2 Action 类，方法默认为入口方法
                if is_struts2_action:
                    is_struts2_entry = True
                
                methods_info[method_name] = {
                    "requires_params": requires_params,
                    "has_mapping_annotation": has_mapping_annotation,
                    "is_struts2_entry": is_struts2_entry
                }
                
                # 收集方法返回类型
                if method_node.return_type:
                    return_type = method_node.return_type.name
                    # 存储方法返回类型：类名:方法名 -> 返回类型
                    self.method_return_types[f"{class_name}:{method_name}"] = return_type
            
            # 存储类信息
            self.class_methods[class_name] = {
                "file_path": file_path,
                "methods": methods_info,
                "is_struts2_action": is_struts2_action
            }
            
            # 提取继承关系
            self._extract_inheritance(node, class_name)
            
            # 提取接口实现关系
            self._extract_interface_implementations(node, class_name)
    
    def _is_struts2_action_class(self, node: ClassDeclaration, class_name: str) -> bool:
        """
        判断类是否是 Struts2 Action 类
        
        Args:
            node: 类声明节点
            class_name: 类名
            
        Returns:
            是否是 Struts2 Action 类
        """
        # 1. 检查类上的 Struts2 注解
        if node.annotations:
            for annotation in node.annotations:
                annotation_name = annotation.name.lstrip("@")
                if annotation_name in STRUTS2_CLASS_ANNOTATIONS:
                    return True
        
        # 2. 检查类名是否以 Action 结尾
        if class_name.endswith("Action"):
            return True
        
        return False
    
    def _extract_imports(self, code_tree: tree.CompilationUnit):
        """
        从 AST 中提取 import 语句，建立简单类名到全限定类名的映射
        
        Args:
            code_tree: Java 文件的 AST 树
        """
        if code_tree.imports:
            for import_decl in code_tree.imports:
                # import 路径，如 "org.hibernate.Session"
                import_path = import_decl.path
                # 提取简单类名
                simple_name = import_path.split('.')[-1]
                # 存储映射
                self.import_mapping[simple_name] = import_path
    
    def _extract_inheritance(self, node: ClassDeclaration, class_name: str):
        """
        提取继承关系
        
        Args:
            node: 类声明节点
            class_name: 类名
        """
        if node.extends:
            parent_class = node.extends.name
            
            # 建立父类到子类的映射
            if parent_class not in self.parent_child_map:
                self.parent_child_map[parent_class] = []
            if class_name not in self.parent_child_map[parent_class]:
                self.parent_child_map[parent_class].append(class_name)
            
            # 建立子类到父类的映射
            self.child_parent_map[class_name] = parent_class
    
    def _extract_interface_implementations(self, node: ClassDeclaration, class_name: str):
        """
        提取接口实现关系
        
        Args:
            node: 类声明节点
            class_name: 类名
        """
        if node.implements:
            # 记录类实现的接口
            self.class_interfaces[class_name] = []
            for impl in node.implements:
                interface_name = impl.name
                self.class_interfaces[class_name].append(interface_name)
                
                # 建立接口到实现类的映射
                if interface_name not in self.interface_implementations:
                    self.interface_implementations[interface_name] = []
                if class_name not in self.interface_implementations[interface_name]:
                    self.interface_implementations[interface_name].append(class_name)
    
    def _print_collection_results(self):
        """
        输出收集结果（调试用）
        """
        print(Fore.LIGHTBLUE_EX + f"[+]第一阶段完成！")
        
        # 输出接口实现关系
        if self.interface_implementations:
            print(Fore.CYAN + f"[+]已识别的接口实现关系：")
            for interface, impls in self.interface_implementations.items():
                print(f"    接口 {interface} 的实现类: {', '.join(impls)}")
        
        # 输出继承关系
        if self.parent_child_map:
            print(Fore.CYAN + f"[+]已识别的继承关系：")
            for parent, children in self.parent_child_map.items():
                print(f"    父类 {parent} 的子类: {', '.join(children)}")
    
    def get_class_methods(self) -> ClassMethodsMap:
        """
        获取类方法映射
        
        Returns:
            类方法映射
        """
        return self.class_methods
    
    def get_interface_implementations(self) -> InterfaceImplementations:
        """
        获取接口实现映射
        
        Returns:
            接口实现映射
        """
        return self.interface_implementations
    
    def get_class_interfaces(self) -> ClassInterfaces:
        """
        获取类接口映射
        
        Returns:
            类接口映射
        """
        return self.class_interfaces
    
    def get_parent_child_map(self) -> ParentChildMap:
        """
        获取父类到子类的映射
        
        Returns:
            父类到子类的映射
        """
        return self.parent_child_map
    
    def get_child_parent_map(self) -> ChildParentMap:
        """
        获取子类到父类的映射
        
        Returns:
            子类到父类的映射
        """
        return self.child_parent_map
    
    def get_method_return_types(self) -> MethodReturnTypes:
        """
        获取方法返回类型映射
        
        Returns:
            方法返回类型映射
        """
        return self.method_return_types
    
    def get_import_mapping(self) -> ImportMapping:
        """
        获取导入映射
        
        Returns:
            简单类名到全限定类名的映射
        """
        return self.import_mapping
