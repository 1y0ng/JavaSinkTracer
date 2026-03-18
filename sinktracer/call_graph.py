# -*- coding: utf-8 -*-
"""
调用图构建模块

本模块负责 Java 源代码调用关系图的构建，包括：
- 从 AST 中提取方法调用关系
- 处理普通方法调用（variable.method()）
- 处理 this 关键字调用（this.variable.method()）
- 处理接口多态调用和继承多态调用
- 提取变量符号表

模块职责：
    构建方法之间的调用关系图，支持多态调用展开，为污点分析提供调用链数据

依赖模块：
    - models: 数据类型定义
"""

from typing import Dict, List, Tuple, Optional

import javalang
from javalang import tree
from colorama import Fore

from .models import (CallGraph, InterfaceImplementations, ParentChildMap, 
                     MethodReturnTypes, ImportMapping)


class CallGraphBuilder:
    """
    调用图构建器
    
    负责从 AST 中提取方法调用关系，构建调用图
    
    Attributes:
        call_graph: 调用关系图
        interface_implementations: 接口到实现类的映射
        parent_child_map: 父类到子类的映射
        method_return_types: 方法返回类型映射
        import_mapping: 导入映射
    """
    
    def __init__(self, interface_implementations: InterfaceImplementations,
                 parent_child_map: ParentChildMap,
                 method_return_types: Optional[MethodReturnTypes] = None,
                 import_mapping: Optional[ImportMapping] = None):
        """
        初始化调用图构建器
        
        Args:
            interface_implementations: 接口到实现类的映射
            parent_child_map: 父类到子类的映射
            method_return_types: 方法返回类型映射
            import_mapping: 导入映射
        """
        self.call_graph: CallGraph = {}
        self.interface_implementations = interface_implementations
        self.parent_child_map = parent_child_map
        self.method_return_types = method_return_types or {}
        self.import_mapping = import_mapping or {}
    
    def build(self, code_trees: Dict[str, tree.CompilationUnit]):
        """
        构建调用关系图
        
        Args:
            code_trees: 文件路径到 AST 树的映射
        """
        print(f"[+]第二阶段：构建调用关系图")
        
        for file_path, code_tree in code_trees.items():
            self._build_from_tree(code_tree)
        
        print(Fore.LIGHTBLUE_EX + f"[+]AST构建全部完成！")
    
    def _build_from_tree(self, file_code_tree: tree.CompilationUnit):
        """
        从单个 AST 树构建调用关系
        
        Args:
            file_code_tree: Java 文件的 AST 树
        """
        # 提取变量符号表
        variable_symbols = self._get_variable_symbols(file_code_tree)
        
        for path, node in file_code_tree:
            # 处理普通方法调用
            if isinstance(node, javalang.tree.MethodInvocation):
                self._process_method_invocation(path, node, variable_symbols)
            
            # 处理 this 关键字调用
            elif isinstance(node, javalang.tree.This):
                self._process_this_invocation(path, node, variable_symbols)
    
    def _process_method_invocation(self, path: Tuple, node: javalang.tree.MethodInvocation,
                                   variable_symbols: Dict[str, str]):
        """
        处理普通方法调用（variable.method() 或 methodCall().method()）
        
        Args:
            path: AST 路径
            node: 方法调用节点
            variable_symbols: 变量符号表
        """
        caller = self._get_current_method_from_path(path)
        callee = "[!]callee解析失败"
        is_polymorphic_call = False
        
        if node.qualifier:
            # 处理带限定符的方法调用（node.qualifier 是调用前的对象或类名，例如 list.add(...) 中的 list）
            qualifier = node.qualifier
            base_type = self._resolve_qualifier_type(qualifier, caller, variable_symbols)
            base_type = base_type.split('<')[0]
            callee = f"{base_type}:{node.member}"
            
            # 处理接口多态调用
            if base_type in self.interface_implementations:
                is_polymorphic_call = True
                self._add_polymorphic_calls(caller, node.member, 
                                           self.interface_implementations[base_type],
                                           "Interface", base_type)
            
            # 处理继承多态调用
            if base_type in self.parent_child_map:
                is_polymorphic_call = True
                self._add_polymorphic_calls(caller, node.member,
                                           self.parent_child_map[base_type],
                                           "Inheritance", base_type)
        
        elif node.qualifier is None:
            # 无限定符的方法调用 - 可能是链式调用的后半部分
            # 例如 getSession().createQuery() 中，createQuery 的 qualifier 是 None
            # 但它实际上是在 getSession() 的 selectors 中
            base_type = self._find_chained_call_base_type(path, node, caller, variable_symbols)
            
            if base_type:
                # 找到了链式调用的基础类型
                callee = f"{base_type}:{node.member}"
                print(Fore.CYAN + f"[ChainedCall] {caller} -> {callee}")
            else:
                # 检查是否是字符串常量调用
                if self._is_string_literal_caller(path):
                    base_type = "String"
                else:
                    # 默认：当前类的实例方法调用
                    base_type = caller.split(':')[0]
                callee = f"{base_type}:{node.member}"
        
        elif '.' not in node.member:
            callee = f"{caller.split(':')[0]}:{node.member}"
        
        # 添加到调用图
        if str(callee).startswith('[!]'):
            print(Fore.RED + f"[CallGraph] {caller} -> {callee}")
        else:
            if not is_polymorphic_call:
                print(f"[CallGraph] {caller} -> {callee}")
                self.call_graph.setdefault(caller, []).append(callee)
    
    def _find_chained_call_base_type(self, path: Tuple, node: javalang.tree.MethodInvocation,
                                     caller: str, variable_symbols: Dict[str, str]) -> Optional[str]:
        """
        查找链式调用的基础类型
        
        对于 getSession().createQuery()，javalang 解析为：
        - getSession() 是一个 MethodInvocation，qualifier=""，selectors=[createQuery()]
        - createQuery() 是另一个独立的 MethodInvocation，qualifier=None
        
        此方法通过向上遍历 AST 路径，查找是否有父级 MethodInvocation 
        包含当前节点在其 selectors 中，从而确定链式调用关系。
        
        Args:
            path: AST 路径
            node: 当前 MethodInvocation 节点（qualifier=None 的那个）
            caller: 当前调用方方法
            variable_symbols: 变量符号表
            
        Returns:
            基础类型名，如果不是链式调用则返回 None
        """
        # 向上遍历 path，查找是否有 MethodInvocation 包含当前节点在其 selectors 中
        for parent_node in reversed(path):
            if isinstance(parent_node, javalang.tree.MethodInvocation):
                # 检查当前节点是否在该父节点的 selectors 中
                if parent_node.selectors:
                    for selector in parent_node.selectors:
                        if isinstance(selector, javalang.tree.MethodInvocation):
                            # selector 就是链式调用中的后半部分
                            if selector.member == node.member:
                                # 找到了！parent_node 是链式调用的前半部分
                                # 例如 parent_node = getSession(), node = createQuery
                                parent_method_name = parent_node.member
                                caller_class = caller.split(':')[0]
                                
                                # 获取父方法的返回类型
                                parent_method_key = f"{caller_class}:{parent_method_name}"
                                if parent_method_key in self.method_return_types:
                                    return_type = self.method_return_types[parent_method_key]
                                    print(Fore.CYAN + f"[ChainedCall] {parent_method_name}() -> {return_type}")
                                    return return_type
                                
                                # 如果找不到返回类型，尝试通过 qualifier 解析
                                if parent_node.qualifier:
                                    return self._resolve_qualifier_type(
                                        parent_node.qualifier, caller, variable_symbols
                                    )
        return None
    
    def _process_this_invocation(self, path: Tuple, node: javalang.tree.This,
                                 variable_symbols: Dict[str, str]):
        """
        处理 this 关键字调用（this.variable.method()）
        
        Args:
            path: AST 路径
            node: This 节点
            variable_symbols: 变量符号表
        """
        callee = "[!]callee解析失败"
        caller = self._get_current_method_from_path(path)
        
        if node.selectors:
            try:
                first_selector = node.selectors[0]   # 变量名
                second_selector = node.selectors[1]  # 方法名
                
                if isinstance(second_selector, javalang.tree.MethodInvocation):
                    var_name = first_selector.member
                    method_name = second_selector.member
                    var_type = variable_symbols.get(var_name)
                    
                    callee = f"{var_type}:{method_name}"
                    print(f"[CallGraph] {caller} -> {callee}")
                    self.call_graph.setdefault(caller, []).append(callee)
                    
                    # 处理接口多态调用
                    if var_type in self.interface_implementations:
                        self._add_polymorphic_calls(caller, method_name,
                                                   self.interface_implementations[var_type],
                                                   "Interface", var_type)
                    
                    # 处理继承多态调用
                    if var_type in self.parent_child_map:
                        self._add_polymorphic_calls(caller, method_name,
                                                   self.parent_child_map[var_type],
                                                   "Inheritance", var_type)
            except Exception as e:
                print(Fore.RED + f"[!]待排查异常解析：{caller}, 异常信息：{e}")
            else:
                print(f"[CallGraph] {caller} -> {callee}")
    
    def _add_polymorphic_calls(self, caller: str, method_name: str,
                               implementations: List[str], call_type: str, base_type: str):
        """
        添加多态调用到调用图
        
        Args:
            caller: 调用方方法
            method_name: 被调用的方法名
            implementations: 实现类或子类列表
            call_type: 调用类型（Interface 或 Inheritance）
            base_type: 基类型（接口名或父类名）
        """
        for impl_class in implementations:
            impl_callee = f"{impl_class}:{method_name}"
            self.call_graph.setdefault(caller, []).append(impl_callee)
            print(f"[{call_type}] {caller} -> {impl_callee} (实现自{base_type})")
    
    def _resolve_qualifier_type(self, qualifier: str, caller: str, 
                                variable_symbols: Dict[str, str]) -> str:
        """
        解析限定符的类型，支持变量和方法调用（包括链式调用）
        
        对于 getSession().createQuery() 这样的链式调用：
        1. 首先解析 getSession() 的返回类型
        2. 然后确定 createQuery 所属的类
        
        Args:
            qualifier: 限定符（变量名或方法调用表达式）
            caller: 当前调用方方法（格式：类名:方法名）
            variable_symbols: 变量符号表
            
        Returns:
            解析出的类型名
        """
        # 1. 首先检查是否是简单变量名
        if qualifier in variable_symbols:
            return variable_symbols[qualifier]
        
        # 2. 检查是否是链式调用（包含点号）
        if '.' in qualifier:
            return self._resolve_chained_call_type(qualifier, caller, variable_symbols)
        
        # 3. 检查是否是方法调用（以括号结尾）
        if qualifier.endswith(')'):
            return self._resolve_method_call_return_type(qualifier, caller)
        
        # 4. 检查是否是类名（首字母大写）
        if qualifier[0].isupper():
            return qualifier
        
        # 5. 兜底：返回原始限定符
        return qualifier
    
    def _resolve_chained_call_type(self, qualifier: str, caller: str,
                                    variable_symbols: Dict[str, str]) -> str:
        """
        解析链式调用的类型，如 getSession().getTransaction().createQuery()
        
        Args:
            qualifier: 链式调用表达式
            caller: 当前调用方方法
            variable_symbols: 变量符号表
            
        Returns:
            最终返回类型
        """
        # 按点号分割，逐层解析
        parts = qualifier.split('.')
        current_type = None
        
        for part in parts:
            if current_type is None:
                # 第一部分：可能是变量或方法调用
                if part in variable_symbols:
                    current_type = variable_symbols[part]
                elif part.endswith(')'):
                    current_type = self._resolve_method_call_return_type(part, caller)
                elif part[0].isupper():
                    current_type = part
                else:
                    # 无法解析，使用原始值
                    current_type = part
            else:
                # 后续部分：基于当前类型解析方法调用
                if part.endswith(')'):
                    method_name = part.split('(')[0]
                    # 查找方法返回类型
                    method_key = f"{current_type}:{method_name}"
                    if method_key in self.method_return_types:
                        current_type = self.method_return_types[method_key]
                    # 如果找不到，保持当前类型不变
                # 如果不是方法调用，保持当前类型
        
        return current_type or qualifier
    
    def _resolve_method_call_return_type(self, method_call: str, caller: str) -> str:
        """
        解析方法调用的返回类型
        
        Args:
            method_call: 方法调用表达式（如 "getSession()"）
            caller: 当前调用方方法
            
        Returns:
            方法返回类型
        """
        # 提取方法名（去掉括号和参数）
        method_name = method_call.split('(')[0]
        
        # 获取调用方所属的类名
        caller_class = caller.split(':')[0]
        
        # 尝试从方法返回类型表中查找
        method_key = f"{caller_class}:{method_name}"
        if method_key in self.method_return_types:
            return_type = self.method_return_types[method_key]
            print(Fore.CYAN + f"[TypeInference] {method_call} -> {return_type}")
            return return_type
        
        # 如果找不到，返回调用方类名作为默认值
        return caller_class
    
    def _get_current_method_from_path(self, path: Tuple) -> str:
        """
        通过 AST 路径直接获取当前函数节点所对应的类的信息
        
        Args:
            path: AST 路径
            
        Returns:
            当前方法标识（格式：类名:方法名）
        """
        for node in reversed(path):
            if isinstance(node, javalang.tree.MethodDeclaration):
                class_node = self._find_parent_class(path)
                class_name = getattr(class_node, 'name', 'unknown')
                return f"{class_name}:{node.name}"
        return "unknown:unknown"
    
    @staticmethod
    def _find_parent_class(path: Tuple) -> tree.ClassDeclaration:
        """
        从 AST 路径中查找最近的类声明或接口声明
        
        Args:
            path: AST 路径
            
        Returns:
            类声明节点
        """
        for node in reversed(path):
            if isinstance(node, (javalang.tree.ClassDeclaration, javalang.tree.InterfaceDeclaration)):
                return node
        
        # 如果找不到类声明，返回一个默认的类节点对象
        default_class = type('obj', (object,), {'name': 'unknown'})()
        return default_class
    
    @staticmethod
    def _get_variable_symbols(file_code_tree: tree.CompilationUnit) -> Dict[str, str]:
        """
        提取类中所有变量声明及其类型
        
        Args:
            file_code_tree: Java 文件的 AST 树
            
        Returns:
            变量名到类型的映射
        """
        variable_symbols: Dict[str, str] = {}
        
        for path, node in file_code_tree:
            # 局部变量声明
            if isinstance(node, javalang.tree.LocalVariableDeclaration):
                var_type = node.type.name
                for declarator in node.declarators:
                    variable_symbols[declarator.name] = var_type
            # 字段声明
            elif isinstance(node, javalang.tree.FieldDeclaration):
                var_type = node.type.name
                for declarator in node.declarators:
                    variable_symbols[declarator.name] = var_type
            # 方法参数
            elif isinstance(node, javalang.tree.MethodDeclaration):
                for param in node.parameters:
                    var_type = param.type.name
                    variable_symbols[param.name] = var_type
        
        return variable_symbols
    
    @staticmethod
    def _is_string_literal_caller(path: Tuple) -> bool:
        """
        判断方法调用是否由字符串常量发起
        
        Args:
            path: AST 路径
            
        Returns:
            是否是字符串常量调用
        """
        for parent in reversed(path):
            if isinstance(parent, javalang.tree.Literal) and isinstance(parent.value, str):
                return True
        return False
    
    def get_call_graph(self) -> CallGraph:
        """
        获取调用关系图
        
        Returns:
            调用关系图
        """
        return self.call_graph
    
    def resolve_actual_type(self, var_type: str) -> List[str]:
        """
        解析变量的实际类型
        
        如果是接口类型返回所有实现类，如果是父类返回所有子类
        
        Args:
            var_type: 变量类型名
            
        Returns:
            实际类型列表
        """
        # 优先检查接口实现
        if var_type in self.interface_implementations:
            return self.interface_implementations[var_type]
        
        # 其次检查继承关系
        if var_type in self.parent_child_map:
            return self.parent_child_map[var_type]
        
        # 普通类型直接返回
        return [var_type]
