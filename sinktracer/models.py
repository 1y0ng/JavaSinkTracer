# -*- coding: utf-8 -*-
"""
数据模型模块

本模块定义了 JavaSinkTracer 工具中使用的核心数据结构和类型定义，包括：
- 方法信息模型
- 调用图数据结构
- 继承与接口关系映射
- 漏洞检测结果模型

模块职责：
    提供统一的数据结构定义，增强代码可读性和类型安全性
"""

from typing import Dict, List, Union, Optional, TypedDict


# ============================================================================
# 方法信息类型定义
# ============================================================================
class MethodInfo(TypedDict):
    """
    方法的详细信息
    
    Attributes:
        requires_params: 方法是否需要参数
        has_mapping_annotation: 方法是否带有 Web 路由注解（Spring MVC / JAX-RS）
        is_struts2_entry: 方法是否是 Struts2 入口方法
    """
    requires_params: bool
    has_mapping_annotation: bool
    is_struts2_entry: bool


class ClassInfo(TypedDict):
    """
    类的详细信息
    
    Attributes:
        file_path: 类所在的文件路径
        methods: 类中所有方法的信息字典，键为方法名，值为 MethodInfo
        is_struts2_action: 类是否是 Struts2 Action 类
    """
    file_path: str
    methods: Dict[str, MethodInfo]
    is_struts2_action: bool


# ============================================================================
# 调用图类型定义
# ============================================================================
# 调用图：键为 "类名:方法名"，值为被调用的方法列表
CallGraph = Dict[str, List[str]]

# 类方法映射：键为类名，值为类的详细信息
ClassMethodsMap = Dict[str, ClassInfo]

# 接口实现映射：键为接口名，值为实现该接口的类列表
InterfaceImplementations = Dict[str, List[str]]

# 类接口映射：键为类名，值为该类实现的接口列表
ClassInterfaces = Dict[str, List[str]]

# 继承关系映射
ParentChildMap = Dict[str, List[str]]  # 父类 -> 子类列表
ChildParentMap = Dict[str, str]        # 子类 -> 父类

# 方法返回类型映射：键为 "类名:方法名"，值为返回类型
MethodReturnTypes = Dict[str, str]

# 导入映射：键为简单类名，值为全限定类名
ImportMapping = Dict[str, str]

# 类名到 Java 文件路径的映射
ClassFileMapping = Dict[str, str]


# ============================================================================
# Sink 点映射类型定义
# ============================================================================
class SinkMappingInfo(TypedDict):
    """
    Sink 点到漏洞类型的映射信息
    
    Attributes:
        sink_name: 漏洞类型名称（如 RCE、SSRF 等）
        sink_desc: 漏洞描述
        severity_level: 严重程度
    """
    sink_name: str
    sink_desc: str
    severity_level: str


# Sink 到漏洞类型的映射
SinkMapping = Dict[str, SinkMappingInfo]


# ============================================================================
# 漏洞检测结果类型定义
# ============================================================================
class VulnerabilityResult(TypedDict):
    """
    单个漏洞检测结果
    
    Attributes:
        vul_type: 漏洞类型
        sink_desc: 漏洞描述
        severity: 严重程度
        sink: Sink 点（格式：类名:方法名）
        call_chains: 调用链列表
    """
    vul_type: str
    sink_desc: str
    severity: str
    sink: str
    call_chains: List[List[str]]


class CallChainResult(TypedDict):
    """
    调用链结果
    
    Attributes:
        chain: 调用链路径列表
        code: 对应的源代码列表
    """
    chain: List[str]
    code: List[str]


# ============================================================================
# 缓存数据类型定义
# ============================================================================
class CacheData(TypedDict):
    """
    AST 缓存数据结构
    
    Attributes:
        call_graph: 调用图
        class_methods: 类方法映射
        class_file_mapping: 类名到 Java 文件路径的映射
        interface_implementations: 接口实现映射
        class_interfaces: 类接口映射
        parent_child_map: 父类到子类映射
        child_parent_map: 子类到父类映射
        method_return_types: 方法返回类型映射
        import_mapping: 导入映射
        project_path: 项目路径
    """
    call_graph: CallGraph
    class_methods: ClassMethodsMap
    class_file_mapping: ClassFileMapping
    interface_implementations: InterfaceImplementations
    class_interfaces: ClassInterfaces
    parent_child_map: ParentChildMap
    child_parent_map: ChildParentMap
    method_return_types: MethodReturnTypes
    import_mapping: ImportMapping
    project_path: str


# ============================================================================
# 规则类型定义
# ============================================================================
class SinkRule(TypedDict):
    """
    Sink 规则定义
    
    Attributes:
        sink_name: 漏洞类型名称
        sink_desc: 漏洞描述
        severity_level: 严重程度
        sinks: Sink 点列表（格式：类名:方法名|方法名2）
    """
    sink_name: str
    sink_desc: str
    severity_level: str
    sinks: List[str]


class Rules(TypedDict):
    """
    完整规则配置
    
    Attributes:
        depth: 回溯深度限制
        path_exclusions: 排除的目录路径列表
        sink_rules: Sink 规则列表
    """
    depth: int
    path_exclusions: List[str]
    sink_rules: List[SinkRule]


class ExistingRules(TypedDict):
    """
    运行时生成的规则配置（用于写入规则文件）
    
    Attributes:
        depth: 回溯深度限制
        path_exclusions: 排除的目录路径列表
        sink_rules: Sink 规则列表
    """
    depth: int
    path_exclusions: List[str]
    sink_rules: List[SinkRule]
