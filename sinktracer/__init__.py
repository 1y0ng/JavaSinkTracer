# -*- coding: utf-8 -*-
"""
JavaSinkTracer 核心模块包

本包包含 JavaSinkTracer 工具的核心功能模块：

- config: 配置与常量模块
- models: 数据模型模块
- rule_manager: 规则管理模块
- ast_builder: AST 构建模块
- call_graph: 调用图构建模块
- taint_analyzer: 污点分析模块
- cache_manager: 缓存管理模块
- entry_detector: 入口点检测模块
"""

from .config import (
    MAPPING_ANNOTATIONS,
    STRUTS2_CLASS_ANNOTATIONS,
    STRUTS2_METHOD_ANNOTATIONS,
    DEFAULT_RULES_PATH,
    DEFAULT_RESULT_DIR,
    DEFAULT_PROJECT_PATH,
    CACHE_SUFFIX,
    RULE_SUFFIX,
    FUNC_SUFFIX,
)

from .models import (
    MethodInfo,
    ClassInfo,
    CallGraph,
    ClassMethodsMap,
    InterfaceImplementations,
    ClassInterfaces,
    ParentChildMap,
    ChildParentMap,
    MethodReturnTypes,
    ImportMapping,
    ClassFileMapping,
    SinkMappingInfo,
    SinkMapping,
    VulnerabilityResult,
    CallChainResult,
    CacheData,
    SinkRule,
    Rules,
    ExistingRules,
)

from .rule_manager import RuleManager
from .ast_builder import ASTBuilder
from .call_graph import CallGraphBuilder
from .taint_analyzer import TaintAnalyzer
from .cache_manager import CacheManager
from .entry_detector import EntryDetector

__all__ = [
    # 配置常量
    "MAPPING_ANNOTATIONS",
    "STRUTS2_CLASS_ANNOTATIONS",
    "STRUTS2_METHOD_ANNOTATIONS",
    "DEFAULT_RULES_PATH",
    "DEFAULT_RESULT_DIR",
    "DEFAULT_PROJECT_PATH",
    "CACHE_SUFFIX",
    "RULE_SUFFIX",
    "FUNC_SUFFIX",
    # 数据模型
    "MethodInfo",
    "ClassInfo",
    "CallGraph",
    "ClassMethodsMap",
    "InterfaceImplementations",
    "ClassInterfaces",
    "ParentChildMap",
    "ChildParentMap",
    "MethodReturnTypes",
    "ImportMapping",
    "ClassFileMapping",
    "SinkMappingInfo",
    "SinkMapping",
    "VulnerabilityResult",
    "CallChainResult",
    "CacheData",
    "SinkRule",
    "Rules",
    "ExistingRules",
    # 核心模块
    "RuleManager",
    "ASTBuilder",
    "CallGraphBuilder",
    "TaintAnalyzer",
    "CacheManager",
    "EntryDetector",
]
