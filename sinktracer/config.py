# -*- coding: utf-8 -*-
"""
配置与常量模块

本模块定义了 JavaSinkTracer 工具运行所需的配置常量，包括：
- 框架注解常量（Spring MVC、JAX-RS、Struts2）
- 默认路径配置
- 其他全局常量

模块职责：
    集中管理所有配置项，便于维护和扩展新的框架支持
"""

# ============================================================================
# Spring MVC / JAX-RS 方法级别注解
# 用于识别 Spring MVC 和 JAX-RS 框架的 Web 路由入口方法
# ============================================================================
MAPPING_ANNOTATIONS = {
    "GetMapping",       # Spring MVC GET 请求映射
    "PostMapping",      # Spring MVC POST 请求映射
    "RequestMapping",   # Spring MVC 通用请求映射
    "PutMapping",       # Spring MVC PUT 请求映射
    "DeleteMapping",    # Spring MVC DELETE 请求映射
    "Path",             # JAX-RS 路径注解
    "GET",              # JAX-RS GET 方法注解
    "POST",             # JAX-RS POST 方法注解
    "PUT",              # JAX-RS PUT 方法注解
    "DELETE"            # JAX-RS DELETE 方法注解
}

# ============================================================================
# Struts2 类级别注解
# 用于识别 Struts2 Action 类
# ============================================================================
STRUTS2_CLASS_ANNOTATIONS = {
    "Namespace",        # 命名空间注解
    "Action",           # Action 配置注解
    "ParentPackage",    # 父包注解
    "InterceptorRef",   # 拦截器引用注解
    "Results"           # 结果配置注解
}

# ============================================================================
# Struts2 方法级别注解
# 用于识别 Struts2 Action 方法入口
# ============================================================================
STRUTS2_METHOD_ANNOTATIONS = {
    "Action"            # Action 方法注解
}

# ============================================================================
# 默认配置
# ============================================================================
DEFAULT_RULES_PATH = "Rules/my_rules.json"  # 默认规则文件路径
DEFAULT_RESULT_DIR = "Result"               # 默认结果输出目录
DEFAULT_PROJECT_PATH = "D:/Code/Github/java-sec-code"  # 默认扫描项目路径

# ============================================================================
# 缓存文件后缀
# ============================================================================
CACHE_SUFFIX = "_ast.json"      # AST 缓存文件后缀
RULE_SUFFIX = "_rule_"          # 规则文件后缀前缀
FUNC_SUFFIX = "_func_"          # 函数内容文件后缀前缀
