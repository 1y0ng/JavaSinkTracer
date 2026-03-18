# -*- coding: utf-8 -*-
"""
入口点检测模块

本模块负责识别 Java 项目中的外部入口点，包括：
- Spring MVC 框架入口点（@RequestMapping 等注解）
- JAX-RS 框架入口点（@Path、@GET 等注解）
- Struts2 框架入口点（Action 类）
- 方法参数检查

模块职责：
    识别程序的外部入口点，用于判断污点追溯是否到达终点

依赖模块：
    - models: 数据类型定义
"""

from typing import TYPE_CHECKING

from .models import ClassMethodsMap

if TYPE_CHECKING:
    pass


class EntryDetector:
    """
    入口点检测器
    
    负责识别程序的外部入口点
    
    支持：
        - Spring MVC 框架（@GetMapping、@PostMapping、@RequestMapping 等）
        - JAX-RS 框架（@Path、@GET、@POST 等）
        - Struts2 框架（Action 类和 @Action 注解）
    
    Attributes:
        class_methods: 类方法映射
    """
    
    def __init__(self, class_methods: ClassMethodsMap):
        """
        初始化入口点检测器
        
        Args:
            class_methods: 类方法映射
        """
        self.class_methods = class_methods
    
    def is_entry_point(self, method: str) -> bool:
        """
        判断当前追溯到的函数是否已经是程序的外部入口点
        
        检测规则：
            1. 方法是否被标记了 Spring MVC / JAX-RS Web 路由注解
            2. 方法是否是 Struts2 入口方法
            3. 类是否是 Struts2 Action 类
        
        Args:
            method: 方法标识（格式：类名:方法名）
            
        Returns:
            是否是入口点
        """
        try:
            class_name, method_name = method.split(":")
        except ValueError:
            return False
        
        class_info = self.class_methods.get(class_name, {})
        method_info = class_info.get("methods", {}).get(method_name, {})
        
        is_method_entry_point = False
        is_class_entry_point = False
        
        if method_info:
            # 1. 检查方法是否被标记了 Spring MVC / JAX-RS Web 路由注解
            is_method_entry_point = method_info.get("has_mapping_annotation", False)
            
            # 2. 检查方法是否是 Struts2 入口方法
            if not is_method_entry_point:
                is_method_entry_point = method_info.get("is_struts2_entry", False)
        
        if class_info:
            # 3. 检查类是否是 Struts2 Action 类
            is_class_entry_point = class_info.get("is_struts2_action", False)
        
        return is_method_entry_point or is_class_entry_point
    
    def is_has_parameters(self, class_name: str, method_name: str) -> bool:
        """
        判断给定类中的给定方法是否包含参数
        
        Args:
            class_name: 类名
            method_name: 方法名
            
        Returns:
            方法是否包含参数
        """
        try:
            class_info = self.class_methods.get(class_name, {})
            method_info = class_info.get("methods", {}).get(method_name, {})
            return method_info.get("requires_params", True)
        except KeyError:
            return True
    
    def get_class_methods(self) -> ClassMethodsMap:
        """
        获取类方法映射
        
        Returns:
            类方法映射
        """
        return self.class_methods
