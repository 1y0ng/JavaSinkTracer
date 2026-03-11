import argparse
import os
import json
import time

import javalang
from javalang import tree
from collections import deque
from typing import Dict, List, Union
from colorama import Fore, init
from javalang.tree import ClassDeclaration

from JavaCodeExtract import extract_method_definition
from AutoVulReport import generate_markdown_report

init(autoreset=True)


class JavaSinkTracer:
    def __init__(self, project_path: str, rules_path: str, force_default_rules: bool = False):
        self.project_path = project_path
        self.force_default_rules = force_default_rules  # 是否强制使用默认规则文件
        self.call_graph: Dict[str, List[str]] = {}
        self.class_methods: Dict[str, Dict[str, Union[str, Dict[str, Dict[str, bool]]]]] = {}
        self.interface_implementations: Dict[str, List[str]] = {}  # 接口到实现类的映射
        self.class_interfaces: Dict[str, List[str]] = {}          # 类到实现的接口的映射
        self.parent_child_map: Dict[str, List[str]] = {}          # 父类到子类的映射
        self.child_parent_map: Dict[str, str] = {}                # 子类到父类的映射
        self.rule_file_path = None  # 规则文件路径
        self.rule_sink_mapping = {}  # sink 到漏洞类型的映射

        # 检测并确定使用的规则文件
        project_name = self.project_path.rstrip('/').split('/')[-1]
        result_dir = os.path.join("Result", project_name)
        os.makedirs(result_dir, exist_ok=True)

        # 查找项目中已存在的规则文件（如 project_rule_1.json, project_rule_2.json）
        existing_rule_files = []
        if not force_default_rules:
            for file in os.listdir(result_dir):
                if file.startswith(f"{project_name}_rule_") and file.endswith(".json"):
                    existing_rule_files.append(file)

        if existing_rule_files:
            # 找到最新的规则文件（数字最大的）
            existing_rule_files.sort(key=lambda x: int(x.split('_')[-1].replace('.json', '')))
            latest_rule_file = existing_rule_files[-1]
            rules_path = os.path.join(result_dir, latest_rule_file)
            print(f"[+]检测到项目规则文件，使用：{rules_path}")

        # 加载规则
        self.rules = self._load_rules(rules_path)

        # 设置输出规则文件的路径（递增数字）
        if force_default_rules:
            # 强制使用默认规则时，从 1 开始
            next_rule_num = 1
        elif existing_rule_files:
            # 根据最新规则文件的数字递增
            latest_num = int(existing_rule_files[-1].split('_')[-1].replace('.json', ''))
            next_rule_num = latest_num + 1
        else:
            # 没有现有规则文件，从 1 开始
            next_rule_num = 1

        self.rule_file_path = os.path.join(result_dir, f"{project_name}_rule_{next_rule_num}.json")
        print(f"[+]新的规则文件将保存到：{self.rule_file_path}")

        self._build_sink_mapping()  # 构建 sink 到漏洞类型的映射

    @staticmethod
    def _load_rules(path: str) -> dict:
        """
        读取本地json格式的配置文件的数据
        """
        with open(path, "r", encoding="utf-8") as f:
            rules = json.load(f)
            print(f"[+]成功加载Rules：{rules}")
            return rules

    def _build_sink_mapping(self):
        """
        构建 sink 点到漏洞类型的映射关系
        """
        for rule in self.rules["sink_rules"]:
            for sink in rule["sinks"]:
                self.rule_sink_mapping[sink] = {
                    "sink_name": rule["sink_name"],
                    "sink_desc": rule["sink_desc"],
                    "severity_level": rule["severity_level"]
                }

    def _is_excluded(self, file_path):
        """
        判断当前的代码路径是不是配置文件设置的无需扫描的白名单路径
        """
        rel_path = os.path.relpath(file_path, self.project_path)
        return any(p in rel_path.split(os.sep) for p in self.rules["path_exclusions"])

    def build_ast(self, cache_file: str = None, force_rebuild: bool = False):
        """
        构建项目AST并建立调用关系（两阶段解析）
        第一阶段：收集所有类、方法、接口、继承关系
        第二阶段：在所有信息收集完成后构建调用关系图
        
        参数:
            cache_file: 缓存文件路径。如果为 None，则自动生成到 Result/{project_name}/{project_name}_ast.json
            force_rebuild: 是否强制重新构建 AST，忽略缓存
        """
        # 初始化输出规则文件的数据结构
        self.existing_rules = {
            "depth": self.rules["depth"],
            "path_exclusions": self.rules["path_exclusions"],
            "sink_rules": []
        }

        # 如果没有提供缓存文件，自动生成缓存文件路径
        project_name = self.project_path.rstrip('/').split('/')[-1]
        cache_dir = os.path.join("Result", project_name)
        if cache_file is None:
            cache_file = os.path.join(cache_dir, f"{project_name}_ast.json")

        # 如果不强制重新构建，尝试加载缓存
        if not force_rebuild and os.path.exists(cache_file):
            print(f"[+]检测到缓存文件，尝试加载：{cache_file}")
            if self.load_cache(cache_file):
                print(Fore.LIGHTGREEN_EX + f"[+]成功从缓存加载 AST 数据，跳过构建过程")
                return
            else:
                print(Fore.YELLOW + f"[+]缓存加载失败，将重新构建 AST")
        else:
            if force_rebuild:
                print(f"[+]检测到 -r 参数，强制重新构建 AST")
            else:
                print(f"[+]缓存文件不存在，将重新构建 AST")

        # 第一阶段：收集所有类、方法、接口、继承关系
        print(f"[+]第一阶段：收集类、方法、接口、继承关系")
        code_trees = {}  # 存储每个文件的AST树，用于第二阶段构建调用图
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

        print(Fore.LIGHTBLUE_EX + f"[+]第一阶段完成！")
        # 输出接口实现关系（调试用）
        if self.interface_implementations:
            print(Fore.CYAN + f"[+]已识别的接口实现关系：")
            for interface, impls in self.interface_implementations.items():
                print(f"    接口 {interface} 的实现类: {', '.join(impls)}")
        # 输出继承关系（调试用）
        if self.parent_child_map:
            print(Fore.CYAN + f"[+]已识别的继承关系：")
            for parent, children in self.parent_child_map.items():
                print(f"    父类 {parent} 的子类: {', '.join(children)}")

        # 第二阶段：在所有信息收集完成后构建调用关系图
        print(f"[+]第二阶段：构建调用关系图")
        for file_path, code_tree in code_trees.items():
            self._build_call_graph(code_tree)

        print(Fore.LIGHTBLUE_EX + f"[+]AST构建全部完成！")
        # print(f"[+]已构建的调用关系图：{self.call_graph}")
        # print(f"[+]已构建的类方法信息：{self.class_methods}")
        
        # 保存构建结果到缓存
        self.save_cache(cache_file)

    def _process_file(self, file_path: str):
        """
        此方法已被 build_ast 的两阶段解析替代，保留以兼容性
        """
        pass

    def _extract_class_info(self, code_tree, file_path: str):
            """
            从Java代码的AST树中提取类和方法信息，并记录继承关系与接口实现关系。
    
            该方法遍历给定的代码树（code_tree），识别所有类声明，收集每个类的方法信息（包括是否需要参数、
            是否包含Web映射注解），并建立以下映射关系：
            - 类名到其所在文件路径及方法信息的映射（存储于 self.class_methods）
            - 父类到子类的映射（存储于 self.parent_child_map）
            - 子类到父类的映射（存储于 self.child_parent_map）
            - 类实现的接口列表（存储于 self.class_interfaces）
            - 接口到其实现类的映射（存储于 self.interface_implementations）
    
            参数:
                code_tree: Java代码解析后的抽象语法树（AST），支持 filter 方法以筛选 ClassDeclaration 节点。
                file_path (str): 当前处理的Java源文件的完整路径，用于关联类与其物理位置。
    
            返回值:
                无（该方法通过修改实例属性完成数据收集）。
            """
            MAPPING_ANNOTATIONS = {
                "GetMapping", "PostMapping", "RequestMapping", "PutMapping", "DeleteMapping",
                "Path", "GET", "POST", "PUT", "DELETE"
            }
            # 遍历所有类声明节点，提取类名、方法信息及继承/实现关系
            for path, node in code_tree.filter(ClassDeclaration):
                class_name = node.name
                methods_info = {}
                # 提取当前类中每个方法的关键属性：是否需要参数、是否带有Web映射注解
                for method_node in node.methods:
                    method_name = method_node.name
                    requires_params = len(method_node.parameters) > 0
                    has_mapping_annotation = False
                    if method_node.annotations:
                        for annotation in method_node.annotations:
                            annotation_name = annotation.name.lstrip("@")
                            if annotation_name in MAPPING_ANNOTATIONS:
                                has_mapping_annotation = True
                                break
                    methods_info[method_name] = {
                        "requires_params": requires_params,
                        "has_mapping_annotation": has_mapping_annotation
                    }
                self.class_methods[class_name] = {
                    "file_path": file_path,
                    "methods": methods_info
                }
    
                # 提取继承关系
                if node.extends:
                    parent_class = node.extends.name
                    # 建立父类到子类的映射
                    if parent_class not in self.parent_child_map:
                        self.parent_child_map[parent_class] = []
                    if class_name not in self.parent_child_map[parent_class]:
                        self.parent_child_map[parent_class].append(class_name)
                    # 建立子类到父类的映射
                    self.child_parent_map[class_name] = parent_class
    
                # 提取接口实现关系
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

    def _build_call_graph(self, file_code_tree):
        """
        构建所有类中方法的调用图，处理接口多态调用和继承多态调用
        """
        variable_symbols = self.get_variable_symbols(file_code_tree)
        for path, node in file_code_tree:
            # --- 情况 1: 识别 variable.method() 普通模式 ---
            if isinstance(node, javalang.tree.MethodInvocation):
                caller = self._get_current_method_from_path(path)
                callee = "[!]callee解析失败"
                is_polymorphic_call = False
                if node.qualifier:
                    qualifier = node.qualifier

                    default = qualifier.split('.')[0] if '.' in qualifier and qualifier.split('.')[0][0].isupper() else qualifier
                    base_type = variable_symbols.get(qualifier, default)
                    base_type = base_type.split('<')[0]
                    callee = f"{base_type}:{node.member}"

                    # 如果调用的是接口方法，则扩展到所有实现类的方法
                    if base_type in self.interface_implementations:
                        is_polymorphic_call = True
                        implementations = self.interface_implementations[base_type]
                        for impl_class in implementations:
                            impl_callee = f"{impl_class}:{node.member}"
                            self.call_graph.setdefault(caller, []).append(impl_callee)
                            print(f"[Interface] {caller} -> {impl_callee} (实现自接口 {base_type})")

                    # 如果调用的是父类方法，则扩展到所有子类的方法
                    if base_type in self.parent_child_map:
                        is_polymorphic_call = True
                        child_classes = self.parent_child_map[base_type]
                        for child_class in child_classes:
                            child_callee = f"{child_class}:{node.member}"
                            self.call_graph.setdefault(caller, []).append(child_callee)
                            print(f"[Inheritance] {caller} -> {child_callee} (继承自父类 {base_type})")

                elif node.qualifier is None:
                    base_type = '[!]base_type解析失败'
                    if self.is_string_literal_caller(path):
                        base_type = "String"
                    else:
                        try:
                            parent_node = path[-2] if len(path) > 1 else None
                            if isinstance(parent_node, javalang.tree.ClassCreator):
                                base_type = parent_node.type.name
                            elif isinstance(parent_node, javalang.tree.ClassReference):
                                base_type = parent_node.type.name
                            else:
                                base_type = self.call_graph[caller][-1].split(':')[0]
                        except Exception as e:
                            print(Fore.RED + f"[!]待排查异常解析：{caller} -> {node.member}, 异常信息：{e}")
                    callee = f"{base_type}:{node.member}"
                elif '.' not in node.member:
                    callee = f"{caller.split(':')[0]}:{node.member}"

                if str(callee).startswith('[!]'):
                    print(Fore.RED + f"[CallGraph] {caller} -> {callee}")
                else:
                    # 如果不是多态调用，则正常添加到调用图
                    if not is_polymorphic_call:
                        print(f"[CallGraph] {caller} -> {callee}")
                        self.call_graph.setdefault(caller, []).append(callee)
            elif isinstance(node, javalang.tree.This):  
                callee = "[!]callee解析失败"
                caller = self._get_current_method_from_path(path)              
                # --- 情况 2: 识别 this.variable.method() 模式 ---
                if  node.selectors:
                    try:
                        first_selector = node.selectors[0] # 变量名
                        second_selector = node.selectors[1] # 方法名
                        if isinstance(second_selector, javalang.tree.MethodInvocation):
                            var_name = first_selector.member
                            method_name = second_selector.member
                            var_type = variable_symbols.get(var_name)                        
                            # print(f"发现调用: this.{var_name}.{method_name}()")
                            # print(f"  -> 变量 '{var_name}' 的类型是: 【{var_type}】")
                            callee = f"{var_type}:{method_name}"
                            print(f"[CallGraph] {caller} -> {callee}")
                            self.call_graph.setdefault(caller, []).append(callee)
                            # 如果调用的是接口方法，则扩展到所有实现类的方法
                            if var_type in self.interface_implementations:
                                is_polymorphic_call = True
                                implementations = self.interface_implementations[var_type]
                                for impl_class in implementations:
                                    impl_callee = f"{impl_class}:{method_name}"
                                    self.call_graph.setdefault(caller, []).append(impl_callee)
                                    print(f"[Interface] {caller} -> {impl_callee} (实现自接口 {var_type})")

                            # 如果调用的是父类方法，则扩展到所有子类的方法
                            if var_type in self.parent_child_map:
                                is_polymorphic_call = True
                                child_classes = self.parent_child_map[var_type]
                                for child_class in child_classes:
                                    child_callee = f"{child_class}:{method_name}"
                                    self.call_graph.setdefault(caller, []).append(child_callee)
                                    print(f"[Inheritance] {caller} -> {child_callee} (继承自父类 {var_type})")
                    except Exception as e:
                        print(Fore.RED + f"[!]待排查异常解析：{caller}, 异常信息：{e}")
                    else:
                        print(f"[CallGraph] {caller} -> {callee}")
    @staticmethod
    def is_string_literal_caller(path):
        """
        判断方法调用是否由字符串常量
        """
        for parent in reversed(path):
            if isinstance(parent, javalang.tree.Literal) and isinstance(parent.value, str):
                return True
        return False

    @staticmethod
    def get_variable_symbols(file_code_tree):
        """
        提取类中所有变量声明及其类型
        """
        variable_symbols = {}
        for path, node in file_code_tree:
            if isinstance(node, javalang.tree.LocalVariableDeclaration):
                var_type = node.type.name
                for declarator in node.declarators:
                    variable_symbols[declarator.name] = var_type
            elif isinstance(node, javalang.tree.FieldDeclaration):
                var_type = node.type.name
                for declarator in node.declarators:
                    variable_symbols[declarator.name] = var_type
            elif isinstance(node, javalang.tree.MethodDeclaration):
                for param in node.parameters:
                    var_type = param.type.name
                    variable_symbols[param.name] = var_type
        return variable_symbols

    def _get_current_method_from_path(self, path) -> str:
        """
        通过AST路径直接获取当前函数节点所对应的类的信息，用于构建调用图
        """
        for node in reversed(path):
            if isinstance(node, javalang.tree.MethodDeclaration):
                class_node = self.find_parent_class(path)
                class_name = getattr(class_node, 'name', 'unknown')
                return f"{class_name}:{node.name}"
        return "unknown:unknown"

    def find_taint_paths(self) -> List[dict]:
        print("-" * 50)
        print(f"[+]正在审计源项目：{self.project_path}")
        # print(Fore.MAGENTA + f"[+]提取到的类函数字典：{self.class_methods}")
        results = []
        for rule in self.rules["sink_rules"]:
            for sink in rule["sinks"]:
                class_name, methods = sink.split(":")
                for method in methods.split("|"):
                    class_name = class_name.split('.')[-1]
                    sink_point = f"{class_name}:{method}"
                    print(f"[+]正在审计sink点：{sink_point}")
                    paths = self._trace_back(sink_point, self.rules["depth"])
                    if paths:
                        results.append({
                            "vul_type": rule["sink_name"],
                            "sink_desc": rule["sink_desc"],
                            "severity": rule["severity_level"],
                            "sink": sink_point,
                            # "call_chains": self.process_call_stacks(self.project_path, paths)
                            "call_chains": paths
                        })
        print("-" * 50)
        return results

    @staticmethod
    def process_call_stacks(root_dir, call_stacks):
        results = []
        method_cache = {}  # 缓存已提取的方法定义，避免重复调用
        for stack in call_stacks:
            visited = set()
            chain = []
            code_list = []
            queue = []
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

    def _trace_back(self, sink: str, max_depth: int) -> List[List[str]]:
        """
        根据最大追溯深度的限制，回溯污点传播的路径，支持多级调用链展开
        """
        paths = []
        queue = deque([([sink], 0)])
        while queue:
            current_path, current_depth = queue.popleft()
            if current_depth >= max_depth:
                continue
            current_sink = current_path[0]
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
                if not self.force_default_rules:
                    self._write_rule_file(sink, caller_methods)
            for caller in caller_methods:
                # if not self.is_has_parameters(caller.split(':')[0], caller.split(':')[1]):
                #     print(Fore.RED + f"[!]发现无参的函数：{caller}，此链路忽略不计！")
                #     continue
                new_path = [caller] + current_path
                print(Fore.YELLOW + f"[→]正在追溯的路径: [{' → '.join(new_path)}]")
                if self.is_entry_point(caller):
                    paths.append(new_path)
                    print(Fore.LIGHTGREEN_EX + f"[✓]发现完整调用链: {new_path}")
                    # 如果使用 -f 参数，只在发现完整调用链时写入倒数第二个节点
                    if self.force_default_rules and len(new_path) >= 2:
                        caller_to_write = new_path[-2]  # 倒数第二个节点（new_path[0] 是 caller, new_path[-1] 是 sink）
                        self._write_rule_file(sink, [caller_to_write])
                else:
                    queue.append((new_path, current_depth + 1))
        return paths

    def _write_rule_file(self, sink: str, caller_methods: List[str]):
        """
        将需要追溯的调用点写入规则文件，并生成包含函数内容的 JSON 文件
        
        参数:
            sink: 当前正在追溯的 sink 点
            caller_methods: 需要追溯的调用点列表
        """
        # print(Fore.MAGENTA + f"[*]正在写入规则文件：{self.rule_file_path}")
        if not self.rule_file_path:
            return
        
        # 查找当前 sink 对应的漏洞类型信息
        vul_type_info = None
        for rule in self.rules["sink_rules"]:
            for Rsink in rule["sinks"]:
                if sink in Rsink:
                    vul_type_info = {
                        "sink_name": rule["sink_name"],
                        "sink_desc": rule["sink_desc"],
                        "severity_level": rule["severity_level"]
                    }
                    break
        # print(f"[+]正在写入漏洞类型信息：{vul_type_info}")
        if not vul_type_info:
            return
        
        # 查找或创建对应的 sink_rule
        existing_rule = None
        for rule in self.existing_rules["sink_rules"]:
            if rule["sink_name"] == vul_type_info["sink_name"]:
                existing_rule = rule
                break
        # print(f"[+]正在写入漏洞类型信息：{existing_rule}")
        if not existing_rule:
            # 创建新的 sink_rule
            existing_rule = {
                "sink_name": vul_type_info["sink_name"],
                "sink_desc": vul_type_info["sink_desc"],
                "severity_level": vul_type_info["severity_level"],
                "sinks": []
            }
            self.existing_rules["sink_rules"].append(existing_rule)
        
        # 将调用点添加到对应的 sink_rule 中
        new_sinks = []
        for caller in caller_methods:
            if caller not in existing_rule["sinks"]:
                existing_rule["sinks"].append(caller)
                new_sinks.append(caller)
                # print(Fore.CYAN + f"[+]已将调用点 [{caller}] 添加到规则文件，漏洞类型：{vul_type_info['sink_name']}")

        # 根据 force_default_rules 参数决定 depth
        if self.force_default_rules:
            self.existing_rules["depth"] = 1  # 使用 -f 参数时，depth 固定为 1
        else:
            self.existing_rules["depth"] = self.rules["depth"]  # 不使用 -f 参数时，使用原始 depth

        # 写入到文件
        try:
            with open(self.rule_file_path, "w", encoding="utf-8") as f:
                json.dump(self.existing_rules, f, indent=4, ensure_ascii=False)
        except Exception as e:
            print(Fore.RED + f"[!]写入规则文件失败：{e}")

        # 生成函数内容文件
        if new_sinks:
            self._write_func_file(new_sinks, vul_type_info)

    def _write_func_file(self, sinks: List[str], vul_type_info: dict):
        """
        为指定的 sink 列表生成包含函数内容的 JSON 文件
        
        参数:
            sinks: 需要提取函数内容的 sink 列表（格式：类名:方法名）
            vul_type_info: 漏洞类型信息，包含 sink_name、sink_desc、severity_level
        """
        # 生成函数内容文件路径（与规则文件命名类似）
        rule_file_name = os.path.basename(self.rule_file_path)
        # 将 "project_rule_1.json" 替换为 "project_func_1.json"
        func_file_name = rule_file_name.replace("_rule_", "_func_")
        func_file_path = os.path.join(os.path.dirname(self.rule_file_path), func_file_name)
        
        # 初始化函数内容数据结构
        func_data = {
            "functions": {}
        }
        
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
                # 调用 extract_method_definition 获取函数内容
                file_path, method_code = extract_method_definition(self.project_path, class_name, method_name)
                
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

    def resolve_actual_type(self, var_type: str) -> List[str]:
        """
        解析变量的实际类型，如果是接口类型返回所有实现类，如果是父类返回所有子类
        """
        # 优先检查接口实现
        if var_type in self.interface_implementations:
            return self.interface_implementations[var_type]
        # 其次检查继承关系
        if var_type in self.parent_child_map:
            return self.parent_child_map[var_type]
        # 普通类型直接返回
        return [var_type]

    def is_has_parameters(self, class_name: str, method_name: str) -> bool:
        """
        判断给定类中的给定方法是否包含参数
        """
        try:
            class_info = self.class_methods.get(class_name, {})
            method_info = class_info.get("methods", {}).get(method_name, {})
            return method_info.get("requires_params", True)
        except KeyError:
            return True

    def is_entry_point(self, method: str) -> bool:
        """
        判断当前追溯到的函数是否已经是程序的外部入口点（MAPPING_ANNOTATIONS相关函数）
        """
        class_name, method_name = method.split(":")
        is_method_entry_point = False
        class_info = self.class_methods.get(class_name, {})
        method_info = class_info.get("methods", {}).get(method_name, {})
        if method_info:
            # 方法是否被标记了 Web 路由注解（如 @PostMapping），
            is_method_entry_point = method_info.get("has_mapping_annotation", False)
        return is_method_entry_point

    def save_cache(self, cache_file: str):
        """
        将构建的 AST 数据保存到缓存文件
        """
        cache_data = {
            "call_graph": self.call_graph,
            "class_methods": self.class_methods,
            "interface_implementations": self.interface_implementations,
            "class_interfaces": self.class_interfaces,
            "parent_child_map": self.parent_child_map,
            "child_parent_map": self.child_parent_map,
            "project_path": self.project_path
        }
        try:
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(cache_data, f, indent=4, ensure_ascii=False)
            print(Fore.GREEN + f"[+]缓存已保存到：{cache_file}")
        except Exception as e:
            print(Fore.RED + f"[!]保存缓存失败：{e}")

    def load_cache(self, cache_file: str) -> bool:
        """
        从缓存文件加载 AST 数据
        返回 True 表示加载成功，False 表示加载失败
        """
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                cache_data = json.load(f)
            
            # 验证缓存数据完整性
            required_keys = ["call_graph", "class_methods", "interface_implementations",
                           "class_interfaces", "parent_child_map", "child_parent_map", "project_path"]
            if not all(key in cache_data for key in required_keys):
                print(Fore.RED + f"[!]缓存文件格式不正确，缺少必要字段")
                return False
            
            # 验证缓存的项目路径是否匹配
            if cache_data["project_path"] != self.project_path:
                print(Fore.YELLOW + f"[!]警告：缓存的项目路径 ({cache_data['project_path']}) 与当前项目路径 ({self.project_path}) 不匹配")
                print(Fore.YELLOW + f"[!]仍然尝试加载缓存，但可能导致结果不准确")
            
            # 加载数据
            self.call_graph = cache_data["call_graph"]
            self.class_methods = cache_data["class_methods"]
            self.interface_implementations = cache_data["interface_implementations"]
            self.class_interfaces = cache_data["class_interfaces"]
            self.parent_child_map = cache_data["parent_child_map"]
            self.child_parent_map = cache_data["child_parent_map"]
            
            print(Fore.GREEN + f"[+]成功从缓存加载 AST 数据：{cache_file}")
            print(f"[+]调用图节点数：{len(self.call_graph)}")
            print(f"[+]类方法数：{len(self.class_methods)}")
            print(f"[+]接口实现数：{len(self.interface_implementations)}")
            print(f"[+]继承关系数：{len(self.parent_child_map)}")
            return True
        except FileNotFoundError:
            print(Fore.RED + f"[!]缓存文件不存在：{cache_file}")
            return False
        except json.JSONDecodeError as e:
            print(Fore.RED + f"[!]缓存文件格式错误：{e}")
            return False
        except Exception as e:
            print(Fore.RED + f"[!]加载缓存失败：{e}")
            return False

    @staticmethod
    def find_parent_class(path) -> javalang.tree.ClassDeclaration:
        """
        从AST路径中查找最近的类声明或接口声明
        """
        for node in reversed(path):
            if isinstance(node, (javalang.tree.ClassDeclaration, javalang.tree.InterfaceDeclaration)):
                return node
        # 如果找不到类声明，返回一个默认的类节点对象
        default_class = type('obj', (object,), {'name': 'unknown'})()
        return default_class


def run():
    start_time = time.time()
    print(Fore.LIGHTCYAN_EX + """
      ███████╗███████╗ ██████╗  
     ██╔════╝██╔════╝██╔════╝ 
     ███████╗█████╗  ██║     
     ╚════██║██╔══╝  ██║      
     ███████║███████╗╚██████╗ 
     ╚══════╝╚══════╝ ╚═════╝ 
    """ + Fore.LIGHTGREEN_EX + """
    Java源代码漏洞审计工具_Tr0e
    """ + Fore.RESET)
    parser = argparse.ArgumentParser(description="JavaSinkTracer")
    parser.add_argument('-p', "--projectPath", type=str, default='D:/Code/Github/java-sec-code', help=f"待扫描的项目本地路径根目录，默认值：D:/Code/Github/java-sec-code")
    # parser.add_argument('-o', "--outputPath", type=str, default='Result', help=f"指定扫描报告输出的本地路径根目录，默认值：当前项目根路径下的 Result 子文件夹")
    parser.add_argument('-r', "--rebuild", action='store_true', help=f"强制重新构建 AST，忽略已存在的缓存文件")
    parser.add_argument('-f', "--force-default-rules", action='store_true', help=f"强制使用默认规则文件（Rules/rules.json），忽略项目中的规则文件")
    args = parser.parse_args()
    java_project_path = args.projectPath.replace('\\', '/')
    java_project_name = java_project_path.rstrip('/').split('/')[-1]
    print(f'[+]待扫描的project_name: {java_project_name}, project_path: {java_project_path}')
    analyzer = JavaSinkTracer(java_project_path, "Rules/rules_plus.json", force_default_rules=args.force_default_rules)
    analyzer.build_ast(force_rebuild=args.rebuild)
    vulnerabilities = analyzer.find_taint_paths()
    print(Fore.LIGHTGREEN_EX + f"[+]代码审计结果汇总：\n{json.dumps(vulnerabilities, indent=2, ensure_ascii=False)}")
    target_dir = os.path.join("Result", java_project_name)
    os.makedirs(target_dir, exist_ok=True)
    sink_save_file = os.path.join(target_dir, f"sink_chains.json")
    with open(sink_save_file, "w", encoding="utf-8") as file:
        json.dump(vulnerabilities, file, indent=4, ensure_ascii=False)
    # generate_markdown_report(java_project_name, java_project_path, sink_save_file, args.outputPath)
    print(f"[+]主进程任务完成，耗时：{round(time.time() - start_time, 2)}秒")


if __name__ == "__main__":
    run()
