import argparse
import os
import json
import time

from colorama import Fore, init

from sinktracer import (
    DEFAULT_RULES_PATH,
    RuleManager,
    ASTBuilder,
    CallGraphBuilder,
    TaintAnalyzer,
    CacheManager,
    EntryDetector,
)

# 初始化 colorama
init(autoreset=True)


class JavaSinkTracer:
    """
    JavaSinkTracer 主类
    
    作为协调器整合各模块功能，完成 Java 源代码漏洞审计流程
    
    Attributes:
        project_path: 项目路径
        rule_manager: 规则管理器
        ast_builder: AST 构建器
        call_graph_builder: 调用图构建器
        entry_detector: 入口点检测器
        taint_analyzer: 污点分析器
        cache_manager: 缓存管理器
    """
    
    def __init__(self, project_path: str, rules_path: str = DEFAULT_RULES_PATH):
        """
        初始化 JavaSinkTracer
        
        Args:
            project_path: 项目路径
            rules_path: 规则文件路径
        """
        self.project_path = project_path
        
        # 初始化各模块
        self.rule_manager = RuleManager(project_path, rules_path)
        
        self.ast_builder = ASTBuilder(
            project_path, self.rule_manager.get_path_exclusions()
        )
        
        self.call_graph_builder = CallGraphBuilder(
            self.ast_builder.get_interface_implementations(),
            self.ast_builder.get_parent_child_map(),
            self.ast_builder.get_method_return_types(),
            self.ast_builder.get_import_mapping()
        )
        
        self.cache_manager = CacheManager(project_path)
        
        # 入口点检测器和污点分析器延迟初始化
        self.entry_detector = None
        self.taint_analyzer = None
    
    def build_ast(self, force_rebuild: bool = False):
        """
        构建项目 AST 并建立调用关系
        
        流程：
            1. 检查缓存（如果存在且未强制重建）
            2. 构建类、方法、接口、继承信息
            3. 构建调用关系图
            4. 保存缓存
        
        Args:
            force_rebuild: 是否强制重新构建 AST
        """
        # 尝试从缓存加载
        if not force_rebuild and self.cache_manager.exists():
            print(f"[+]检测到缓存文件，尝试加载：{self.cache_manager.get_cache_file()}")
            if self._load_from_cache():
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
        code_trees = self.ast_builder.build()
        
        # 更新调用图构建器的映射关系
        self.call_graph_builder = CallGraphBuilder(
            self.ast_builder.get_interface_implementations(),
            self.ast_builder.get_parent_child_map(),
            self.ast_builder.get_method_return_types(),
            self.ast_builder.get_import_mapping()
        )
        
        # 第二阶段：构建调用关系图
        self.call_graph_builder.build(code_trees)
        
        # 初始化入口点检测器
        self.entry_detector = EntryDetector(self.ast_builder.get_class_methods())
        
        # 保存缓存
        self.cache_manager.save(self.ast_builder, self.call_graph_builder)
    
    def _load_from_cache(self) -> bool:
        """
        从缓存加载数据并恢复各模块状态
        
        Returns:
            加载是否成功
        """
        import json
        
        try:
            with open(self.cache_manager.get_cache_file(), "r", encoding="utf-8") as f:
                cache_data = json.load(f)
            
            # 恢复 AST 构建器状态
            self.ast_builder.class_methods = cache_data["class_methods"]
            self.ast_builder.interface_implementations = cache_data["interface_implementations"]
            self.ast_builder.class_interfaces = cache_data["class_interfaces"]
            self.ast_builder.parent_child_map = cache_data["parent_child_map"]
            self.ast_builder.child_parent_map = cache_data["child_parent_map"]
            
            # 恢复新增的数据（兼容旧缓存）
            self.ast_builder.method_return_types = cache_data.get("method_return_types", {})
            self.ast_builder.import_mapping = cache_data.get("import_mapping", {})
            self.ast_builder.class_file_mapping = cache_data.get("class_file_mapping", {})
            
            # 恢复调用图构建器状态
            self.call_graph_builder = CallGraphBuilder(
                self.ast_builder.get_interface_implementations(),
                self.ast_builder.get_parent_child_map(),
                self.ast_builder.get_method_return_types(),
                self.ast_builder.get_import_mapping()
            )
            self.call_graph_builder.call_graph = cache_data["call_graph"]
            
            # 初始化入口点检测器
            self.entry_detector = EntryDetector(self.ast_builder.get_class_methods())
            
            return True
        except Exception as e:
            print(Fore.RED + f"[!]从缓存恢复状态失败：{e}")
            return False
    
    def find_taint_paths(self):
        """
        查找污点路径
        
        Returns:
            漏洞检测结果列表
        """
        # 初始化污点分析器
        self.taint_analyzer = TaintAnalyzer(
            self.project_path,
            self.call_graph_builder.get_call_graph(),
            self.ast_builder.get_class_methods(),
            self.rule_manager,
            self.entry_detector,
            self.ast_builder.get_parent_child_map()
        )
        
        return self.taint_analyzer.find_taint_paths()


def run():
    """
    主函数入口
    
    解析命令行参数并执行漏洞审计流程
    """
    start_time = time.time()
    
    # 打印 Banner
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
    
    # 解析命令行参数
    parser = argparse.ArgumentParser(description="JavaSinkTracer")
    parser.add_argument('-p', "--projectPath", type=str,
                       default='D:/Code/Github/java-sec-code',
                       help="待扫描的项目本地路径根目录")
    parser.add_argument('-r', "--rebuild", action='store_true',
                       help="强制重新构建 AST，忽略已存在的缓存文件")
    
    args = parser.parse_args()
    
    # 处理路径
    java_project_path = args.projectPath.replace('\\', '/')
    java_project_name = java_project_path.rstrip('/').split('/')[-1]
    
    print(f'[+]待扫描的project_name: {java_project_name}, project_path: {java_project_path}')
    
    # 创建分析器并执行分析
    analyzer = JavaSinkTracer(
        java_project_path,
        DEFAULT_RULES_PATH
    )
    
    # 构建 AST
    analyzer.build_ast(force_rebuild=args.rebuild)
    
    # 查找污点路径
    vulnerabilities = analyzer.find_taint_paths()
    
    # 输出结果
    print(Fore.LIGHTGREEN_EX + f"[+]代码审计结果汇总：\n"
          f"{json.dumps(vulnerabilities, indent=2, ensure_ascii=False)}")
    
    # 保存结果到文件
    target_dir = os.path.join("Result", java_project_name)
    os.makedirs(target_dir, exist_ok=True)
    sink_save_file = os.path.join(target_dir, f"sink_chains.json")
    
    with open(sink_save_file, "w", encoding="utf-8") as file:
        json.dump(vulnerabilities, file, indent=4, ensure_ascii=False)
    
    print(f"[+]主进程任务完成，耗时：{round(time.time() - start_time, 2)}秒")


if __name__ == "__main__":
    run()