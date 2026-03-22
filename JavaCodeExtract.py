import os
import javalang


def extract_method_from_file(filepath, class_name, method_name):
    """
    从指定的 Java 文件中提取指定类的指定方法定义。

    参数:
        filepath (str): Java 文件的完整路径。
        class_name (str): 目标类的名称。
        method_name (str): 目标方法的名称。

    返回值:
        tuple: 包含两个元素的元组：
            - filepath (str 或 None): 找到方法定义的 Java 文件路径；若未找到则为 None。
            - definition (str 或 None): 方法的完整代码块字符串；若未找到则为 None。
    """
    result = extract_methods_from_file(filepath, [f"{class_name}:{method_name}"])
    key = f"{class_name}:{method_name}"
    if key in result:
        return filepath, result[key]
    return None, None


def extract_methods_from_file(filepath, method_list):
    """
    从指定的 Java 文件中批量提取多个方法的代码定义。

    参数:
        filepath (str): Java 文件的完整路径。
        method_list (list): 方法标识列表，格式为 ["类名:方法名", ...]
                           例如: ["TaskAction:indexTaskStatistikQuery", "TaskAction:statistByDepart"]

    返回值:
        dict: 字典，key 为 "类名:方法名"，value 为对应的方法代码块字符串。
              未找到的方法不会出现在结果中。
    """
    result = {}
    
    if not method_list:
        return result
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        content = ''.join(lines)
        tree = javalang.parse.parse(content)
    except (IOError, javalang.parser.JavaSyntaxError, IndexError):
        return result

    # 构建需要查找的方法集合，按类名分组
    methods_to_find = {}
    for item in method_list:
        if ':' in item:
            cls, mtd = item.split(':', 1)
            if cls not in methods_to_find:
                methods_to_find[cls] = set()
            methods_to_find[cls].add((mtd, item))  # (方法名, 原始key)

    # 在语法树中查找匹配的类或接口声明
    for node_type in (javalang.tree.ClassDeclaration, javalang.tree.InterfaceDeclaration):
        for _, node in tree.filter(node_type):
            if node.name in methods_to_find:
                # 在匹配的类中查找目标方法
                for method in node.methods:
                    for mtd_name, original_key in methods_to_find[node.name]:
                        if method.name == mtd_name and method.position:
                            definition = _extract_code_block(lines, method.position.line - 1)
                            result[original_key] = definition
                            break

    return result


def extract_method_definition(root_dir, class_name, method_name):
    """
    在指定目录及其子目录中搜索并提取指定类中的指定方法定义。

    该函数遍历给定根目录下的所有 Java 文件，解析每个文件的语法树，
    查找匹配的类名和方法名，并返回该方法的完整代码块及其所在文件路径。

    参数:
        root_dir (str): 要搜索的根目录路径。
        class_name (str): 目标类的名称。
        method_name (str): 目标方法的名称。

    返回值:
        tuple: 包含两个元素的元组：
            - filepath (str 或 None): 找到方法定义的 Java 文件路径；若未找到则为 None。
            - definition (str 或 None): 方法的完整代码块字符串；若未找到则为 None。
    """
    # 遍历根目录下所有文件，仅处理 .java 文件
    for dirpath, _, filenames in os.walk(root_dir):
        for filename in filenames:
            if not filename.endswith('.java'):
                continue
            filepath = os.path.join(dirpath, filename)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                content = ''.join(lines)
                tree = javalang.parse.parse(content)
            except (IOError, javalang.parser.JavaSyntaxError, IndexError):
                continue
            
            # 在语法树中查找匹配的类或接口声明
            for node_type in (javalang.tree.ClassDeclaration, javalang.tree.InterfaceDeclaration):
                for _, node in tree.filter(node_type):
                    if node.name == class_name:
                        # 在匹配的类中查找目标方法
                        for method in node.methods:
                            if method.name == method_name and method.position:
                                definition = _extract_code_block(lines, method.position.line - 1)
                                return filepath, definition
    return None, None


def _extract_code_block(lines, start_index):
    code_lines = []
    brace_depth = 0
    started = False
    for line in lines[start_index:]:
        code_lines.append(line)
        if not started and '{' in line:
            brace_depth += line.count('{') - line.count('}')
            started = True
        elif started:
            brace_depth += line.count('{') - line.count('}')
        if started and brace_depth == 0:
            break
    return ''.join(code_lines)


if __name__ == "__main__":
    root_directory = r"C:/Users/1y0ng/Downloads/srccode/product-v3/src"
    print(extract_methods_from_file("C:/Users/1y0ng/Downloads/srccode/product-v3/src/com/unitever/dc/intelligentOffice/module/task/action/TaskAction.java",["TaskAction:indexTaskStatistikQuery","TaskAction:statistByDepart"]))
    # path, code = extract_method_definition(root_directory, "EbookForPadAction", "getTeachingMaterialContent")
    # if path:
    #     print(f"Found in {path}:\n{code}")
    # else:
    #     print("未找到匹配的类或方法！")