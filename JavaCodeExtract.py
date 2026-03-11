import os
import javalang

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
    root_directory = r"D:\Code\Java\JavaVulHunter"
    path, code = extract_method_definition(root_directory, "TomcatFilterMemShell", "doFilter")
    if path:
        print(f"Found in {path}:\n{code}")
    else:
        print("未找到匹配的类或方法！")