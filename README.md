## 前言

JavaSinkTracer 是基于 Python javalang 库开发的一款轻量级 Java 源代码漏洞审计工具，开发人员 [Tr0e](https://github.com/Tr0e)。
> JavaSinkTracer is a lightweight Java source code vulnerability auditing tool developed based on the Python javalang library, developed by [Tr0e](https://github.com/Tr0e).

## 原理

常见的 SAST 工具（比如著名的 CodeQL）一般都是基于"变量级"的污点分析，即追踪从 Source 到 Sink 的调用路径上，外部可控的变量是否可达、以及是否经过净化，从而判定是否存在漏洞。 但是"变量级"的污点分析存在缺陷：对于线程调用、监听回调、反射调用、动态加载等场景，SAST 分析过程容易出现"断链"问题，从而导致漏报。

此工具基于"函数级"的污点分析，即反向追溯从 Sink（漏洞函数）到 Source（外部API函数）的调用链，暂不关注污点变量，只关注函数调用关系，可有效规避上述"变量级"污点跟踪的缺陷。

但是此工具也存在缺陷："函数级"的污点追踪决定了提取到的"污点链路"中，不可避免地会存在部分外不可控的变量并无法有效传递到Sink点，从而导致误报。不过这个缺陷可以依靠当前火热的 AI 技术能力来有效解决。

## 功能

此工具当前已实现的功能有：
- 可在 Sink 配置文件中，自由拓展待检测的漏洞危险函数；
- 自动构建 Java 源代码中所有函数的互相调用关系图call graph；
- 从 Sink 点反向追溯到 Source 函数（可从配置文件的"depth"自定义追溯深度），提取调用链；
- 程序自动识别"污点传播链路"上"不包含任何参数"的函数，排除不可能存在外部可控变量的链路；
- 借助 Python javalang 三方库，自动提取每条"函数级污点链路"上所有函数的源代码，方便分析审计；
- 自动生成漏洞报告（Md和html两种格式），Html报告支持漏洞栏目导航、漏洞代码高亮、代码变量跟踪等；
- 已支持的漏洞类型包括：RCE、SSRF、SQLI、XSS、XXE、URL重定向、路径穿越、反序列化等多种类型漏洞；
- 接口多态支持：支持接口方法调用自动扩展到所有实现类；
- 继承多态支持：支持父类方法调用自动扩展到所有子类；
- AST 缓存机制：首次扫描后自动缓存 AST，更新规则后无需重新构建；
- 规则自动生成与使用：自动使用生成的规则文件，支持用户自定义修改规则；
- this 关键字支持：正确处理 `this.variable.method()` 调用模式；
- 两阶段解析机制：确保解析顺序不影响分析结果；

## 用法

基础环境：
```shell
pip install -r requirements.txt
```
运行命令：
```shell
python JavaSinkTracer.py [-h] [-p PROJECTPATH] [-r] [-f]
```
完整参数：
```powershell
λ python JavaSinkTracer.py -h

      ███████╗███████╗ ██████╗
     ██╔════╝██╔════╝██╔════╝
     ███████╗█████╗  ██║
     ╚════██║██╔══╝  ██║
     ███████║███████╗╚██████╗
     ╚══════╝╚══════╝ ╚═════╝

    Java源代码漏洞审计工具_Tr0e

usage: JavaSinkTracer.py [-h] [-p PROJECTPATH] [-r] [-f]

JavaSinkTracer

options:
  -h, --help            显示帮助信息
  -p PROJECTPATH, --projectPath PROJECTPATH
                        待扫描的项目本地路径根目录，默认值：D:/Code/Github/java-sec-code
  -r, --rebuild         强制重新构建 AST，忽略已存在的缓存文件
  -f, --force-default-rules 强制使用默认规则文件（Rules/rules.json），忽略项目中的规则文件
```

## 核心修改内容

### 1. 接口多态支持

当函数调用接口类的方法时，由于接口本身没有具体实现，工具只能记录 `调用者 -> 接口方法` 的调用关系，导致污点链路在接口处断开，无法追溯到具体实现类中的 sink 点。

解决方案：
- 添加了 `interface_implementations` 和 `class_interfaces` 字典存储接口与实现类的映射关系
- 在 `_extract_class_info` 方法中添加接口关系提取逻辑
- 在 `_build_call_graph` 方法中添加接口方法调用解析，自动扩展到所有实现类
- 添加 `resolve_actual_type` 辅助方法解析接口类型

### 2. 继承多态支持

当函数调用父类的方法时，实际运行时可能调用的是子类的重写方法。工具只能记录 `调用者 -> 父类方法` 的调用关系，无法追溯到子类重写方法中的 sink 点。

解决方案：
- 添加了 `parent_child_map` 和 `child_parent_map` 字典存储继承关系
- 在 `_build_call_graph` 方法中添加父类方法调用解析，自动扩展到所有子类

### 3. 两阶段解析机制

原始代码采用单次解析方式，解析顺序会影响最终结果。

解决方案：
- 第一阶段：收集所有类、方法、接口、继承关系，保存所有 AST 树到 `code_trees` 字典
- 第二阶段：遍历所有 AST 树构建调用关系图，此时可以利用完整的接口和继承映射信息

### 4. AST 缓存机制

每次扫描项目时都需要重新解析所有 Java 文件构建 AST，对于大型项目这个过程非常耗时。

解决方案：
- 自动生成缓存文件：`Result/{project_name}/{project_name}_ast.json`
- 新增 `-r` / `--rebuild` 参数强制重新构建 AST
- 首次扫描后自动生成缓存，更新规则后直接使用缓存

### 5. 规则自动生成与使用

用户希望修改生成的规则（如删除明知不可利用的 sink 点），以减少后续扫描的时间成本。

解决方案：
- 在项目 Result 目录下自动检测已存在的规则文件（如 `{project_name}_rule_1.json`）
- 自动选择数字最大的规则文件作为当前使用的规则
- 新生成的规则文件会自动递增数字
- 新增 `-f` / `--force-default-rules` 参数强制使用默认规则文件

### 6. this 关键字支持

当调用形式为 `this.a.b()` 时，javalang 解析后 `node.qualifier` 为 `None`，工具无法正确识别被调用对象的类型。

解决方案：
- 在 `_build_call_graph` 方法中添加对 `javalang.tree.This` 节点的专门处理
- 提取 `this.variable.method()` 模式中的变量名和方法名
- 在 `variable_symbols` 字典中查找变量的类型并构建正确的调用关系

本次修改主要解决了 Java 静态分析中的多态性问题，包括：接口多态、继承多态、解析顺序无关性、AST 缓存机制、规则自动生成与使用、容错性增强、this 关键字支持。这些改进使得 JavaSinkTracer 能够更准确地追踪污点传播路径，减少因多态导致的漏报问题，同时提升了扫描效率。

### 7. 模块化架构重构

原 `JavaSinkTracer.py` 文件（819 行）职责过于集中，不利于维护和扩展。现已拆分为独立的功能模块，统一放置在 `sinktracer/` 文件夹中。

#### 模块结构

```
sinktracer/
├── __init__.py        # 包初始化，导出所有公开接口
├── config.py          # 配置与常量模块
├── models.py          # 数据模型模块
├── rule_manager.py    # 规则管理模块
├── ast_builder.py     # AST 构建模块
├── call_graph.py      # 调用图构建模块
├── taint_analyzer.py  # 污点分析模块
├── cache_manager.py   # 缓存管理模块
└── entry_detector.py  # 入口点检测模块
```


#### 模块依赖关系

```
config.py ←────────────────────────────┐
models.py ←────────────────────────────┤
                                       │
rule_manager.py                        │
ast_builder.py ──→ call_graph.py       │
      │                                │
      └──→ cache_manager.py            │
              ↓                        │
        taint_analyzer.py ──→ entry_detector.py
              ↓                        │
        JavaSinkTracer.py ─────────────┘
              (主入口)
```



### 8. 链式调用类型推断

#### 问题描述

对于链式调用 `a().b()`，工具无法正确识别方法 `b` 所属的类型，导致错误地将 `b` 归属到当前类而非 `a()` 的返回类型。

#### 问题根源

javalang 解析链式调用时，`a()` 和 `b()` 作为两个独立的节点遍历，`b()` 的 `qualifier` 属性为 `None`，无法直接获取调用者信息。

#### 解决方案

- **AST 构建阶段**：收集所有方法的返回类型，建立 `"类名:方法名" -> 返回类型` 的映射
- **链式调用检测**：当方法调用无 `qualifier` 时，向上遍历 AST 查找是否存在父级方法调用包含当前节点，若有则从返回类型映射中获取基础类型
