import re
import networkx as nx

pre = 0
post = 1
unknown = 2


def find_method_node(cpg: nx.MultiDiGraph, node_id: str):
    # 找到包含指定节点的函数节点
    for n, attr in cpg.nodes(data=True):
        if 'label' in attr and attr['label'].startswith('METHOD'):
            # 找到该方法内的所有节点
            contained_nodes = []
            for source, target, edge_attr in cpg.edges(n, data=True):
                if edge_attr.get('label', '').strip() == 'CONTAINS':
                    contained_nodes.append(target)
                    # 递归查找更深层次包含的节点
                    to_check = [target]
                    while to_check:
                        curr = to_check.pop(0)
                        for s, t, e_attr in cpg.edges(curr, data=True):
                            if e_attr.get('label', '').strip() == 'CONTAINS':
                                contained_nodes.append(t)
                                to_check.append(t)

            if node_id in contained_nodes:
                return n
    return ''


def get_method_name(cpg: nx.MultiDiGraph, method_node: str):
    # 从METHOD节点获取函数名
    if method_node == '':
        return ''
    label = cpg.nodes[method_node].get('label', '')
    match = re.search(r'NAME="([^"]+)"', label)
    if match:
        return match.group(1)
    return ''


def find_contained_nodes(cpg: nx.MultiDiGraph, method_id: str):
    # 找到函数中包含的所有节点
    contained = set()
    to_check = [method_id]
    while to_check:
        current = to_check.pop(0)
        for s, t, attr in cpg.out_edges(current, data=True):
            if attr.get('label', '').strip() == 'CONTAINS':
                contained.add(t)
                to_check.append(t)
    return contained


def build_call_graph(cpg: nx.MultiDiGraph):
    # 构建完整的函数调用图
    call_graph = nx.DiGraph()

    # 查找所有函数定义
    methods = {}
    for n, attr in cpg.nodes(data=True):
        if 'label' in attr and attr['label'].startswith('METHOD '):
            name_match = re.search(r'NAME="([^"]+)"', attr['label'])
            if name_match and not name_match.group(1).startswith('<'):
                methods[n] = name_match.group(1)

    # 找出所有CALL边
    for method_id, method_name in methods.items():
        # 查找该方法内的所有调用
        for node_id in find_contained_nodes(cpg, method_id):
            for s, t, attr in cpg.out_edges(node_id, data=True):
                if attr.get('label', '').strip() == 'CALL':
                    target_label = cpg.nodes[t].get('label', '')
                    target_match = re.search(r'METHOD_FULL_NAME="([^"]+)"', target_label)
                    if target_match:
                        called_name = target_match.group(1)
                        if not called_name.startswith('<operator>'):
                            call_graph.add_edge(method_name, called_name)

    return call_graph


def find_common_callers(call_graph: nx.DiGraph, method1: str, method2: str):
    # 找到同时调用两个函数的函数
    callers1 = set()
    callers2 = set()

    for s, t in call_graph.edges():
        if t == method1:
            callers1.add(s)
        if t == method2:
            callers2.add(s)

    return callers1.intersection(callers2)


def determine_call_order_in_function(cpg: nx.MultiDiGraph, function_name: str, method1: str, method2: str):
    # 确定函数内调用顺序
    # 找到函数节点
    function_node = None
    for n, attr in cpg.nodes(data=True):
        if 'label' in attr and f'NAME="{function_name}"' in attr['label']:
            function_node = n
            break

    if not function_node:
        return unknown

    # 找到函数内的所有调用
    calls = []
    for node_id in find_contained_nodes(cpg, function_node):
        node_label = cpg.nodes[node_id].get('label', '')
        if 'CALL' in node_label:
            match = re.search(r'METHOD_FULL_NAME="([^"]+)".*LINE_NUMBER=(\d+)', node_label)
            if match and (match.group(1) == method1 or match.group(1) == method2):
                calls.append((int(match.group(2)), match.group(1)))

    # 按行号排序
    calls.sort(key=lambda x: x[0])

    methods_order = [call[1] for call in calls]
    if method1 in methods_order and method2 in methods_order:
        if methods_order.index(method1) < methods_order.index(method2):
            # print(f'Test, 函数{function_name}先调用{method1}再调用{method2}')
            return pre
        else:
            # print(f'Test, 函数{function_name}先调用{method2}再调用{method1}')
            return post

    return unknown


def compare_program_order(cpg: nx.MultiDiGraph, method1: str, method2: str, node1: str, node2: str):
    # 基于程序顺序（如文件位置、函数定义顺序）比较
    # 从节点标签中提取行号信息
    label1 = cpg.nodes[method1].get('label', '')
    label2 = cpg.nodes[method2].get('label', '')

    line1_match = re.search(r'LINE_NUMBER=(\d+)', label1)
    line2_match = re.search(r'LINE_NUMBER=(\d+)', label2)

    if line1_match and line2_match:
        line1 = int(line1_match.group(1))
        line2 = int(line2_match.group(1))

        if line1 < line2:
            # print(f'Test, method1 is called before method2')
            return pre
        else:
            # print(f'Test, method1 is called after method2')
            return post
    # print(f'Test, 无法确定节点{node1}和节点{node2}的执行顺序')
    return unknown


def determine_execution_order(cpg: nx.MultiDiGraph, node1: str, node2: str):
    if node1 == node2:
        return unknown
    # 确定两个节点的执行顺序
    method1 = find_method_node(cpg, node1)
    method2 = find_method_node(cpg, node2)
    # print(f'Test method1 is {method1}, method2 is {method2}')
    if method1 != '' and method2 != '' and method1 == method2:
        # 在同一函数内，使用CFG边和node id大小判断
        try:
            if nx.has_path(cpg, node1, node2) and int(node1) < int(node2):
                # print(f'Test, 节点{node1}在节点{node2}之前执行')
                return pre

            if nx.has_path(cpg, node2, node1) and int(node1) > int(node2):
                # print(f'Test, 节点{node2}在节点{node1}之前执行')
                return post
            # print(f'Test, 无法确定执行顺序，节点之间没有路径')
            return unknown
        except nx.NetworkXNoPath:
            # print(f'Test, 无法确定执行顺序，节点之间没有路径')
            return unknown
    else:
        # 在不同函数中
        method1_name = get_method_name(cpg, method1)
        method2_name = get_method_name(cpg, method2)
        if method1_name == '' or method2_name == '':
            return unknown
        # 构建完整的函数调用图
        call_graph = build_call_graph(cpg)

        # 检查函数间直接调用关系
        if nx.has_path(call_graph, method1_name, method2_name):
            # print(f'Test, 节点{node1}({method1_name})在节点{node2}({method2_name})之前执行')
            return pre
        elif nx.has_path(call_graph, method2_name, method1_name):
            # print(f'Test, 节点{node2}({method2_name})在节点{node1}({method1_name})之前执行')
            return post

        # 检查共同调用源
        common_callers = find_common_callers(call_graph, method1_name, method2_name)
        if common_callers:
            # 分析在共同调用者中的调用顺序
            for caller in common_callers:
                order = determine_call_order_in_function(cpg, caller, method1_name, method2_name)
                if order:
                    return order

        # 检查程序执行顺序（文件、行号等）
        return compare_program_order(cpg, method1, method2, node1, node2)


def analyze_nodes_order(cpg: nx.MultiDiGraph, node1: str, node2: str):
    # 分析两个节点的执行顺序
    result = determine_execution_order(cpg, node1, node2)
    return result
