import re
import networkx as nx

from static_analyze_util import get_all_nodes_in_method

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
                    '''
                    # 递归查找更深层次包含的节点
                    to_check = [target]
                    while to_check:
                        curr = to_check.pop(0)
                        for s, t, e_attr in cpg.edges(curr, data=True):
                            if e_attr.get('label', '').strip() == 'CONTAINS':
                                contained_nodes.append(t)
                                to_check.append(t)
                    '''
            if node_id in contained_nodes:
                return n
    return ''


def get_method_name(cpg: nx.MultiDiGraph, method_node: str):
    # 从METHOD节点获取函数名
    if method_node == '':
        return ''
    name = cpg.nodes[method_node].get('NAME', '')
    # print(f'Test name is {name}')
    return name


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

def find_caller(cpg: nx.MultiDiGraph, method_id: str):
    call_nodes = set()
    if cpg.has_node(method_id):
        for s in cpg.predecessors(method_id):
            edge_data = cpg.get_edge_data(s, method_id)
            for key, attr in edge_data.items():
                if 'label' in attr and attr['label'] == 'CALL':
                    call_nodes.add(s)
    return call_nodes

def find_caller_path(cpg: nx.MultiDiGraph, method_id: str, caller_path: list):
    if len(caller_path) == 0:
        caller_path.append(method_id)
    caller_nodes = find_caller(cpg, method_id)
    for node in caller_nodes:
        if caller_path[0] != method_id:
            caller_path.insert(0, method_id)
        caller_path.insert(0, node)
        caller_method_id = find_method_node(cpg, node)
        caller_path.insert(0, caller_method_id)
        find_caller_path(cpg, caller_method_id, caller_path)


def is_in_caller_path(caller_paths: list, caller_id: str):
    for curr in caller_paths:
        if curr == caller_id:

            return True
    return False

def find_common_callers(path1: list, path2: list):
    res = set()
    for caller_1 in path1:
        for caller_2 in path2:
            if caller_1 == caller_2:
                res.add(caller_1)
    return res


def determine_call_order_in_function(callers: set, path1: list, path2: list):
    for caller in callers:
        method1_matches = [(index, item) for index, item in enumerate(path1) if item == caller]
        method2_matches = [(index, item) for index, item in enumerate(path2) if item == caller]
        method1_caller_location = []
        method2_caller_location = []

        for index, item in method1_matches:
            caller_location_index = index + 1
            if caller_location_index < len(path1):
                caller_location_id = path1[caller_location_index]
                method1_caller_location.append(int(caller_location_id))
        for index, item in method2_matches:
            caller_location_index = index + 1
            if caller_location_index < len(path2):
                caller_location_id = path2[caller_location_index]
                method2_caller_location.append(int(caller_location_id))

        method1_caller_location.sort()
        method2_caller_location.sort()
        if method1_caller_location[0] < method2_caller_location[0]:
            return pre
        elif method1_caller_location[0] > method2_caller_location[0]:
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

def determine_call_order(cpg: nx.MultiDiGraph, callee: str, caller: str, node: str):
    contain_nodes = get_all_nodes_in_method(cpg, caller)
    callers_id = find_caller(cpg, callee)
    for caller_id in callers_id:
        if caller_id in contain_nodes:
            if int(node) > int(caller_id):
                # 注意，这里的pre和post指的是被调用函数在调用函数内部与目标节点的顺序
                return post
            else:
                # 被调用函数在调用函数的内部中，处于被比较节点之前
                return pre
        # 如果存在跨级调用，则找到上一级
        else:
            method_node = find_method_node(cpg, caller_id)
            return determine_call_order(cpg, method_node, caller, node)
    return

def determine_execution_order(cpg: nx.MultiDiGraph, node1: str, node2: str):
    if node1 == node2:
        return unknown
    # 确定两个节点的执行顺序
    method1 = find_method_node(cpg, node1)
    method2 = find_method_node(cpg, node2)
    # print(f'Test method1 of {node1} is {method1}, method2 of {node2} is {method2}')
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
        # print(f'Test method1_name of {node1} is {method1_name}, method2_name of {node2} is {method2_name}')
        if method1_name == '' or method2_name == '':
            return unknown
        # 向前遍历找到每个函数的函数级调用链
        method1_caller_paths = list()
        find_caller_path(cpg, method1, method1_caller_paths)
        method2_caller_paths = list()
        # 函数级的调用关系，不在一个函数内比较时可能出现错误
        find_caller_path(cpg, method2, method2_caller_paths)
        # print(f'Test, method1 caller path is {method1_caller_paths}')
        # print(f'Test, method2 caller path is {method2_caller_paths}')
        if is_in_caller_path(method1_caller_paths, method2):
            # method1在method2之后被执行
            res = determine_call_order(cpg, method1, method2, node2)
            if res == pre:
                return post
            elif res == post:
                return pre
            return unknown

        if is_in_caller_path(method2_caller_paths, method1):
            # method1在method2之前被执行
            res = determine_call_order(cpg, method2, method1, node1)
            if res == pre:
                return pre
            elif res == post:
                return post
            return unknown

        # 检查共同调用源
        common_callers = find_common_callers(method1_caller_paths, method2_caller_paths)
        if len(common_callers) != 0:
            order = determine_call_order_in_function(common_callers, method1_caller_paths, method2_caller_paths)
            return order

        # 检查程序执行顺序（文件、行号等）
        return compare_program_order(cpg, method1, method2, node1, node2)


def analyze_nodes_order(cpg: nx.MultiDiGraph, node1: str, node2: str):
    # 分析两个节点的执行顺序
    result = determine_execution_order(cpg, node1, node2)
    return result
