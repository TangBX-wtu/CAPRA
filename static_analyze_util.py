import networkx as nx
import xml.etree.ElementTree as ET
from typing import Set, Tuple, List


# 包含关系检查
def data_check(code: str, target_list) -> bool:
    for data in target_list:
        if data in code:
            return True
    return False


def get_var_name(cpg: nx.MultiDiGraph, node_id: str):
    if node_id in [None, '']:
        return None
    node = cpg.nodes[node_id]
    if node['label'] == 'CALL':
        # 默认认为第一个参数是被释放或被分配的变量
        for n in cpg.successors(node_id):
            edges = cpg.get_edge_data(node_id, n)
            for edge_data in edges.values():
                if edge_data['label'] == 'ARGUMENT':
                    data = cpg.nodes[n]
                    if data['label'] == 'IDENTIFIER':
                        var = data['NAME']
                        return var
    return None


def find_local_global_nodes(cpg: nx.MultiDiGraph, target: str, current: str) -> List[str]:
    same_vars = []
    # 获得输入cpg的转置，方便计算别名变量
    # print(f'aaa, current is {target}')
    reverse_cpg = nx.reverse(cpg)
    for neighbor in reverse_cpg.neighbors(target):
        # print(f'bbb, neighbor is {neighbor}')
        if neighbor != current:
            edges = reverse_cpg.get_edge_data(target, neighbor)
            for edge_data in edges.values():
                if (edge_data['label'] in ['REF']
                        and cpg.nodes[neighbor].get('label', 'Unknown') == 'IDENTIFIER'):
                    same_vars.append(neighbor)
    # print(f'Test same_vars {same_vars}')
    return same_vars


def track_aliases(cpg: nx.MultiDiGraph, start_node: str, visited=None) -> Set[str]:
    if visited is None:
        visited = set()
    visited.add(start_node)
    if start_node in [None, '']:
        return set()
    # aliases = {get_var_name(cpg, start_node)}
    aliases = {start_node}
    # print(f'current node is {start_node}, visited are {visited}')
    for neighbor in cpg.neighbors(start_node):
        if neighbor not in visited:
            edges = cpg.get_edge_data(start_node, neighbor)
            for edge_data in edges.values():
                if edge_data['label'] in ['ALIAS', 'REACHING_DEF', 'CALL', 'REF', 'ARGUMENT', 'RETURN']:
                    # neighbor不能是globle类型的函数调用
                    if (cpg.nodes[neighbor].get('label', 'Unknown') == 'METHOD'
                            and cpg.nodes[neighbor].get('AST_PARENT_TYPE', 'Unknown') == 'NAMESPACE_BLOCK'
                            and cpg.nodes[neighbor].get('AST_PARENT_FULL_NAME', 'Unknown') == '<global>'):
                        continue
                    # 如果是neighbor是局部或者全局变量，则找到其他指向这个节点的，find_local_global_alias(cpg,curr,local_global)
                    # 把这些别名也放进来update
                    # if 当前neighbor是local或者global，则调用新函数，并遍历找到的局部和全局节点别名，注意对应的局部/全局不能重复
                    if cpg.nodes[neighbor].get('label', 'Unknown') in ['MEMBER', 'LOCAL']:
                        visited.add(neighbor)
                        aliases_var = find_local_global_nodes(cpg, neighbor, start_node)
                        for var in aliases_var:
                            aliases.update(track_aliases(cpg, var, visited))
                    aliases.update(track_aliases(cpg, neighbor, visited))
    return aliases


def find_local_var(cpg: nx.MultiDiGraph, current_node_id: str) -> str:
    local_node = ''
    if current_node_id in [None, '']:
        # print('[find_local_var]: Invalid node info')
        return local_node
    for neighbor in cpg.neighbors(current_node_id):
        edges = cpg.get_edge_data(current_node_id, neighbor)
        for edge_data in edges.values():
            if edge_data['label'] in ['REF']:
                # print(f"Test: current neighbor is {neighbor}")
                if cpg.nodes[neighbor].get('label', 'Unknown') == 'LOCAL':
                    return neighbor
                else:
                    local_node = find_local_var(cpg, neighbor)
                    if local_node != '':
                        return local_node
    return local_node


def find_member_var(cpg: nx.MultiDiGraph, current_node_id: str) -> str:
    member_node = ''
    if current_node_id in [None, '']:
        # print('[find_member_var]: Invalid node info')
        return member_node
    for neighbor in cpg.neighbors(current_node_id):
        edges = cpg.get_edge_data(current_node_id, neighbor)
        for edge_data in edges.values():
            if edge_data['label'] in ['REF']:
                # print(f"Test: current neighbor is {neighbor}")
                if cpg.nodes[neighbor].get('label', 'Unknown') == 'MEMBER':
                    return neighbor
                else:
                    member_node = find_member_var(cpg, neighbor)
                    if member_node != '':
                        return member_node
    return member_node


# 判断两个变量是否指向同一个局部变量或全局变量
def are_same_local_member_var(cpg: nx.MultiDiGraph, source_node_id: str, target_node_id: str) -> bool:
    local_source = find_local_var(cpg, source_node_id)
    local_target = find_local_var(cpg, target_node_id)
    if local_source != '' and local_target != '' and local_source == local_target:
        # print(f"Test, var_node {source_node_id} and var_node {target_node_id} are same local var")
        return True

    member_source = find_member_var(cpg, source_node_id)
    member_target = find_member_var(cpg, target_node_id)
    if member_source != '' and member_target != '' and member_source == member_target:
        # print(f"Test, var_node {source_node_id} and var_node {target_node_id} are same member var")
        return True
    return False


def has_path_of_type(cpg: nx.MultiDiGraph, source_node_id: str, target_node_id: str, edge_type: list) -> bool:
    # 创建一个只有数据流的子图，注意，这里会消耗比较大的内存
    data_flow_edges = [(u, v) for (u, v, d) in cpg.edges(data=True) if d['label'] in edge_type]
    subgraph = nx.MultiDiGraph(data_flow_edges)
    if nx.has_path(subgraph, source_node_id, target_node_id):
        # print(f'Test, has path from {source_node_id} to {target_node_id} in subgraph')
        return True
    else:
        return False


# 间接函数调用场景中，判断函数内被操作变量是否与函数入参等价
def are_argument_alias(cpg: nx.MultiDiGraph, source_node_id: str, argument_node_id: str) -> bool:
    if source_node_id in [None, ''] or argument_node_id in [None, '']:
        # print('[are_argument_alias]: Invalid node info')
        return False
    source_var_refs = []
    argument_var_refs = []
    for neighbor in cpg.neighbors(source_node_id):
        # 找到被操作变量的引用，所以是REF边后继节点
        edges = cpg.get_edge_data(source_node_id, neighbor)
        for edge_data in edges.values():
            if edge_data['label'] == 'REF':
                # 如果是直接使用没有用别名，那么被释放的变量的ref就是argement
                if neighbor == argument_node_id:
                    return True
                source_var_refs.append(neighbor)
    # print(f'Test, node {source_node_id} source_var_refs are {source_var_refs}')
    # argument_predecessors = list(cpg.predecessors(argument_node_id))
    for neighbor in cpg.predecessors(argument_node_id):
        # 找到入参在函数内的引用，因此是入参节点的REF前驱节点
        edges = cpg.get_edge_data(neighbor, argument_node_id)
        for edge_data in edges.values():
            if edge_data['label'] == 'REF':
                argument_var_refs.append(neighbor)
    # print(f'Test, node {argument_node_id} argument_var_refs are {argument_var_refs}')
    for argument in argument_var_refs:
        for source in source_var_refs:
            return has_path_of_type(cpg, argument, source, ['REACHING_DEF', 'REF'])
    return False


def are_same_var(cpg: nx.MultiDiGraph, source_node_id: str, target_node_id: str) -> bool:
    # print(f"{source_node_id} {target_node_id}")
    if source_node_id == target_node_id:
        return True
    # 首先根据全局变量和局部变量判断是否是同一个变量
    if are_same_local_member_var(cpg, source_node_id, target_node_id):
        # print(f"{source_node_id} and {target_node_id} are same local mamber var")
        return True
    # 如果是通过函数变量传递方式产生的别名也认为是同一个变量
    if are_argument_alias(cpg, source_node_id, target_node_id):
        # print(f"{source_node_id} and {target_node_id} are same argument alias")
        return True
    # 如果不是同一个变量，则判断是否是别名
    source_aliases = track_aliases(cpg, source_node_id)
    # print(f"Test, the aliases of source node {source_node_id} are {source_aliases}")
    target_aliases = track_aliases(cpg, target_node_id)
    # print(f"Test, the aliases of target node {target_node_id} are {target_aliases}")
    intersection = source_aliases.intersection(target_aliases)
    intersection.discard(None)
    # print(f"Test intersection is {intersection}")
    # print(f'Test {nx.has_path(cpg, source_node_id, target_node_id)}')
    return bool(intersection)


def is_condition_structure(cpg: nx.MultiDiGraph, node_id: str) -> bool:
    if cpg.nodes[node_id].get('label', 'Unknown') == 'CONTROL_STRUCTURE':
        return True
    elif (cpg.nodes[node_id].get('label', 'Unknown') == 'CALL'
          and cpg.nodes[node_id].get('NAME', 'Unknown') == '<operator>.conditional'):
        return True
    return False


def has_condition_node_in_path(cpg: nx.MultiDiGraph, source_node: str, target_node: str) -> bool:
    for path in nx.all_simple_paths(cpg, source_node, target_node, cutoff=10):
        for node in path:
            if is_condition_structure(cpg, node):
                return True
    return False


# 创建节点和对应文件的映射，对于大型图可能导致内存不足
def get_nodes_to_file(cpg: nx.MultiDiGraph) -> dict:
    nodes_to_file = {}
    for node in cpg.nodes():
        if node in nodes_to_file:
            continue
        if 'FILENAME' in cpg.nodes[node]:
            nodes_to_file[node] = cpg.nodes[node].get('FILENAME')
            continue

        # 通过BFS搜索最近的FILENAME节点
        queue = [node]
        visited = {node}
        while queue:
            current_node = queue.pop(0)
            for neighbor in list(cpg.predecessors(current_node)) + list(cpg.successors(current_node)):
                if neighbor not in visited:
                    visited.add(neighbor)
                    if 'FILENAME' in cpg.nodes[neighbor]:
                        nodes_to_file[node] = cpg.nodes[neighbor].get('FILENAME')
                        break
                    queue.append(neighbor)
        # 如果当前节点没有找到对应filename，则赋值空
        if node not in nodes_to_file:
            nodes_to_file[node] = '<empty>'

    return nodes_to_file


# 判断node是否属于指定文件
def is_node_in_file(nodes_to_file: dict, node_id: str, file_name: str) -> bool:
    if node_id not in nodes_to_file:
        print(f"Node id {node_id} not in nodes_to_file")
        return False
    # print(f"Test nodes_to_file is {nodes_to_file}")
    node_file = nodes_to_file[node_id]
    # print(f"node {node_id} is in file {node_file}")
    # print(f"Test node_file is {node_file}, file name is {file_name}")
    if node_file in file_name or file_name in node_file:
        return True
    return False


def get_var_name_node(cpg: nx.MultiDiGraph, node_id: str):
    node = cpg.nodes[node_id]
    # print(f'Test, get_var_name_node node is {node}')
    if node['label'] == 'CALL':
        # 默认认为第一个参数是被操作的变量
        for n in cpg.successors(node_id):
            edges = cpg.get_edge_data(node_id, n)
            for edge_data in edges.values():
                if edge_data['label'] == 'ARGUMENT':
                    data = cpg.nodes[n]
                    if data['label'] == 'IDENTIFIER':
                        var = data['NAME']
                        return var, n
                    elif data['label'] == 'CALL':
                        return get_var_name_node(cpg, n)
    return '', ''


def is_indirect_call_equal(cpg: nx.MultiDiGraph, func_type: str, matching_nodes: list) -> str:
    res_node = ''
    is_equal = False
    max_node = int(len(cpg.nodes)) + 1
    if func_type == 'release':
        # 如果是函数调用，则找到这个函数的内部，然后确认是否有一个入参（当前我们只考虑一个情况，类似Hypo的figure 7）
        # 找到函数定义在cpg中的位置，找到对应入参的node，然后分析后面路径上是否被释放，如果被释放则认为这个间接调用也是释放
        # 如果间接调用的函数找不到，这里打印告警，说明这里有变量操作，但是cpg中没有代码，存在分析不全的风险，请人工关注变量的使用
        func_name = ''
        for node, data in matching_nodes:
            if (data.get('label', 'Unknown') == 'CALL'
                    and 'METHOD_FULL_NAME' in data
                    and '<operator>' not in data.get('METHOD_FULL_NAME', 'Unknown')):
                func_name = data.get('METHOD_FULL_NAME', 'Unknown')
                # print(f"Test, indirect func_name is {func_name}, node data is {data}")
                res_node = node
                break
        if func_name != '':
            for node, data in cpg.nodes(data=True):
                if data.get('label', 'Unknown') == 'METHOD' and data.get('FULL_NAME', 'Unknown') == func_name:
                    # 当前释放场景之考虑一个参数的情况，根据统计结果看这种情况占多数
                    # print(f'Test, find node of {func_name}')
                    if (cpg.nodes[str(int(node) + 1)].get('label', 'Unknown') == 'METHOD_PARAMETER_IN'
                            and cpg.nodes[str(int(node) + 2)].get('label', 'Unknown') == 'BLOCK'):
                        # 遍历block中的节点，判断是否有free操作（不考虑嵌套超过2层的情况），node线性增长直到碰到BINDING
                        # print(f'Test, find source code of {func_name}')
                        current = str(int(node) + 3)
                        while True:
                            # print(f"Test {cpg.nodes[current]}")
                            # TBD：改成data_check()
                            if (cpg.nodes[current].get('label', 'Unknown') == 'CALL'
                                    and cpg.nodes[current].get('METHOD_FULL_NAME', 'Unknown') in ['free', 'kfree', 'put_device']):
                                var_name, var_id = get_var_name_node(cpg, current)
                                # print(str(are_same_var(cpg, var_id, str(20))))
                                if var_id != '' and are_same_var(cpg, var_id, str(int(node) + 1)):
                                    print(f'Find indirect call {func_name}')
                                    is_equal = True
                                    break
                            if cpg.nodes[current].get('label', 'Unknown') == 'BINDING' or int(current) + 1 >= max_node:
                                break
                            current = str(int(current) + 1)
        else:
            print(f"Warning! Can not find the source code of the indirect call {func_name}, "
                  f"please pay attention to following operation.")
    # elif func_type == 'malloc': 从风险的角度暂时不考虑间接的内存分配
    if is_equal:
        return res_node
    else:
        return ''


def is_memory_operation(cpg: nx.MultiDiGraph, node_id: str, memory_operation: list) -> bool:
    node_type = cpg.nodes[node_id].get('label', 'Unknown')
    node_name = cpg.nodes[node_id].get('NAME', 'Unknown')
    node_code = cpg.nodes[node_id].get('CODE', 'Unknown')
    if node_type in ['CALL', 'IDENTIFIER']:
        # 检查是否是内存操作函数（不考虑内存的重新分配）
        if node_type == 'CALL':
            # 直接内存操作函数
            if node_name in memory_operation:
                return True
            # 间接函数操作中包含了入参，这里产生误报的概率很高，但是可以作为一种提示
            next_node_type = cpg.nodes[str(int(node_id) + 1)].get('label', 'Unknown')
            if next_node_type == 'IDENTIFIER':
                return True
        # 判读是否是指针操作
        if '*' in node_code or '->' in node_code:
            return True
        # 判断是否是地址操作
        if '&' in node_code:
            return True
        # 判断是否是数组操作
        if '[' in node_code and ']' in node_code:
            return True
        # 调用函数是否为内存相关操作
        post_node = str(int(node_id) - 1)
        if (cpg.has_node(post_node) and cpg.nodes[post_node].get('label', 'Unknown') == 'CALL'
                and cpg.nodes[post_node].get('NAME', 'Unknown') in memory_operation):
            return True
    # 判断相邻节点是否有内存相关操作
    for neighbor in cpg.neighbors(node_id):
        if (cpg.nodes[neighbor].get('label', 'Unknown') == 'MEMBER'
                and cpg.nodes[neighbor].get('TYPE_FULL_NAME', 'Unknown').endswith('*')):
            # print("Test 6")
            return True
    return False


def get_var_operation_node(cpg: nx.MultiDiGraph, matching_nodes: list, memory_operation: list):
    node_id = ''
    var_name = ''
    for node, data in matching_nodes:
        if is_memory_operation(cpg, node, memory_operation):
            var_name, node_id = get_var_name_node(cpg, node)
            if var_name != '' and node_id != '':
                return node_id, var_name
    return node_id, var_name


def memory_func_init(xml_path: str) -> Tuple[list, list, list]:
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()

        # 获取所有内存分配函数名
        allocation_funcs = []
        for alloc in root.findall(".//allocation/function"):
            allocation_funcs.append(alloc.text.strip())

        # 获取所有内存释放函数名
        deallocation_funcs = []
        for dealloc in root.findall(".//deallocation/function"):
            deallocation_funcs.append(dealloc.text.strip())

        # 获取内存操作相关函数名
        memory_operations = []
        for oper in root.findall(".//memory/operation"):
            memory_operations.append(oper.text.strip())

        return allocation_funcs, deallocation_funcs, memory_operations

    except FileNotFoundError:
        raise FileNotFoundError(f"Can not find xml file: {xml_path}")
    except ET.ParseError:
        raise ET.ParseError(f"File error: {xml_path}")