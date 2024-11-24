import networkx as nx
from typing import Set


# 包含关系检查（待修改，target_set改成file_name，load一个xml文件，xml文件中放各种函数名）
def data_check(code: str, target_set) -> bool:
    for data in target_set:
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


def track_aliases(cpg: nx.MultiDiGraph, start_node: str, visited=None) -> Set[str]:
    if visited is None:
        visited = set()
    visited.add(start_node)
    if start_node in [None, '']:
        return set()
    aliases = {get_var_name(cpg, start_node)}

    for neighbor in cpg.neighbors(start_node):
        if neighbor not in visited:
            edges = cpg.get_edge_data(start_node, neighbor)
            for edge_data in edges.values():
                if edge_data['label'] in ['ALIAS', 'REACHING_DEF', 'CALL', 'REF', 'ARGUMENT', 'RETURN']:
                    aliases.update(track_aliases(cpg, neighbor, visited))
    return aliases


def find_local_var(cpg: nx.MultiDiGraph, current_node_id: str) -> str:
    local_node = ''
    if current_node_id in [None, '']:
        print('[find_local_var]: Invalid node info')
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
        print('[find_member_var]: Invalid node info')
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
        print('[are_argument_alias]: Invalid node info')
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
    # 首先根据全局变量和局部变量判断是否是同一个变量
    if are_same_local_member_var(cpg, source_node_id, target_node_id):
        return True
    # 如果是通过函数变量传递方式产生的别名也认为是同一个变量
    if are_argument_alias(cpg, source_node_id, target_node_id):
        return True
    # 如果不是同一个变量，则判断是否是别名
    source_aliases = track_aliases(cpg, source_node_id)
    # print(f"The aliases of source node {source_node_id} are {source_aliases}")
    target_aliases = track_aliases(cpg, target_node_id)
    # print(f"The aliases of target node {target_node_id} are {target_aliases}")
    intersection = source_aliases.intersection(target_aliases)
    intersection.discard(None)
    return bool(intersection)


def is_condition_structure(cpg: nx.MultiDiGraph, node_id: str) -> bool:
    if cpg.nodes[node_id].get('label', 'Unknown') == 'CONTROL_STRUCTURE':
        return True
    elif (cpg.nodes[node_id].get('label', 'Unknown') == 'CALL'
          and cpg.nodes[node_id].get('NAME', 'Unknown') == '<operator>.conditional'):
        return True
    return False


def has_condition_node_in_path(cpg: nx.MultiDiGraph, source_node: str, target_node: str) -> bool:
    for path in nx.all_simple_paths(cpg, source_node, target_node):
        for node in path:
            if is_condition_structure(cpg, node):
                return True
    return False


# 迭代获取节点node的全部前驱节点
def get_all_predecessors(cpg: nx.MultiDiGraph, node_id: str, visited: Set[str] = None) -> Set[str]:
    if visited is None:
        visited = set()

    predecessors = set(cpg.predecessors(node_id)) - visited
    visited.update(predecessors)

    for pred in predecessors:
        visited.update(get_all_predecessors(cpg, pred, visited))

    return visited


# 创建节点和对应文件的映射，对于大型图可能导致内存不足
def get_nodes_to_file(cpg: nx.MultiDiGraph) -> dict:
    nodes_to_file = {}
    for node in cpg.nodes():
        if node in nodes_to_file:
            continue
        all_predecessors = get_all_predecessors(cpg, node)
        for pred in all_predecessors:
            if 'FILENAME' in cpg.nodes[pred]:
                nodes_to_file[node] = cpg.nodes[pred].get('FILENAME')
    return nodes_to_file


# 判断node是否属于指定文件
def is_node_in_file(nodes_to_file: dict, node_id: str, file_name: str) -> bool:
    if node_id not in nodes_to_file:
        return False
    node_file = nodes_to_file[node_id]
    # print(f"node {node_id} is in file {node_file}")
    if node_file in file_name or file_name in node_file:
        return True
    return False


def get_var_name_node(cpg: nx.MultiDiGraph, node_id: str):
    node = cpg.nodes[node_id]
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
    return None, None


def is_indirect_call_equal(cpg: nx.MultiDiGraph, func_type: str, matching_nodes: list) -> str:
    res_node = ''
    is_equal = False
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
                            # print(cpg.nodes[current])
                            # TBD：改成data_check()
                            if (cpg.nodes[current].get('label', 'Unknown') == 'CALL'
                                    and cpg.nodes[current].get('METHOD_FULL_NAME', 'Unknown') in ['free', 'kfree']):
                                var_name, var_id = get_var_name_node(cpg, current)
                                # print(str(are_same_var(cpg, var_id, str(20))))
                                if var_id is not None and are_same_var(cpg, var_id, str(int(node) + 1)):
                                    print(f'Find indirect call {func_name}')
                                    is_equal = True
                                    break
                            if cpg.nodes[current].get('label', 'Unknown') == 'BINDING':
                                break
                            current = str(int(current) + 1)
        else:
            print(f"Warning! Can not find the source code of the indirect call {func_name}, "
                  f"please pay attention to following operation.")
    # elif func_type == 'malloc': 从风险的角度暂时不考虑间接的内存分配
    if is_equal:
        # print('Test func end')
        return res_node
    else:
        return ''
