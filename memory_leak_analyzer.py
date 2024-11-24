import networkx as nx
import unidiff
from typing import Dict, Set, Tuple

from static_analyze_util import data_check, are_same_var, has_condition_node_in_path, is_indirect_call_equal


class MemoryLeakAnalyzer:
    def __init__(self, cpg: nx.MultiDiGraph):
        self.cpg = cpg
        self.allocations: Dict[str, Set[str]] = {}  # 变量到分配点的映射
        self.de_allocations: Dict[str, Set[str]] = {}  # 变量到释放点的映射

    def analyze_potential_leak(self, matching_nodes: list, line: unidiff.patch.Line, file_type: str) -> Tuple[
        bool, str]:
        # file type是source，则是删除了释放场景，分析free/delete；如果是target，则是添加场景，要分析malloc/new，还有一些间接内存创建
        if file_type == 'source':
            # 获取删除数据中包含free的node，以及包含的变量名称，认为是潜在泄漏点
            node, var = self.get_free_node(matching_nodes)
            if not var:
                return False, "No var in matching nodes."
            print(f"Node id is {node}, and var name is {var}")

            # 查找变量的所有分配点，包括malloc/new，注意，这里可能存在通过调用其他函数实现的间接分配
            allocation_nodes = self.find_all_allocations(var, node, file_type)
            de_allocation_nodes = self.find_de_allocations(var, node)

            # 1）如果被删除的var没有其他内存分配的位置，则需要进行告警，存在内存泄漏风险
            if not de_allocation_nodes:
                # print(f"Can not find allocation nodes for var={var}")
                res = f"Removing line {line.source_line_no}: '{line.value.strip()}' has potential memory leak risk!"
                if allocation_nodes:
                    tmp_str = "The allocated memory in line { "
                    for n in allocation_nodes:
                        tmp_str = tmp_str + str(self.cpg.nodes[n].get('LINE_NUMBER', 'Unknown')) + " "
                    tmp_str = tmp_str + "} may leak."
                    res = res + f" {tmp_str}"
                return True, res
            # 2）如果有内存分配点，且有其他内存释放点，则需要计算之间是否存在通路，即内存分配的变量是否与内存释放的变量是同一个变量（考虑别名）
            if allocation_nodes:
                risk_nodes = self.has_path_between_source_target(allocation_nodes, de_allocation_nodes)
                if not risk_nodes:
                    return False, f"Removing line {line.source_line_no} is safe"
                else:
                    tmp_str = "{"
                    for risk_node in risk_nodes:
                        # 根据node找到行号
                        tmp_str = tmp_str + self.get_line_no_by_node(risk_node)
                    tmp_str = tmp_str + "}"
                    res = (f"Removing line {line.source_line_no}: '{line.value.strip()}' has potential "
                           f"memory leak risk! Please pay attention to line {tmp_str}")
                    return True, res
            else:
                # 3) 如果有释放位置，但是没有分配位置，则认为没有风险
                return False, f"Removing line {line.source_line_no} has no memory leak risk."
        elif file_type == 'target':
            # target对应添加场景，要分析malloc/calloc/realloc/new(c++)，还有一些间接内存创建
            node, var = self.get_alloc_node(matching_nodes)
            if not var:
                return False, "No var in matching nodes."
            # print(f"Node id is {node}, and var name is {var}")

            allocation_nodes = self.find_all_allocations(var, node, file_type)
            de_allocation_nodes = self.find_de_allocations(var, node)

            if not de_allocation_nodes:
                res = (f"Adding line {line.target_line_no}: '{line.value.strip()}' has potential memory leak risk! "
                       f"Unable to find the corresponding memory deallocation operation for the variable in the file")
                return True, res
            else:
                risk_nodes = self.has_path_between_source_target(allocation_nodes, de_allocation_nodes)
                if not risk_nodes:
                    return False, f"Adding line {line.target_line_no} has no memory leak risk."
                else:
                    res = (f"Adding line {line.target_line_no}: '{line.value.strip()}' has potential memory leak risk! "
                           f"Ensure that the corresponding memory release operation exists in the program")
                    return True, res
        return False, "Can not find potential memory leak risk for current committed line"

    def get_line_no_by_node(self, node_id: str) -> str:
        line_no = self.cpg.nodes[node_id].get('LINE_NUMBER', 'Unknown')
        return line_no

    def get_free_node(self, matching_nodes: list) -> tuple[str, str]:
        node_id = ''
        var_name = ''
        if not matching_nodes:
            print("The matching node is NULL")
        else:
            for node, data in matching_nodes:
                # 直接场景，找到free/delete的函数调用
                # TBD:改成data_check()
                if (data['label'] == 'CALL'
                        and (data['METHOD_FULL_NAME'] == 'free'
                             or data['METHOD_FULL_NAME'] == 'delete')):
                    var_name, node_id = self.get_var_name_node(node)
                    return node_id, var_name
            func_node = is_indirect_call_equal(self.cpg, 'release', matching_nodes)
            if func_node != '':
                # 如果是间接操作，且函数的入参在函数内被释放
                var_name, node_id = self.get_var_name_node(func_node)
        return node_id, var_name

    def get_alloc_node(self, matching_nodes: list) -> tuple[str, str]:
        node_id = ''
        var_name = ''
        if not matching_nodes:
            print("The matching node is NULL")
        else:
            alloc_methods = ['malloc', 'calloc', 'realloc', 'new']
            for node, data in matching_nodes:
                # 直接场景，找到malloc/calloc/realloc的函数调用
                # TBD:改file_name
                if (data['label'] == 'CALL'
                        and ('CODE' in data) and (data_check(data['CODE'], alloc_methods)
                                                  and data['METHOD_FULL_NAME'] == '<operator>.assignment')):
                    var_name, var_id = self.get_var_name_node(node)
                    node_id = var_id
        return node_id, var_name

    # 获取对应node_id的赋值变量和node
    def get_var_name_node(self, node_id):
        node = self.cpg.nodes[node_id]
        if node['label'] == 'CALL':
            # 默认认为第一个参数是被释放或被分配的变量
            for n in self.cpg.successors(node_id):
                edges = self.cpg.get_edge_data(node_id, n)
                for edge_data in edges.values():
                    if edge_data['label'] == 'ARGUMENT':
                        data = self.cpg.nodes[n]
                        if data['label'] == 'IDENTIFIER':
                            var = data['NAME']
                            return var, n
        return None, None

    # 找到图中所有内存分配的位置和潜在位置
    def find_all_allocations(self, var: str, node_id: str, file_type: str) -> Set[str]:
        allocation_nodes = set()
        allocation_functions = []
        # 当file_type为target时，则表示对新增的内存分配场景进行分析，而内存动态分配后只能通过realloc进行扩展
        # TBD：改成两个file
        if file_type == "source":
            allocation_functions = ['malloc', 'calloc', 'realloc']
        elif file_type == "target":
            allocation_functions = ['realloc']
        # 注意：如果考虑通过外部函数调用间接分配内存场景，则会增加误报率，降低漏报率，需要根据实际场景选择
        allocation_assigns = [var + '=', var + ' =']

        # 找到分配内存操作的根节点（line）
        for node, data in self.cpg.nodes(data=True):
            # 直接内存分配场景，比较内存分配函数
            # TBD：改成file_name
            if ('CODE' in data) and (data_check(data['CODE'], allocation_functions)
                                     and data['label'] == 'CALL'
                                     and data['METHOD_FULL_NAME'] == '<operator>.assignment'):
                # 进行数据流通路判断，检测是否为同一个内存地址
                var_name, var_node = self.get_var_name_node(node)
                if var_node is not None and var_node is not None and are_same_var(self.cpg, var_node, node_id):
                    # print(f"Test1: node {var_node} and node {node_id} ara same")
                    allocation_nodes.add(var_node)
            # 间接内存分配场景，调用其他函数封装内存分配函数对待分析变量进行赋值
            elif ('CODE' in data) and (data['CODE'] in allocation_assigns
                                       and data['label'] == 'CALL'
                                       and data['METHOD_FULL_NAME'] == '<operator>.assignment'):
                # 进行数据流通路判断，检测是否为同一个内存地址
                var_name, var_node = self.get_var_name_node(node)
                if var_node is not None and var_node is not None and are_same_var(self.cpg, var_node, node_id):
                    # print(f"Test2: node {var_node} and node {node_id} ara same")
                    allocation_nodes.add(var_node)
        return allocation_nodes

    def find_de_allocations(self, var: str, node_id: str) -> Set[str]:
        de_allocation_nodes = set()
        de_allocation_functions = ['free', 'delete', 'kfree']
        # 找到释放内存操作的根节点（line）
        for node, data in self.cpg.nodes(data=True):
            # 直接内存释放场景，比较内存释放函数
            # TDB: 改成data_check
            if ('CODE' in data) and (data_check(data['CODE'], de_allocation_functions)
                                     and data['label'] == 'CALL'
                                     and data['METHOD_FULL_NAME'] in de_allocation_functions):
                # 需要去掉被删除的节点，然后再判断是否是同一个变量
                # 计算被释放的变量节点
                var_name, var_node = self.get_var_name_node(node)
                if (var_node is not None and var_node is not None and
                        not var_node == node_id and are_same_var(self.cpg, var_node, node_id)):
                    # print(f"Test3: node {var_node} and node {node_id} ara same")
                    de_allocation_nodes.add(var_node)
            # 降低漏报场景，不考虑间接释放
        return de_allocation_nodes

    # 计算内存分配点与内存释放点之间是否存在通路
    def has_path_between_source_target(self, allocation_nodes: set, de_allocation_nodes: set) -> set:
        # 查找分配节点和释放节点时已经计算了被操作的变量是同一个，这里通过通路计算分配和释放之间是否存在通路，且通路中不存在条件控制节点
        last_source_nodes = set()
        # 1）从cpg中抽取数据流与控制流相关的子图,主要针对数据流，不要POST_DOMINATE边，会出现错误,CFG和DOMINATE的边加入导致通路增加
        edge_type = ['CALL', 'ARGUMENT', 'RETURN', 'REACHING_DEF', 'AST']
        data_flow_edges = [(u, v) for (u, v, d) in self.cpg.edges(data=True) if d['label'] in edge_type]
        # 2）创建一个精简图
        data_flow_graph = nx.MultiDiGraph(data_flow_edges)
        visited = set()
        for allocation_node in allocation_nodes:
            has_path = False
            for de_allocation_node in de_allocation_nodes:
                try:
                    # path = nx.shortest_path(data_flow_graph, allocation_node, de_allocation_node)
                    # print(f"Path from {allocation_node} to {de_allocation_node} is {path}")
                    if (nx.has_path(data_flow_graph, allocation_node, de_allocation_node) and
                            not has_condition_node_in_path(self.cpg, allocation_node, de_allocation_node) and
                            (de_allocation_node not in visited)):
                        has_path = True
                        visited.add(de_allocation_node)
                        break
                except nx.NetworkXNoPath:
                    print(f"There is no path from {allocation_node} to {de_allocation_node}")
            if not has_path:
                last_source_nodes.add(allocation_node)
        return last_source_nodes
