import networkx as nx
import unidiff
from typing import Tuple, Set
from static_analyze_util import data_check, are_same_var, is_condition_structure, has_condition_node_in_path, \
    is_indirect_call_equal


class UseAfterFreeAnalyzer:
    UAF_VUL = 0
    NULL_POINT_VUL = 1
    UAF_RISK = 2
    SAFE = 3

    def __init__(self, cpg: nx.MultiDiGraph):
        self.cpg = cpg
        edge_type = ['CALL', 'ARGUMENT', 'RETURN', 'REACHING_DEF', 'AST']
        data_flow_edges = [(u, v) for (u, v, d) in self.cpg.edges(data=True) if d['label'] in edge_type]
        self.light_cpg = nx.MultiDiGraph(data_flow_edges)

    def analyze_potential_uaf(self, matching_nodes: list, line: unidiff.patch.Line, file_type: str) -> Tuple[
        bool, str]:
        # target场景分析内存释放和内存访问操作；source场景分析删除赋值NULL操作

        if file_type == "target":
            # print("UAF Test target")
            # 针对添加代码场景，分析内存释放操作和变量的使用操作
            node, var = self.get_free_node(matching_nodes)
            # 如果是free节点，则分析变量的后续使用情况
            if var != '' and node != '':
                # 在cpg中查找变量var是否还在继续使用
                uses = self.get_var_use_path(node, var, self.light_cpg)
                if len(uses) == 0:
                    # print("Test: use len is 0")
                    res, res_str = self.result_format(self.UAF_RISK, file_type, line, var)
                    return res, res_str
                else:
                    # 需要在uses中找到var = NULL的赋值语句，且是首句
                    # print(f"Test: use path is: {uses}")
                    res_no = self.check_use_after_free_by_path(uses, node)
                    res, res_str = self.result_format(res_no, file_type, line, var)
                    return res, res_str
            # 如果是变量内存操作节点，则分析该变量是否在之前被free
            node, var = self.get_var_operation_node(matching_nodes)
            # print(f"Test use var name is {var}")
            # 反向遍历变量是否被free过：找到全局对应上述变量的free，看看是否有通路
            # 如果找到free的节点，则计算他们的通路，并在通路之间查看是否有赋值为NULL的节点 G.reverse()
            if var != '' and node != '':
                de_allocations = self.find_de_allocations(var, node)
                if len(de_allocations) != 0:
                    # print(f"Test, free nodes are {de_allocations}")
                    all_assign_null_nodes = self.get_all_assign_null_node(self.cpg, node)
                    # 检测free节点和var节点之间是否有通路，通路中是否设置了NULL
                    for de_allocation in de_allocations:
                        # find_de_allocations中已经计算过变量的一致性/别名，所以这里的通路需要用包含控制流的cpg
                        res_no = self.check_use_after_free_by_var(self.cpg, all_assign_null_nodes, de_allocation, node)
                        res, res_str = self.result_format(res_no, file_type, line, var)
                        return res, res_str
                else:
                    print("Cannot find memory free nodes in this CPG")
        else:
            # print("UAF Test source")
            # 1.检查删除line中是否是清理赋值NULL
            # 2.若删除了var = NULL操作，则看变量后续是否还有使用，如果没有操作则可能存在UAF风险（也可能是把整个var使用都删除，这个时候留给审核者），如果后面还有同变量内存相关操作，则是空指针
            node, var = self.get_remove_assign_null(matching_nodes)
            if node != '' and var != '':
                # print(f"remove assign null node is {node}, and var name is {var}")
                uses = self.get_var_use_path(node, var, self.light_cpg)
                # 因为是删除操作，所以需要在use path中删除当前赋值NULL的节点，也就是matching nodes
                uses = self.uses_path_clear(matching_nodes, uses)
                if len(uses) == 0:
                    # 删除了var == NULL，且后续没有操作，则可能未来引入UAF的风险
                    res, res_str = self.result_format(self.UAF_RISK, file_type, line, var)
                    return res, res_str
                else:
                    res_no = self.check_use_after_free_by_path(uses, node)
                    res, res_str = self.result_format(res_no, file_type, line, var)
                    return res, res_str
        return False, "Can not find potential use-after-free risk for current committed line"

    def uses_path_clear(self, matching_nodes: list, uses_path: list) -> list:
        for node, data in matching_nodes:
            if node in uses_path:
                uses_path.remove(node)
        return uses_path

    def get_remove_assign_null(self, matching_nodes: list) -> tuple[str, str]:
        node = ''
        var = ''
        for node_id, data in matching_nodes:
            var_name, var_node = self.get_var_name_node(node_id)
            if var_node is not None and var_name is not None and self.is_assign_null(node_id, var_node):
                node = var_node
                var = var_name
        return node, var

    def get_all_assign_null_node(self, cpg: nx.MultiDiGraph, target_node) -> set:
        nodes = set()
        for node in cpg.nodes:
            if self.is_assign_null(node, target_node):
                nodes.add(node)
        return nodes

    def check_use_after_free_by_var(self, cpg: nx.MultiDiGraph, assign_null_nodes: set,
                                    de_allocation: str, target_node: str) -> int:
        # 找到的free节点已经计算过操作的变量是同一个变量或别名，所以如果发现存在path则就有可能存在uaf风险
        reverse_cpg = cpg.reverse(copy=True)
        # 通过反向图来判断内存释放操作与制定变量存在关系
        if nx.has_path(reverse_cpg, de_allocation, target_node):
            # 遍历NULL赋值节点是否是在内存释放之后进行
            for node in assign_null_nodes:
                if nx.has_path(cpg, de_allocation, node) and not has_condition_node_in_path(cpg, de_allocation, node):
                    if nx.has_path(cpg, node, target_node):
                        print(f"Find assignment to NULL {node} after free")
                        # 内存释放节点和内存操作节点之间如果存在赋值NULL，则可能存在空指针漏洞
                        return self.NULL_POINT_VUL
            # 内存释放节点和内存操作节点之间如果存在通路，但是又没有将指针设置为NULL，则存在UAF漏洞
            return self.UAF_VUL
        else:
            # free和添加的变量内存操作没有通路，则说明没有UAF缺陷，我们研究的前提假设是base代码是安全的，所以默认之前的free后已经对变量进行了NULL赋值
            # 所以这里不再进一步对free节点的UAF risk进行分析
            return self.SAFE

    def result_format(self, res_no: int, file_type: str, line: unidiff.patch.Line, var_name: str) -> tuple[bool, str]:
        result_str = ''
        result_bool = False
        if file_type == 'target':
            if res_no == self.UAF_VUL:
                result_str = (
                    f"Adding line {line.target_line_no}: '{line.value.strip()}' may lead to a UAF vulnerability "
                    f"where variable {var_name} is still used after memory is freed.")
                result_bool = True
            elif res_no == self.NULL_POINT_VUL:
                result_str = (
                    f"Adding line {line.target_line_no}: '{line.value.strip()}' may lead to a NULL point vulnerability "
                    f"where variable {var_name} is still used after being assigned NULL.")
                result_bool = True
            elif res_no == self.UAF_RISK:
                result_str = (
                    f"Adding line {line.target_line_no}: '{line.value.strip()}' poses a potential UAF "
                    f"vulnerability risk because the variable {var_name} is not assigned a NULL value "
                    f"after memory is freed")
                result_bool = True
            else:
                result_str = f"Adding line {line.target_line_no}: '{line.value.strip()}' has no UAF risk."
                result_bool = False
        elif file_type == 'source':
            if res_no == self.UAF_VUL:
                result_str = (
                    f"Removing line {line.source_line_no}: '{line.value.strip()}' may lead to a UAF vulnerability "
                    f"where variable {var_name} is still used after memory is freed.")
                result_bool = True
            elif res_no == self.NULL_POINT_VUL:
                result_str = (
                    f"Removing line {line.source_line_no}: '{line.value.strip()}' may lead to a NULL point vulnerability "
                    f"where variable {var_name} is still used after being assigned NULL.")
                result_bool = True
            elif res_no == self.UAF_RISK:
                result_str = (
                    f"Removing line {line.source_line_no}: '{line.value.strip()}' poses a potential UAF "
                    f"vulnerability risk because the variable {var_name} is not assigned a NULL value "
                    f"after memory is freed")
                result_bool = True
            else:
                result_str = f"Adding line {line.source_line_no}: '{line.value.strip()}' has no UAF risk."
                result_bool = False
        return result_bool, result_str

    def get_var_operation_node(self, matching_nodes: list):
        node_id = ''
        var_name = ''
        for node, data in matching_nodes:
            if self.is_memory_operation(node):
                var_name, node_id = self.get_var_name_node(node)
                if var_name is not None and node_id is not None:
                    return node_id, var_name
        return node_id, var_name

    def check_use_after_free_by_path(self, uses: list, var_node: str) -> int:
        has_uaf = self.SAFE
        has_assign_null = False
        has_condition_node = False
        # 找到第一个赋值NULL操作(joern中将赋值也看作call)，并且要判断是否存在条件语句，应对Hypo攻击
        for use in uses:
            # node_type = self.cpg.nodes[use].get('label', 'Unknown')
            if is_condition_structure(self.cpg, use):
                has_condition_node = True
            # 判断赋值操作是否为NULL，这里没有考虑别名，因为希望减少漏报
            if self.is_assign_null(use, var_node):
                # 注意：这里增加误报率来应对Hypocrite攻击，如果赋值语句之前存在条件判断节点，则这里的赋值NULL可能无法到达
                if (not has_assign_null) and (not has_condition_node):
                    has_assign_null = True
            elif self.is_memory_operation(use):
                if has_assign_null:
                    has_uaf = self.NULL_POINT_VUL
                    return has_uaf
                else:
                    has_uaf = self.UAF_VUL
                    return has_uaf
            else:
                continue
        if not has_assign_null:
            has_uaf = self.UAF_RISK
        return has_uaf

    def is_assign_null(self, node_id: str, target_node: str) -> bool:
        node_type = self.cpg.nodes[node_id].get('label', 'Unknown')
        if node_type == 'CALL':
            if self.cpg.nodes[node_id].get('METHOD_FULL_NAME', 'Unknown') == '<operator>.assignment':
                node_var = str(int(node_id) + 1)
                node_null = str(int(node_id) + 2)
                if self.cpg.has_node(node_var) and self.cpg.has_node(node_null):
                    var_label = self.cpg.nodes[node_var].get('label', 'Unknown')
                    var_arg_index = self.cpg.nodes[node_var].get('ARGUMENT_INDEX', 0)
                    null_label = self.cpg.nodes[node_null].get('label', 'Unknown')
                    null_arg_index = self.cpg.nodes[node_null].get('ARGUMENT_INDEX', 0)
                    null_name = self.cpg.nodes[node_null].get('NAME', 'Unknown')
                    check_same_var = are_same_var(self.cpg, node_var, target_node)
                    if (var_label == 'IDENTIFIER' and var_arg_index == '1'
                            and null_label == 'IDENTIFIER' and null_arg_index == '2'
                            and null_name == 'NULL' and check_same_var):
                        return True
            return False
        return False

    def find_de_allocations(self, var: str, node_id: str) -> Set[str]:
        de_allocation_nodes = set()
        de_allocation_functions = ['free', 'delete', 'kfree']
        # 找到释放内存操作的根节点（line）
        for node, data in self.cpg.nodes(data=True):
            # 直接内存释放场景，比较内存释放函数
            if ('CODE' in data) and (data_check(data['CODE'], de_allocation_functions)
                                     and data['label'] == 'CALL'
                                     and data['METHOD_FULL_NAME'] in de_allocation_functions):
                # print(f"Test Code of current data is {data}")
                # 计算被释放的变量节点
                var_name, var_node = self.get_var_name_node(node)
                if (var_node is not None and var_node is not None and
                        not var_node == node_id and are_same_var(self.cpg, var_node, node_id)):
                    # print(f"Test3: node {var_node} and node {node_id} ara same")
                    de_allocation_nodes.add(var_node)
            # 降低漏报场景，不考虑间接释放
        return de_allocation_nodes

    def is_memory_operation(self, node_id: str) -> bool:
        node_type = self.cpg.nodes[node_id].get('label', 'Unknown')
        node_name = self.cpg.nodes[node_id].get('NAME', 'Unknown')
        node_code = self.cpg.nodes[node_id].get('CODE', 'Unknown')
        if node_type in ['CALL', 'IDENTIFIER']:
            # 检查是否是内存操作函数（不考虑内存的重新分配）
            if node_type == 'CALL':
                # TBD：改成data_check()
                memory_funcs = ['memcpy', 'memmove', '<operator>.pointerCall']
                if node_name in memory_funcs:
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
        # 判断相邻节点是否有内存相关操作
        for neighbor in self.cpg.neighbors(node_id):
            if (self.cpg.nodes[neighbor].get('label', 'Unknown') == 'MEMBER'
                    and self.cpg.nodes[neighbor].get('TYPE_FULL_NAME', 'Unknown').endswith('*')):
                return True
        return False

    def get_free_node(self, matching_nodes: list):
        node_id = ''
        var_name = ''
        # print(matching_nodes)
        if not matching_nodes:
            print("The matching node is NULL")
        else:
            for node, data in matching_nodes:
                # 直接场景，找到free/delete的函数调用
                # TBD:改成data_check
                if data['label'] == 'CALL' and data['METHOD_FULL_NAME'] in ['free', 'kfree']:
                    # matching nodes是针对某一行的，所以不会出现多个free操作
                    var_name, node_id = self.get_var_name_node(node)
                    return node_id, var_name
            func_node = is_indirect_call_equal(self.cpg, 'release', matching_nodes)
            if func_node != '':
                # 如果是间接操作，且函数的入参在函数内被释放
                var_name, node_id = self.get_var_name_node(func_node)
        return node_id, var_name

    # 遍历变量的使用路径
    def get_var_use_path(self, node_id: str, var: str, graph: nx.MultiDiGraph) -> list:
        uses = []
        # 因为是跟踪变量的使用情况，所以这里需要在light_cpg中遍历
        for succ in nx.dfs_preorder_nodes(graph, node_id):
            node_type = self.cpg.nodes[succ].get('label', 'Unknown')
            if node_type == 'IDENTIFIER':
                uses.append(succ)
            elif node_type == 'CALL':
                # 判断是否是当前node的argument
                var_name, current_node = self.get_var_name_node(succ)
                # print(f'Test 5: node_id is {node_id}, current_node is {current_node}')
                if current_node not in [None, ''] and are_same_var(self.cpg, node_id, current_node):
                    uses.append(succ)
        return uses

    def get_var_name_node(self, node_id):
        node = self.cpg.nodes[node_id]
        if node['label'] == 'CALL':
            # 默认认为第一个参数是被操作的变量
            for n in self.cpg.successors(node_id):
                edges = self.cpg.get_edge_data(node_id, n)
                for edge_data in edges.values():
                    if edge_data['label'] == 'ARGUMENT':
                        data = self.cpg.nodes[n]
                        if data['label'] == 'IDENTIFIER':
                            var = data['NAME']
                            return var, n
        return None, None
