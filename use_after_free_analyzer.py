import networkx as nx
import unidiff
from typing import Tuple, Set

from determine_order import analyze_nodes_order, determine_execution_order
from static_analyze_util import data_check, are_same_var, is_condition_structure, has_condition_node_in_path, \
    is_indirect_call_equal, get_var_name_node, is_memory_operation, get_var_operation_node, memory_func_init


class UseAfterFreeAnalyzer:
    UAF_VUL = 0
    NULL_POINT_VUL = 1
    UAF_RISK = 2
    SAFE = 3

    def __init__(self, cpg: nx.MultiDiGraph, strict: bool):
        self.cpg = cpg
        edge_type = ['CALL', 'ARGUMENT', 'RETURN', 'REACHING_DEF', 'REF', 'CFG']
        data_flow_edges = [(u, v) for (u, v, d) in self.cpg.edges(data=True) if d['label'] in edge_type]
        self.light_cpg = nx.MultiDiGraph(data_flow_edges)
        data_flow_edges = [(u, v) for (u, v, d) in self.cpg.edges(data=True) if d['label'] != 'SOURCE_FILE']
        self.cpg_without_source_file = nx.MultiDiGraph(data_flow_edges)
        self.allocation_funcs, self.deallocation_funcs, self.memory_operation = memory_func_init(
            'func_file/memory_functions.xml')
        self.strict = strict

    def analyze_potential_uaf(self, matching_nodes: list, line: unidiff.patch.Line, file_type: str) -> Tuple[
        bool, str]:
        # target场景分析内存释放和内存访问操作；source场景分析删除赋值NULL操作
        if file_type == "target":
            # print("UAF Test target")
            # 针对添加代码场景，分析内存释放操作和变量的使用操作
            node, var = self.get_free_node(matching_nodes)
            # 如果是free节点，则分析变量的后续使用情况
            if var != '' and node != '':
                # print(f'Test currnt node is {node}')
                # 在cpg中查找变量var是否还在继续使用
                uses = self.get_all_use_path(node, var, self.light_cpg)
                # print(f'Test uses path is {uses}')
                uses = self.uses_path_clear(matching_nodes, uses)
                # print(f'Test uses path of {node} is {uses}')
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
            node, var = get_var_operation_node(self.cpg, matching_nodes, self.memory_operation)
            # 反向遍历变量是否被free过：找到全局对应上述变量的free，看看是否有通路
            # 如果找到free的节点，则计算他们的通路，并在通路之间查看是否有赋值为NULL的节点 G.reverse()
            if var != '' and node != '':
                # print(f'Test, operation node is {node}, var is {var}')
                if self.is_assign_null(node, node):
                    # print(f'Test, current operation is nullified')
                    uses = self.get_all_use_path(node, var, self.light_cpg)
                    uses = self.uses_path_clear(matching_nodes, uses)
                    # print(f'Test, uses path is {uses}')
                    if len(uses) == 0 or self.is_post_alloc(uses, node):
                        res, res_str = self.result_format(self.SAFE, file_type, line, var)
                    else:
                        # 这里可能产生误报：如果nullified后面跟着malloc，则会出现误报，但是增加判断逻辑价值不高
                        res, res_str = self.result_format(self.NULL_POINT_VUL, file_type, line, var)
                    return res, res_str

                de_allocations = self.find_de_allocations(var, node)
                # print(f'Test de_allocations nodes are {de_allocations}')
                if len(de_allocations) != 0:
                    # print(f"Test, free nodes are {de_allocations}")
                    all_assign_null_nodes = self.get_all_assign_null_node(self.cpg, node)
                    # print(f"Test, nullified nodes are {all_assign_null_nodes}")
                    # 检测free节点和var节点之间是否有通路，通路中是否设置了NULL
                    for de_allocation in de_allocations:
                        # find_de_allocations中已经计算过变量的一致性/别名，在这里的cpg需要排除掉通过source_file进行连接的函数关系
                        res_no = self.check_use_after_free_by_var(self.cpg_without_source_file, all_assign_null_nodes,
                                                                  de_allocation, node)
                        res, res_str = self.result_format(res_no, file_type, line, var)
                        return res, res_str
                else:
                    print("UAF detection: Cannot find corresponding memory free nodes in this CPG")
        else:
            # print("UAF Test source")
            # 1.检查删除line中是否是清理赋值NULL
            # 2.若删除了var = NULL操作，则先判断指针内存是否被释放，再看变量后续是否还有使用
            # 如果没有操作则可能存在UAF风险（也可能是把整个var使用都删除，这个时候留给审核者），如果后面还有同变量内存相关操作，则是空指针
            node, var = self.get_remove_assign_null(matching_nodes)
            if node != '' and var != '':
                # print(f"remove assign null node is {node}, and var name is {var}")
                # 判断指针变量指向的内存在前面是否已经被释放
                de_allocations = self.find_de_allocations(var, node)
                if len(de_allocations) == 0:
                    # 删除的赋空操作的对应内存并未被释放，则认为没有风险
                    res, res_str = self.result_format(self.SAFE, file_type, line, var)
                    return res, res_str
                else:
                    # 如果存在相关内存释放操作与当前变量相关，则还需要判断内存释放是否在当前赋空操作之前
                    has_freed = False
                    for de_allocation in de_allocations:
                        # print(f'Test de_alloction node is {de_allocation}')
                        if nx.has_path(self.cpg, de_allocation, node):
                            has_freed = True
                            break
                    if not has_freed:
                        # 如果不是在赋空操作前，则也不认为已经被释放
                        res, res_str = self.result_format(self.SAFE, file_type, line, var)
                        return res, res_str

                uses = self.get_all_use_path(node, var, self.light_cpg)
                # 因为是删除操作，所以需要在use path中删除当前赋值NULL的节点，也就是matching nodes
                uses = self.uses_path_clear(matching_nodes, uses)
                # print(f'Test uses path from node {node} is {uses}')
                if len(uses) == 0:
                    # 删除了var == NULL，且后续没有操作，则可能未来引入UAF的风险
                    res, res_str = self.result_format(self.UAF_RISK, file_type, line, var)
                    return res, res_str
                else:
                    res_no = self.check_use_after_free_by_path(uses, node)
                    res, res_str = self.result_format(res_no, file_type, line, var)
                    return res, res_str
        return False, "Can not find potential use-after-free risk for current committed line"

    def is_post_alloc(self, uses_path: list, nullified_node: str) -> bool:
        post_node = uses_path[0]
        # print(f'Test, post_node is {post_node}')
        if self.cpg.has_node(post_node) and determine_execution_order(self.cpg, nullified_node, post_node) == 0:
            label = self.cpg.nodes[post_node].get('label', 'Unknown')
            if (label == 'CALL'
                    and self.cpg.nodes[post_node].get('METHOD_FULL_NAME', 'Unknown') in self.allocation_funcs):
                return True
            elif label == 'IDENTIFIER':
                line_num = self.cpg.nodes[post_node].get('LINE_NUMBER', 'Unknown')
                same_l_nodes = [n for n, d in self.cpg.nodes(data=True) if d.get('LINE_NUMBER', 'Unknown') == line_num]
                for node in same_l_nodes:
                    if (self.cpg.nodes[node].get('label', 'Unknown') == 'CALL'
                            and self.cpg.nodes[node].get('METHOD_FULL_NAME', 'Unknown') in self.allocation_funcs):
                        return True
                for neighbor in self.cpg.neighbors(post_node):
                    neighbor_line_num = self.cpg.nodes[neighbor].get('LINE_NUMBER', 'Unknown')
                    if neighbor_line_num != line_num:
                        continue
                    if (self.cpg.nodes[neighbor].get('label', 'Unknown') == 'CALL'
                            and self.cpg.nodes[neighbor].get('METHOD_FULL_NAME', 'Unknown') in self.allocation_funcs):
                        return True
        return False

    def sort_for_nodes(self, uses_path: list) -> list:
        n = len(uses_path)
        if n <= 1:
            return uses_path
        for i in range(0, n):
            for j in range(0, n-i-1):
                if analyze_nodes_order(self.cpg, uses_path[j], uses_path[j+1]) == 1:
                    (uses_path[j], uses_path[j+1]) = (uses_path[j+1], uses_path[j])
        return uses_path

    def uses_path_clear(self, matching_nodes: list, uses_path: list) -> list:
        uses_path = list(dict.fromkeys(uses_path))
        for node, data in matching_nodes:
            for tmp in uses_path:
                if tmp == node:
                    uses_path.remove(tmp)
        # 对use list中的节点根据调用顺序进行排序，因为dfs算法找到的节点顺序是混乱的
        uses_path = self.sort_for_nodes(uses_path)
        return uses_path

    def get_remove_assign_null(self, matching_nodes: list) -> tuple[str, str]:
        node = ''
        var = ''
        for node_id, data in matching_nodes:
            var_name, var_node = get_var_name_node(self.cpg, node_id)
            if var_node != '' and var_name != '' and self.is_assign_null(node_id, var_node):
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
        # reverse_cpg = cpg.reverse(copy=True)
        # 通过代码属性图来判断内存释放操作与制定变量存在关系(de_alloc->target_node是顺序操作，target_node->de_alloc是间接返回)
        if nx.has_path(cpg, de_allocation, target_node) or nx.has_path(cpg, target_node, de_allocation):
            # print(f'Test path from {de_allocation} to {target_node} is {nx.shortest_path(cpg, de_allocation, target_node)}')
            # 遍历NULL赋值节点是否是在内存释放之后进行
            for node in assign_null_nodes:
                if (nx.has_path(cpg, de_allocation, node) and analyze_nodes_order(self.cpg, de_allocation, node) == 0
                        and not has_condition_node_in_path(cpg, de_allocation, node)):
                    if nx.has_path(cpg, node, target_node) and analyze_nodes_order(self.cpg, node, target_node) == 0:
                        # 内存释放节点和内存操作节点之间如果存在赋值NULL，则可能存在空指针漏洞
                        return self.NULL_POINT_VUL
            # 内存释放节点和内存操作节点之间如果存在通路，但是又没有将指针设置为NULL，则存在UAF漏洞
            return self.UAF_VUL
        # 如果没有直接路径，但是是对同一个内存地址操作，那么free在use之前也是认为存在UAF漏洞。
        # 在查询dealloc时已经判断了是同一地址，那么就需要判断free和use的顺序，或者说这里需要的就是一个执行顺序的计算逻辑
        elif analyze_nodes_order(self.cpg, de_allocation, target_node) == 0:
            # print(f'Test, deallocate node {de_allocation} is before use node {target_node}')
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
                    f"where variable '{var_name}' is still used after memory is freed.")
                result_bool = True
            elif res_no == self.NULL_POINT_VUL:
                result_str = (
                    f"Adding line {line.target_line_no}: '{line.value.strip()}' may lead to a NULL point vulnerability "
                    f"where variable {var_name} is still used after being assigned NULL.")
                result_bool = not self.strict
            elif res_no == self.UAF_RISK:
                result_str = (
                    f"Adding line {line.target_line_no}: '{line.value.strip()}' poses a potential UAF "
                    f"vulnerability risk because the variable {var_name} is not assigned a NULL value "
                    f"after memory is freed")
                result_bool = not self.strict
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
                result_bool = not self.strict
            elif res_no == self.UAF_RISK:
                result_str = (
                    f"Removing line {line.source_line_no}: '{line.value.strip()}' poses a potential UAF "
                    f"vulnerability risk because the variable {var_name} is not assigned a NULL value "
                    f"after memory is freed")
                result_bool = not self.strict
            else:
                result_str = f"Adding line {line.source_line_no}: '{line.value.strip()}' has no UAF risk."
                result_bool = False
        return result_bool, result_str

    def check_use_after_free_by_path(self, uses: list, var_node: str) -> int:
        has_uaf = self.SAFE
        has_assign_null = False
        has_condition_node = False
        # 找到第一个赋值NULL操作(joern中将赋值也看作call)，并且要判断是否存在条件语句，应对Hypo攻击
        for use in uses:
            # print(f'Test, current node is {use}')
            # node_type = self.cpg.nodes[use].get('label', 'Unknown')
            if is_condition_structure(self.cpg, use):
                has_condition_node = True
            # 判断赋值操作是否为NULL，这里没有考虑别名，因为希望减少漏报
            if self.is_assign_null(use, var_node):
                # 注意：这里增加误报率来应对Hypocrite攻击，如果赋值语句之前存在条件判断节点，则这里的赋值NULL可能无法到达
                if (not has_assign_null) and (not has_condition_node):
                    has_assign_null = True
            elif is_memory_operation(self.cpg, use, self.memory_operation):
                # print(f'node {use} is memory operation')
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
        elif node_type == 'IDENTIFIER':
            order = self.cpg.nodes[node_id].get('ORDER', 'Unknown')
            if order != 'Unknown':
                pre_node = str(int(node_id) - int(order))
                return self.is_assign_null(pre_node, target_node)
        return False

    def find_de_allocations(self, var: str, node_id: str) -> Set[str]:
        de_allocation_nodes = set()
        # de_allocation_functions = ['free', '<operator>.delete', 'kfree', 'put_device']
        # 找到释放内存操作的根节点（line）
        for node, data in self.cpg.nodes(data=True):
            # 直接内存释放场景，比较内存释放函数
            if ('CODE' in data) and (data_check(data['CODE'], self.deallocation_funcs)
                                     and data['label'] == 'CALL'
                                     and data['METHOD_FULL_NAME'] in self.deallocation_funcs):
                # print(f"Test Code of current data is {data}")
                # 计算被释放的变量节点
                var_name, var_node = get_var_name_node(self.cpg, node)
                # print(f"Test3: node {var_node} and node {node_id}")
                if (var_node != '' and var_node != '' and
                        not var_node == node_id and are_same_var(self.cpg, var_node, node_id)):
                    # print(f"Test3: node {var_node} and node {node_id} ara same")
                    de_allocation_nodes.add(var_node)
        return de_allocation_nodes

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
                if (data['label'] == 'CALL'
                        and data['METHOD_FULL_NAME'] in self.deallocation_funcs):
                    # matching nodes是针对某一行的，所以不会出现多个free操作
                    var_name, node_id = get_var_name_node(self.cpg, node)
                    return node_id, var_name
            func_node = is_indirect_call_equal(self.cpg, 'release', matching_nodes)
            if func_node != '':
                # 如果是间接操作，且函数的入参在函数内被释放
                var_name, node_id = get_var_name_node(self.cpg, func_node)
        return node_id, var_name

    # 遍历变量的使用路径
    def get_var_use_path(self, node_id: str, var: str, graph: nx.MultiDiGraph) -> list:
        uses = set()
        # 因为是跟踪变量的使用情况，所以这里需要在light_cpg中遍历
        for succ in nx.dfs_preorder_nodes(graph, node_id):
            node_type = self.cpg.nodes[succ].get('label', 'Unknown')
            if (node_type == 'IDENTIFIER' and are_same_var(self.cpg, node_id, succ)
                    and analyze_nodes_order(self.cpg, node_id, succ) == 0):
                uses.add(succ)
            elif node_type == 'CALL':
                # 判断是否是当前node的argument
                var_name, current_node = get_var_name_node(self.cpg, succ)
                # print(f'Test 5: node_id is {node_id}, current_node is {current_node}')
                if (current_node != '' and are_same_var(self.cpg, node_id, current_node)
                        and analyze_nodes_order(self.cpg, node_id, current_node) == 0):
                    uses.add(current_node)
        return list(uses)

    # 创建一个新的函数get_all_use_path，先从当前函数开始分析，再从入参调用开始分析
    def get_all_use_path(self, node_id: str, var: str, graph: nx.MultiDiGraph) -> list:
        uses = []
        # 在当前函数下文中的使用路径
        uses = self.get_var_use_path(node_id, var, graph)
        # print(f'uses[] are {uses}')
        # 判断是否与当过前函数入参存在数据关系
        parameters_in, method_id = self.get_current_method_parameter_in(node_id)
        # 记录存在数据关系的入参
        same_para_in = []
        if len(parameters_in) != 0:
            for index, para in enumerate(parameters_in):
                if are_same_var(self.cpg, node_id, para):
                    # print(f'Test, node {node_id} and node {para} are same, index is {index}')
                    same_para_in.append(index)
        # 如果存在数据传递关系，找到函数的调用位置，跟踪其在后续代码中的路径
        if len(same_para_in) != 0:
            vars_id = self.find_method_caller(method_id, same_para_in)
            # print(f'Test vars_id are {vars_id}')
            # 从调用位置更新后续使用的路径
            if len(vars_id) != 0:
                for var_id in vars_id:
                    new_path = self.get_var_use_path(var_id, var, graph)
                    uses.extend(new_path)
        return uses

    # 获得当前节点所在函数的入参
    def get_current_method_parameter_in(self, current_id) -> Tuple[list, str]:
        parameters_in = []
        tmp_id = int(current_id) - 1
        finded_method = False
        method_node = ''
        while tmp_id > 0 and self.cpg.has_node(str(tmp_id)):
            label = self.cpg.nodes[str(tmp_id)].get('label', 'Unknown')
            if label == 'METHOD':
                finded_method = True
                method_node = str(tmp_id)
                break
            tmp_id = tmp_id - 1
        if finded_method:
            while True:
                tmp_id = tmp_id + 1
                label = self.cpg.nodes[str(tmp_id)].get('label', 'Unknown')
                if label == 'METHOD_PARAMETER_IN':
                    parameters_in.append(str(tmp_id))
                else:
                    break
        return parameters_in, method_node

    def find_method_caller(self, method_id: str, param_index: list):
        method_name = self.cpg.nodes[method_id].get('NAME', 'Unknown')
        callers_id = []
        vars_id = []
        for node, data in self.cpg.nodes(data=True):
            if ('label' in data and 'METHOD_FULL_NAME' in data
                    and data['label'] == 'CALL' and data['METHOD_FULL_NAME'] == method_name):
                callers_id.append(node)
        # print(f'Test, callers id are {callers_id}')
        if len(callers_id) != 0:
            for caller_id in callers_id:
                tmp_vars_id = []
                next_id = str(int(caller_id) + 1)
                while True:
                    if self.cpg.has_node(next_id) and self.cpg.nodes[next_id].get('label', 'Unknown') == 'IDENTIFIER':
                        tmp_vars_id.append(next_id)
                        # print(f'Test, append node {next_id}')
                        next_id = str(int(next_id) + 1)
                    else:
                        break
                for index in param_index:
                    if index < len(tmp_vars_id):
                        vars_id.append(tmp_vars_id[index])
        return vars_id
