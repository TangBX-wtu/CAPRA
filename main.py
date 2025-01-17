import os
import re
import sys

import graphviz
import networkx as nx
from networkx.drawing.nx_agraph import read_dot
from unidiff import PatchSet

from memory_leak_analyzer import MemoryLeakAnalyzer
from static_analyze_util import get_nodes_to_file, is_node_in_file
from use_after_free_analyzer import UseAfterFreeAnalyzer
from diff_directories import generate_diff_by_path

def get_patch_info(file_path):
    with open(file_path, 'r') as patch_file:
        patch_content = patch_file.read()
    patch_info = PatchSet(patch_content)
    return patch_info


# 判断是否是注释行
def is_commnet(line):
    return re.match(r'^\s*(//)|(^\s*/\*)', line) is not None


# 获取patchinfo中增加的line和减少的line
def get_added_removed_line(patch_info):
    added_line_info = {}
    removed_line_info = {}
    for patched_file in patch_info:
        # 删除或者新增文件场景，行为比较敏感，足够引起审核者的注意，因此这里不进行分析
        if patched_file.is_removed_file or patched_file.is_added_file:
            continue
        else:
            added_line = []
            removed_line = []
            source_file = patched_file.source_file
            target_file = patched_file.target_file

            for hunk in patched_file:
                target_lines = list(hunk.target_lines())
                source_lines = list(hunk.source_lines())
                for line in target_lines:
                    if (not is_commnet(line.value)) and line.is_added:
                        added_line.append(line)
                        # print(f"added line is {line.value.strip()}")
                for line in source_lines:
                    if (not is_commnet(line.value)) and line.is_removed:
                        removed_line.append(line)
                        # print(f"removed line is {line.value.strip()}")
            if bool(added_line):
                added_line_info[target_file] = added_line
            if bool(removed_line):
                removed_line_info[source_file] = removed_line
    return added_line_info, removed_line_info


# 通过joern生成待测源码的cpg
def generate_cpg(code_path):
    if os.path.exists(code_path + '/a/outA'):
        os.system(f"sudo rm -rf {code_path}/a/outA")
    if os.path.exists(code_path + '/b/outB'):
        os.system(f"sudo rm -rf {code_path}/b/outB")

    os.system(f"cd /home/tbx/bin/joern/joern-cli/; sudo ./joern-parse {code_path}/a;"
              f" sudo ./joern-export --repr=all --format=dot --out {code_path}/a/outA")
    os.system(f"cd /home/tbx/bin/joern/joern-cli/; sudo ./joern-parse {code_path}/b;"
              f" sudo ./joern-export --repr=all --format=dot --out {code_path}/b/outB")


def analyze_graph(lines, dot_file_path, file_type, file_name):
    risk_set = set()
    if len(lines) < 0:
        return
    graph = read_dot(dot_file_path)
    # print(f"Test dot_file_path is {dot_file_path}")
    # 创建缺陷解析器实例
    memory_leak_analyzer = MemoryLeakAnalyzer(graph)
    use_after_free_analyzer = UseAfterFreeAnalyzer(graph)

    # 获取node和filename之间的映射关系
    nodes_to_file = get_nodes_to_file(graph)
    # print(f"Test file name is {file_name}")
    # print(f"Test nodes_to_file is {nodes_to_file}")
    # 为了方便后续查询，创建一个line_num和nodes的映射，后续查询可以通过matching_nodes = nodes_line_num.get(target_line, [])
    nodes_line_num = {}
    for node, data in graph.nodes(data=True):
        # print(is_node_in_file(nodes_to_file, node, file_name))
        if 'LINE_NUMBER' in data and is_node_in_file(nodes_to_file, node, file_name):
            line_num = int(data['LINE_NUMBER'])
            if line_num not in nodes_line_num:  # and filename == node file
                nodes_line_num[line_num] = []
            nodes_line_num[line_num].append((node, data))
    # 针对修改逐行分析
    # print(f"Test nodes line num size is {len(nodes_line_num)}")
    for line in lines:
        # 找到图中对应的节点集合，matching_nodes
        matching_nodes = list()
        if file_type == "source":
            # print(f"Test source: Line value is {line.value.strip()}, line num is {line.source_line_no}")
            matching_nodes = nodes_line_num.get(line.source_line_no, [])
        elif file_type == "target":
            # print(f"Test target: Line value is {line.value.strip()}, line num is {line.target_line_no}")
            matching_nodes = nodes_line_num.get(line.target_line_no, [])

        if not matching_nodes:
            print(f"There is no matching nodes in CPG, line value is '{line.value.strip()}'")
        else:
            # print(f"Test: the node contained line num {line.target_line_no} are {matching_nodes}")
            # 可能存在同时删除 内存分配和内存释放 的情况，我们并不做过滤，这种简单的判断留给committer
            # 1.检测内存泄漏风险
            risk, res_str = memory_leak_analyzer.analyze_potential_leak(matching_nodes, line, file_type)
            # print(f"Test res_str of memory leak analyze is {res_str}")
            if risk:
                risk_set.add(res_str)
            # 2.检测UAF风险
            risk, res_str = use_after_free_analyzer.analyze_potential_uaf(matching_nodes, line, file_type)
            # print(f"Test res_str of use after free analyze is {res_str}")
            if risk:
                risk_set.add(res_str)
    return risk_set


# 根据dot文件生成图片，测试使用
def dot_to_image(file_path, out_put_path, format='png'):
    with open(file_path, 'r') as file:
        dot_graph = file.read()
    graph = graphviz.Source(dot_graph)

    graph.render(out_put_path, format=format, cleanup=True)
    print(f"Image saved as {out_put_path}.{format}")


def data_preprocess(case_path: str, mk_new_diff: bool, mk_new_cpg: bool) -> str:
    # data_path 是test_case的路径
    patch_path = generate_diff_by_path(mk_new_diff, case_path)

    if patch_path != '' and mk_new_cpg:
        generate_cpg(case_path)

    return patch_path


if __name__ == '__main__':

    # 对测试用例的数据进行预处理，输入为测试用例目录，创建diff文件，生成patch文件和cpg文件
    test_case_path = "/home/tbx/workspace/DataSet-2022-08-11-juliet/MemoryLeak/bad/Addition/testcase_05"
    patch_path = data_preprocess(test_case_path, False, False)
    # print(f"{patch_path}")
    if patch_path == '':
        print(f"data preprocess fail, can not generate new patch...")
        sys.exit(0)

    # patch_path_free_test = "/home/tbx/bin/joern/test-file/patch-info/fcc6655"
    # patch_path_malloc_test = "/home/tbx/bin/joern/test-file-malloc/patch-info/fcc6655"
    # patch_path_uaf_add_free = "/home/tbx/bin/joern/test-UAF-add-free/patch-info/fcc6655"
    # patch_path_uaf_add_free_and_null = "/home/tbx/bin/joern/test-UAF-add-free-and-null/patch-info/fcc6655"
    # patch_path_uaf_add_use = "/home/tbx/bin/joern/test-UAF-add-use/patch-info/fcc6655"
    # patch_path_uaf_remove_null = "/home/tbx/bin/joern/test-UAF-remove-NULL/patch-info/fcc6655"
    # patch_path_uaf_indirect_call = "/home/tbx/bin/joern/test-UAF-indirect-call/patch-info/fcc6655"
    patch_info = get_patch_info(patch_path)

    # 生成a/b目录下的cpg文件（dot格式）
    # code_path = "/home/tbx/PycharmProjects/StaticAnly/OpenSSH_test"
    # code_path = "/home/tbx/bin/joern/test-file"
    # code_path = "/home/tbx/bin/joern/test-file-malloc"
    # code_path = "/home/tbx/bin/joern/test-UAF-add-free"
    # code_path = "/home/tbx/bin/joern/test-UAF-add-free-and-null"
    # code_path = "/home/tbx/bin/joern/test-UAF-add-use"
    # code_path = "/home/tbx/bin/joern/test-UAF-remove-NULL"
    # test_case_path = "/home/tbx/bin/joern/test-UAF-indirect-call"
    # generate_cpg(code_path)
    source_cpg_path = test_case_path + "/a/outA/export.dot"
    target_cpg_path = test_case_path + "/b/outB/export.dot"

    # 查看图中路径，注意非常耗时
    # dot_to_image(target_cpg_path, code_path+'/b/cpg_img', 'png')

    # 解析patch文件，找到删除的行和添加的行信息
    added_line_info, removed_line_info = get_added_removed_line(patch_info)

    if bool(added_line_info):
        # 针对增加场景，分析提交后的版本
        for file_name, added_lines in added_line_info.items():
            risk_set = analyze_graph(added_lines, target_cpg_path, "target", file_name)
            if risk_set:
                print("The potential risk by the added lines in this commit are: ")
                for risk in risk_set:
                    print(f"#### {risk} ####")
            else:
                print("#### Adding in this commit is safe ####")
    if bool(removed_line_info):
        # 针对删除行场景，我们分析提交前的版本
        for file_name, removed_lines in removed_line_info.items():
            risk_set = analyze_graph(removed_lines, source_cpg_path, "source", file_name)
            # 后面可以考虑生成文本文件，然后输出到对应patch的目录下
            if risk_set:
                print("The potential risk by the removed lines in this commit are: ")
                for risk in risk_set:
                    print(f"#### {risk} ####")
            else:
                print("#### Removing in this commit is safe ####")
    # 如果是added_line，则对target文件（b文件），如果是removed_line则对source文件进行分析
