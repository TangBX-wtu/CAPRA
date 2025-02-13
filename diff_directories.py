import os
import subprocess
import sys
import time
from pathlib import Path
import unidiff  # 用于验证生成的patch文件


def generate_diff(dir_a: str, dir_b: str, patch_file: str) -> bool:
    """
    比较两个目录的差异并生成patch文件

    Args:
        dir_a: 源目录路径
        dir_b: 目标目录路径
        patch_file: 生成的patch文件路径

    Returns:
        bool: 操作是否成功
    """
    try:
        # 确保目录存在
        if not os.path.isdir(dir_a) or not os.path.isdir(dir_b):
            print(f"Error: One or both directories do not exist: {dir_a}, {dir_b}")
            return False

        # 使用diff命令生成统一格式的差异文件
        # -N: 将不存在的文件视为空文件
        # -a: 将所有文件视为文本文件
        # -u0: 只显示修改部分，不现实上下文（容易出现行号错误情况）
        # -r: 递归处理子目录
        # -P：自动创建缺失的父目录
        cmd = ['diff', '-Naru0P', dir_a, dir_b]

        # 执行diff命令并将输出重定向到文件
        with open(patch_file, 'w') as f:
            result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True)

        # diff命令返回值：
        # 0 - 没有差异
        # 1 - 有差异
        # 2 - 发生错误
        if result.returncode > 1:
            print(f"Error running diff command: {result.stderr}")
            return False

        # 验证生成的patch文件是否可以被unidiff解析
        try:
            with open(patch_file, 'r') as f:
                patch_content = f.read()
                # 尝试解析patch文件
                unidiff.PatchSet(patch_content)
            print(f"Successfully generated patch file: {patch_file}")
            return True
        except Exception as e:
            print(f"Error: Generated patch file is not valid: {str(e)}")
            return False

    except Exception as e:
        print(f"Error during diff generation: {str(e)}")
        return False


def generate_diff_by_path(mk_new_diff: bool, input_path: str) -> str:
    patch_file = input_path + '/patch-info/patch'

    if mk_new_diff is not True:
        return patch_file

    start_time = time.time()
    dir_a = input_path + '/a'
    dir_b = input_path + '/b'

    # 确保patch文件的目录存在
    patch_path = Path(patch_file)
    patch_path.parent.mkdir(parents=True, exist_ok=True)

    success = generate_diff(dir_a, dir_b, patch_file)
    if success:
        end_time = time.time()
        print(f'Time to create new patch: {(end_time - start_time) * 1000:.3f} ms')
        return patch_file
    else:
        return ''
