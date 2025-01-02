import os
import json

# 定义要遍历的目录
directory = '.'
# 定义输出文件的路径
output_file = 'merged_output.json'

# 创建一个空字典来存储合并后的数据
merged_data = {}

# 初始化索引计数器
index_counter = 0

def get_func_configs(func):
    configs = []
    print('[F] ', func)
    func += '('
    # 根目录
    root_dir = '/home/user/Kernel/v6.6/x86_64'
    
    # 遍历根目录及其子目录中的所有文件
    for dirpath, _, filenames in os.walk(root_dir):
        for filename in filenames:
            # 只处理 .c 文件
            if filename.endswith('.c'):
                c_file_path = os.path.join(dirpath, filename)
                # 检查文件是否包含 func 字符串
                with open(c_file_path, 'r') as c_file:
                    if func in c_file.read():
                        # 查找相应目录下的 Makefile
                        makefile_path = os.path.join(dirpath, 'Makefile')
                        if os.path.exists(makefile_path):
                            if  "samples" in makefile_path or \
                                "scripts" in makefile_path or \
                                "tools" in makefile_path:
                                return ["NOT_KERNEL"]
                            with open(makefile_path, 'r') as makefile:
                                lines = makefile.readlines()

                            # 生成 .o 文件名
                            obj_file_name = filename.replace('.c', '.o')
                            while obj_file_name != "":
                                print(f"[o] {obj_file_name} {makefile_path}")
                                for i in range(len(lines)):
                                    if obj_file_name in lines[i] and \
                                        "CFLAG" not in lines[i]:
                                        break
                                if obj_file_name not in lines[i]:
                                    break
                                obj_file_name = ""
                                while i >= 0:
                                    if "obj-y" in lines[i]:
                                        obj_file_name = ""
                                        break
                                    if "-y " in lines[i]:
                                        obj_file_name = lines[i].split('-y ')[0]+".o"
                                        break
                                    if "-objs" in lines[i]:
                                        obj_file_name = lines[i].split('-objs')[0]+".o"
                                        break
                                    if "-$(CONFIG" in lines[i] or "-${CONFIG" in lines[i]:
                                        obj_file_name = ""
                                        print("[i]", lines[i].strip())
                                        if "-$(" in lines[i]:
                                            config = lines[i].split("-$(")[1].split(')')[0]
                                        elif "-${" in lines[i]:
                                            config = lines[i].split("-${")[1].split(')')[0]
                                        configs.append(config)
                                        print(f"[+] config: {config}\n")
                                        break
                                    i -= 1
                            
                        else:
                            print(f"No Makefile found in directory: {dirpath}")
    return list(set(configs))

# 定义生成config数组的函数
def generate_config(copy_list):
    configs = []
    for func in copy_list:
        configs += get_func_configs(func)
    return list(set(configs))

# 遍历目录下的所有文件
for filename in os.listdir(directory):
    # 检查文件扩展名是否为.json
    if filename.endswith('.json') and filename.startswith('struct'):
    # if filename == "struct.intel_crtc_state.json":
        # 构建完整的文件路径
        file_path = os.path.join(directory, filename)
        # 打开并读取JSON数据
        with open(file_path, 'r') as file:
            # 加载JSON数据
            data = json.load(file)
            # 遍历字典，并将数据添加到merged_data中
            for key, value in data.items():
                # 如果键不在merged_data中，添加新数据
                if key not in merged_data:
                    # 添加 index 字段
                    value['index'] = index_counter
                    index_counter += 1
                    # 使用generate_config函数生成config字段
                    if 'copy' in value:
                        value['configs'] = generate_config(value['copy'])
                    else:
                        value['configs'] = []
                    # 添加到 merged_data 中
                    merged_data[key] = value

# 将合并后的数据写入新的JSON文件
with open(output_file, 'w') as file:
    json.dump(merged_data, file, indent=4)

print(f'All JSON files have been merged into {output_file}')
