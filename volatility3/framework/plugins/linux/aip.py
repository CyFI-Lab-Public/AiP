from volatility3.framework import interfaces, renderers, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist

from volatility3.framework.symbols.generic.types.python.python_3_8_18 import Python_3_8_18_IntermedSymbols
from volatility3.framework.symbols.generic.types.pytorch.pytorch_1_11 import PyTorch_1_11_IntermedSymbols

import numpy as np
import json
import pdb
from collections import OrderedDict
from readelf import ReadElf
import os

PROFILE_PATH = "/home/joseph/5-7-eval/volatility/ScriptOutputs/profile_py_376.txt"  # PATH TO PYTHON PROFILE
PROFILE_DATA = None
GPU_SEC_DICT = None
GPU_SEC_DICT_ALL = None
GPU_NOT_WEIGHT_PTRS = None
ON_GPU = True
EXPORT_WEIGHTS = False
'''
    Put name of gpu dump
'''
GPU_MEM_DUMP_NAME = "X.nvcudmp"
GPU_MEMDUMP_PATH = None
elf_output_path = None
'''
GPU_MEMDUMP_PATH = "/home/joseph/5-7-eval/volatility/dumps/pytorch/%s/%s/%s/%s_%d/%s" % (
    TORCH_VERSION, DATASET, MODEL, BD_TYPE, ALPHA, GPU_MEM_DUMP_NAME)
GPU_MEMDUMP_SIZE = os.path.getsize(GPU_MEMDUMP_PATH)
elf_output_path = GPU_MEMDUMP_PATH + '_profile.txt'

'''


gpu_ptr_list = []
recovered_c_structs = 0
recovered_python_objects = 0
false_positives = 0
hyperparameters = 0

percent_gpu_memory_used_forensics = 0
invalid_tensors_avoided = 0
gpu_mem_recovery_time = 0
managment_objects = 0
model_dict_percent_used_for_rec = 0


PyRuntimeOffsets = {'3_7_13': 0x6f1480, '3_8_18': 0x71e510}  # PyRuntime offset for 3.7, 3.8

pid = None
pyver = None
USING_GPU = True


class aip(interfaces.plugins.PluginInterface):
    """
    Finds PyTorch machine learning models and underlying layers, tensors, and attributes present in the memory image.

    - Developed for Python 3.8, 3.7.
    - Other versions may require adjustment of offsets

    Output:
        stdout: Model.layer instances found, in standard Volatility3 format
        ModelRecovery3_8.txt: Text file containing layers, tensors, and attributes
    """
    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel64"],
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                description="PID of the Python process in question",
                element_type=int,
                optional=False,
            ),
            requirements.ListRequirement(
                name="PyVersion",
                description="Offset of the PyRuntime symbol from your system's Python3 executable",
                element_type=str,
                optional=False,
            ),
        ]

    def _generator(self, tasks):

        PyVersionStr = self.config.get("PyVersion", None)[0]  # 'PyVersion' arg from command line

        global pid
        pid = self.config.get("pid", None)[0]



        global pyver
        pyver = PyVersionStr

        if PyVersionStr == '3_8_18':
            python_table_name = Python_3_8_18_IntermedSymbols.create(
                self.context, self.config_path, sub_path="generic/types/python", filename="python-3_8_18-x64"
            )
        else:
            print("WRONG PYTHON VERSION. RETURNING. \n")

        pytorch_table_name = PyTorch_1_11_IntermedSymbols.create(
            self.context, self.config_path, sub_path="generic/types/pytorch", filename="pytorch-1_11-x64"
        )

        task = list(tasks)[0]
        if not task or not task.mm:
            return

        task_name = utility.array_to_string(task.comm)

        task_layer = task.add_process_layer()
        curr_layer = self.context.layers[task_layer]

        if PyVersionStr in PyRuntimeOffsets:
            PyRuntimeOffsetRaw = PyRuntimeOffsets[PyVersionStr]
        else:
            return
        try:
            PyRuntimeOffset = int(
                PyRuntimeOffsetRaw)  # offset of PyRuntimeState in the executable's VMA, based on version of Python executable
        except ValueError:
            print("Invalid pyruntime hexadecimal string: ", PyRuntimeOffsetRaw)

        # PyRuntimeState = vma_start + PyRuntimeOffset
        PyRuntimeState = PyRuntimeOffset
        # gc_runtime = int.from_bytes(curr_layer.read(PyRuntimeState + 40, 8), byteorder='little')


        set_gpu_sec()

        if pyver == '3_8_18':
            PYGC_HEAD_OFFSET = 368
            models = traverse_GC_3_8(self.context, curr_layer, PyRuntimeState, PYGC_HEAD_OFFSET,
                                                           python_table_name)
        elif pyver == '3_7_13':
            PYGC_HEAD_OFFSET = 352
            models = traverse_GC_3_7(self.context, curr_layer, PyRuntimeState, PYGC_HEAD_OFFSET,
                                                           python_table_name)
        else:
            print('Invalid PyGC Head Offset. Returning. \n')
            return

        for counter, model in enumerate(models):
            layers, types, unique_path_types = get_layers_recursive(self.context, curr_layer, python_table_name, model)

            info_string, tensor_count, weight_count = process_tensors(self.context, curr_layer, pytorch_table_name,
                                                                    layers, unique_path_types)
            print(info_string)

            print(f'Total tensor count : {tensor_count}\n')
            print(f'Total weight count : {weight_count}\n')



    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("Layers", str)
            ],
            self._generator(
                pslist.PsList.list_tasks(
                    self.context,
                    self.config["kernel"],
                    filter_func=filter_func
                )
            ),
        )



def set_gpu_sec():
    global GPU_SEC_DICT
    global GPU_SEC_DICT_ALL
    GPU_SEC_DICT = {}
    GPU_SEC_DICT_ALL = {}
    if GPU_MEMDUMP_PATH is not None:
        with open(GPU_MEMDUMP_PATH, 'rb') as elf_stream, open(elf_output_path, 'w') as output:
            elf_reader = ReadElf(elf_stream, output)
            elf_reader.display_file_header()
            elf_reader.display_section_headers()
            # elf_reader.display_string_dump('.cudbg.global.0')
            for nsec, section in enumerate(elf_reader.elffile.iter_sections()):
                if 'global' in section.name:
                    GPU_SEC_DICT[section.name] = {}
                    GPU_SEC_DICT[section.name]['offset'] = section['sh_offset']
                    GPU_SEC_DICT[section.name]['address'] = section['sh_addr']
                    GPU_SEC_DICT[section.name]['size'] = section['sh_size']
                GPU_SEC_DICT_ALL[section.name] = {}
                GPU_SEC_DICT_ALL[section.name]['offset'] = section['sh_offset']
                GPU_SEC_DICT_ALL[section.name]['address'] = section['sh_addr']
                GPU_SEC_DICT_ALL[section.name]['size'] = section['sh_size']

def get_gpu_sec():
    return GPU_SEC_DICT

def extract_from_gpu(num_elements, buf):
    global gpu_memory_ptrs
    gpu_memory_ptrs+=1
    ret = []
    ct = 0
    section_dict = get_gpu_sec()
    if GPU_MEMDUMP_PATH is None:
        return
    with open(GPU_MEMDUMP_PATH, 'rb') as elf_stream, open(elf_output_path, 'w') as output:
        elf_reader = ReadElf(elf_stream, output)
        for global_sec in section_dict:
            address_start = section_dict[global_sec]['address']
            address_end = address_start + section_dict[global_sec]['size']
            if buf < address_end and buf > address_start:
                while buf < (address_start + (num_elements * 4)):
                    offset = buf - address_start
                    elf_reader.elffile.stream.seek(offset + section_dict[global_sec]['offset'])
                    bytes = elf_reader.elffile.stream.read(4)
                    ret.append(bytes)
                    buf += 4
                    ct += 1
                break
    return ret

def extract_data(context, curr_layer, num_elements, buf, python_table_name):
    global invalid_tensors_avoided
    ct = 0
    ret = []
    if not ON_GPU:
        while (ct != num_elements):
            float = context.object(
                object_type=python_table_name + constants.BANG + "PyFloatObject",
                layer_name=curr_layer.name,
                offset=buf
                # this is not 16 and is instead 32, for Python 3.7.13, seems to be extra padding
            )
            if (ct < 3):
                print(float.get_value())
            if not isinstance(float.get_value(), float): #invalid tensor
                invalid_tensors_avoided+=1
                return []
            else:
                ret.append(float.get_value())
            buf += 4
            ct += 1
    else:
        ret = extract_from_gpu(num_elements, buf)

    return ret


def check_weights(task, out_dict):
    """
    Prints metrics about accuracy of weight recovery relative to ground truth
    """
    f = open("correct_weights_" + str(task.pid) + ".txt", "r")
    correct_dump = json.load(f)

    missing_weights = 0
    missing_layers = 0
    diff_weights = 0
    sum_diff = 0
    missing_arr = []
    diff_layers = []

    for layer in correct_dump['tensors']:
        if (layer in out_dict['tensors']):
            print(layer)

            correct_arr = correct_dump['tensors'][layer]
            recovered_arr = out_dict['tensors'][layer]

            diff_pos = []

            if (len(recovered_arr) != len(correct_arr)):
                print("Shapes Different")
            else:
                for i in range(len(correct_arr)):
                    if (recovered_arr[i] != correct_arr[i]):
                        diff_pos.append(i)

            if (len(diff_pos) == len(correct_arr)):
                print("No Valid Tensors")
            else:
                print("{} weights different".format(len(diff_pos)))
                print(diff_pos)
                sum_diff += len(diff_pos)
            if len(diff_pos) > 0:
                diff_layers.append(layer)

        else:
            missing_layers += 1
            missing_weights += len(correct_dump['tensors'][layer])
            missing_arr.append(layer)

    print("Correct model_name: {}".format(correct_dump['model_name']))
    print("Received model_name: {}".format(out_dict['model_name']))
    print("Correct num_elements: {}".format(correct_dump['num_elements']))
    print("Received num_elements: {}\n".format(out_dict['num_elements']))
    print(len(diff_layers))
    print(diff_layers)
    print(sum_diff)
    print("{} layers not found".format(missing_layers))
    print(missing_arr)
    print("{} out of {} found weights are different".format(sum_diff, correct_dump['num_elements'] - missing_weights))



def export_offsets(task, tensor_offsets, export_path, alpha):
    """
    Write offsets of TensorImpl structs to file for rehosting
    File format:
        First line contains integer n, the number of tensors.
        n lines follow containing the name of the TensorImpl struct and its address.
    """
    f = open(export_path + "offsets_" + str(task.pid) + "_" + str(int(alpha*100)) + ".txt", 'w')
    f.write(str(len(tensor_offsets)) + "\n")
    for name in tensor_offsets:
        f.write(name + " " + str(hex(tensor_offsets[name])) + "\n")
    f.close()


def get_gpu_sec_all():
    return GPU_SEC_DICT


def check_ptr_candidate(ptr_candidate):
    global gpu_ptr_list
    global GPU_NOT_WEIGHT_PTRS
    GPU_NOT_WEIGHT_PTRS = {}
    section_dict = get_gpu_sec_all()
    if GPU_MEMDUMP_PATH is None:
        return False
    with open(GPU_MEMDUMP_PATH, 'rb') as elf_stream, open(elf_output_path, 'w') as output:
        elf_reader = ReadElf(elf_stream, output)
        for sec in section_dict:
            address_start = section_dict[sec]['address']
            address_end = address_start + section_dict[sec]['size']
            if ptr_candidate < address_end and ptr_candidate > address_start:
                if ptr_candidate not in gpu_ptr_list:
                    print("Ptr Candidate not in GPU ptr list, but is in section ")
                    print(sec)
                    print("Ptr Value")
                    print(ptr_candidate)
                    if hex(ptr_candidate) in GPU_NOT_WEIGHT_PTRS:
                        GPU_NOT_WEIGHT_PTRS[hex(ptr_candidate)]['count']+=1
                    else:
                        GPU_NOT_WEIGHT_PTRS[hex(ptr_candidate)] = {}
                        GPU_NOT_WEIGHT_PTRS[hex(ptr_candidate)]['count'] = 1
                        GPU_NOT_WEIGHT_PTRS[hex(ptr_candidate)]['sec'] = sec
                return True
    return False

def process_tensors(context, curr_layer, pytorch_table_name, layers, path_types):
    """
    Recovers/tensors/weights/etc.

    Args:
        context = Vol Context
        curr_layer = Vol Cur Layer
        pytorch_table_name = name of table associated with version of pytorch targeted (table for 1.11)
        layers = layers recovered for DL model
        path_types = types for all objects

    Returns:
        info_string = Printable representation for logging purposes
    """
    global USING_GPU
    # params = []
    info = ''
    model_info = {}
    weight_counter = 0
    tensor_counter = 0

    for layer_name, layer_obj in layers:
        layer_dict = layer_obj.dict.dereference().get_dict()
        info += "\n-------------------------------------------------------------------------\n\n"
        info += layer_name + " Attributes: \n\n"

        model_info[layer_name] = {}

        '''Keys of layer object dictionary. '''
        model_info[layer_name]['keys'] = []

        # All known keys currently into model info for each layer
        for key in layer_dict:
            if not key.startswith('_'):
                info += key + ': ' + str(layer_dict[key]) + '\n'
                model_info[layer_name]['keys'].append(str(layer_dict[key]))

        if 'name' not in layer_dict.keys():
            for layer_type in path_types.keys():
                if layer_name in path_types[layer_type]:
                    model_info[layer_name]['name'] = layer_type
                    model_info[layer_name]['keys'].append('name')
        else:
            model_info[layer_name]['name'] = layer_dict['name']

        if 'type' not in layer_dict.keys():
            model_info[layer_name]['type'] = None
        else:
            model_info[layer_name]['type'] = layer_dict['type']

        param_dict = layer_dict['_parameters']
        buffer_dict = layer_dict['_buffers']

        model_info[layer_name]['params'] = {}

        # Traverse parameters if present in layer (like weight/bias)
        if len(param_dict) > 0:
            for k in param_dict:
                model_info[layer_name]['params'][k] = {}
                param_name = layer_name + '.' + k
                model_info[layer_name]['params'][k]['param_name'] = param_name
                info += '\n' + k.capitalize() + '\n'

                if param_dict[k] == None:
                    continue
                param = context.object(
                    object_type=pytorch_table_name + constants.BANG + "Parameter",
                    layer_name=curr_layer.name,
                    offset=param_dict[k].vol.offset,
                )

                tensor = param.data.dereference()
                model_info[layer_name]['params'][k]['tensor_obj'] = tensor
                tensor_counter += 1

                num_elements = tensor.num_elements()
                model_info[layer_name]['params'][k]['num_el'] = num_elements

                weight_counter += num_elements

                tensor_data_ptr = tensor.get_data_ptr()
                model_info[layer_name]['params'][k]['data_ptr'] = tensor_data_ptr

                shape = tuple(tensor.shape())
                model_info[layer_name]['params'][k]['shape'] = shape

                USING_GPU = check_ptr_candidate(tensor_data_ptr)
                if not USING_GPU:
                    tensor_weights = np.reshape(np.array(tensor.get_data()), shape)
                    model_info[layer_name]['params'][k]['data'] = tensor_weights
                else:
                    # GPU WEIGHT EXTRACTION HERE
                    model_info[layer_name]['params'][k]['data'] = extract_from_gpu(num_elements, tensor_data_ptr)

                # params.append((param_name, tensor_data_ptr))

                info += "Number of Elements: " + str(num_elements) + '\n'
                info += "Shape: " + str(shape) + '\n'
                # info += "data_type: " + tensor.get_type()[0] + '\n\n'
                info += "Tensor Floats Pointer:  " + hex(tensor_data_ptr) + '\n'
    tensor_count = "Tensor Count:  " + str(tensor_counter) + '\n'
    weight_count = "Total Weights Count:  " + str(weight_counter) + '\n'

    model_info['weight_count'] = weight_counter
    model_info['tensor_count'] = tensor_counter
    return  info, tensor_count, weight_count


def get_layers_recursive(context, curr_layer, python_table_name, model):
    """Acquires the modules (ie. layers) of the ML model.

    Args:
        model: tuple (model name, model obj as a PyInstanceObject)

    Returns:
        A list of tuples: (module name, module object)
    """
    modules = []
    types = []
    model_name, model_object = model[0], model[1]
    unique_path_types = {}
    queue = [("model", model_object)]
    layer_count = 0
    while (len(queue)):
        path, node = queue.pop(0)
        node_dict = node.dict.dereference().get_dict()
        if len(node_dict['_modules'].keys()) == 0:
            modules.append((path, node))  # path (i.e. model.model.0) and obj
            continue
        for key in node_dict['_modules'].keys():
            obj = node_dict['_modules'][key]
            new_obj = context.object(
                object_type=python_table_name + constants.BANG + "PyInstanceObject",
                layer_name=curr_layer.name,
                offset=obj.vol.offset)
            new_obj_type = new_obj.ob_type.dereference().get_name()
            if new_obj_type not in types:
                types.append(new_obj_type)
                unique_path_types[new_obj_type] = []
                unique_path_types[new_obj_type].append(path + "." + key)
            else:
                unique_path_types[new_obj_type].append(path + "." + key)
            # print(hex(obj.vol.offset))

            queue.append((path + "." + key, new_obj))
    for type in types:
        print(f"Unique type found: {type}\n")
    return modules, types, unique_path_types


def traverse_GC_3_8(context, curr_layer, PyRuntimeState, PyGC_Head_Offset, python_table_name):
    """Locates ML models by name by traversing the Python garbage collector.

    https://github.com/pytorch/pytorch/blob/v2.0.0/torch/nn/modules/module.py#L366

    Args:
        context: the context object this configuration is stored in
        curr_layer: current memory layer
        PyIntrpState: address of the PyInterpreterState struct within current layer
        PyGC_Head_Offset: offset of the first generation within the PyInterpreterState struct
        python_table_name: Python symbol table name

    Returns:
        A list of tuples: (type name, model object)
    """
    GC_GENERATIONS = 3
    ct_filt = 0
    model_identifiers = ['resnet18.ResNet', 'ResNet', 'Model', 'Net', 'models.yolo.DetectionModel', 'DetectionModel']
    ct_saved = 0

    Models = []

    for i in range(GC_GENERATIONS):  # 3 GC generations (separated by 48 bytes in 3.7.13)
        PyGC_Head = int.from_bytes(
            curr_layer.read(PyRuntimeState + PyGC_Head_Offset, 8),
            byteorder='little'
        )
        PyGC_Tail = int.from_bytes(
            curr_layer.read(PyRuntimeState + PyGC_Head_Offset + 8, 8),
            byteorder='little'
        )
        GC_Stop = int.from_bytes(  # 'end' of the circular doubly linked list
            curr_layer.read(PyGC_Head + 8, 8),
            byteorder='little'
        )
        print(f'PyGC_Head: {hex(PyGC_Head)}, GC_Stop: {hex(GC_Stop)}')
        print(f'PyGC_Tail: {hex(PyGC_Tail)}')
        visited = set()
        while PyGC_Head != GC_Stop and PyGC_Head != 0:
            if PyGC_Head in visited:
                print(f'Broke search of gen({i}) because revisited PyGC_Header: {PyGC_Head}')
                break
            visited.add(PyGC_Head)

            ptr_next = int.from_bytes(  # next GC object
                curr_layer.read(PyGC_Head, 8),
                byteorder='little'
            )

            ptr_type = int.from_bytes(  # pointer to PyTypeObject This is 40 and not 24 for Python 3.7.13
                curr_layer.read(PyGC_Head + 24, 8),
                byteorder='little'
            )

            ptr_tp_name = int.from_bytes(  # pointer to type name This is the same between Python 3.7.13 and 3.10.6
                curr_layer.read(ptr_type + 24, 8),
                byteorder='little'
            )
            tp_name = hex_bytes_to_text(curr_layer.read(ptr_tp_name, 64, pad=True))
            # MODEL IDENTIFICATION
            if tp_name in model_identifiers:
                model = context.object(
                    object_type=python_table_name + constants.BANG + "PyInstanceObject",
                    layer_name=curr_layer.name,
                    offset=PyGC_Head + 16,
                    # this is not 16 and is instead 32, for Python 3.7.13, seems to be extra padding
                )
                Models.append((tp_name, model))
            PyGC_Head = ptr_next
        PyGC_Head_Offset += 24


        print(f'Finished Traversing GC Generation {i}')

    return Models


def traverse_GC_3_7(context, curr_layer, PyRuntimeState, PyGC_Head_Offset, python_table_name):
    """Locates ML models by name by traversing the Python garbage collector.

    https://github.com/pytorch/pytorch/blob/v2.0.0/torch/nn/modules/module.py#L366

    Args:
        context: the context object this configuration is stored in
        curr_layer: current memory layer
        PyIntrpState: address of the PyInterpreterState struct within current layer
        PyGC_Head_Offset: offset of the first generation within the PyInterpreterState struct
        python_table_name: Python symbol table name

    Returns:
        A list of tuples: (type name, model object)
    """
    GC_GENERATIONS = 3
    ct_filt = 0
    ct_saved = 0
    model_identifiers = ['resnet18.ResNet', 'ResNet', 'Model', 'Net', 'models.yolo.DetectionModel', 'DetectionModel']


    Models = []

    for i in range(GC_GENERATIONS):  # 3 GC generations (separated by 48 bytes in 3.7.13)

        PyGC_Head = int.from_bytes(
            curr_layer.read(PyRuntimeState + PyGC_Head_Offset, 8),
            byteorder='little'
        )
        PyGC_Tail = int.from_bytes(
            curr_layer.read(PyRuntimeState + PyGC_Head_Offset + 8, 8),
            byteorder='little'
        )
        GC_Stop = int.from_bytes(  # 'end' of the circular doubly linked list
            curr_layer.read(PyGC_Head + 8, 8),
            byteorder='little'
        )
        print(f'PyGC_Head: {hex(PyGC_Head)}, GC_Stop: {hex(GC_Stop)}')
        print(f'PyGC_Tail: {hex(PyGC_Tail)}')
        visited = set()
        while PyGC_Head != GC_Stop and PyGC_Head != 0:
            if PyGC_Head in visited:
                print(f'Broke search of gen({i}) because revisited PyGC_Header: {PyGC_Head}')
                break
            visited.add(PyGC_Head)

            ptr_next = int.from_bytes(  # next GC object
                curr_layer.read(PyGC_Head, 8),
                byteorder='little'
            )
            ptr_type = int.from_bytes(  # pointer to PyTypeObject This is 40 and not 24 for Python 3.7.13
                curr_layer.read(PyGC_Head + 40, 8),
                byteorder='little'
            )

            ptr_tp_name = int.from_bytes(  # pointer to type name This is the same between Python 3.7.13 and 3.10.6
                curr_layer.read(ptr_type + 24, 8),
                byteorder='little'
            )
            tp_name = hex_bytes_to_text(curr_layer.read(ptr_tp_name, 64, pad=True))

            # MODEL IDENTIFICATION
            tp_name = hex_bytes_to_text(curr_layer.read(ptr_tp_name, 64, pad=True))
            # MODEL IDENTIFICATION
            if tp_name in model_identifiers:
                model = context.object(
                    object_type=python_table_name + constants.BANG + "PyInstanceObject",
                    layer_name=curr_layer.name,
                    offset=PyGC_Head + 32,
                    # this is not 16 and is instead 32, for Python 3.7.13, seems to be extra padding
                )
                Models.append((tp_name, model))
            PyGC_Head = ptr_next
        PyGC_Head_Offset += 48
        # changed from 24 for python3.7
        print(f'Finished Traversing GC Generation {i}')

    return Models

def hex_bytes_to_text(value):
    """Renders HexBytes as text.

    Args:
        value: A series of bytes

    Returns:
        The ASCII representation of the hexadecimal bytes.
    """
    if not isinstance(value, bytes):
        raise TypeError(f"hex_bytes_as_text() takes bytes not: {type(value)}")

    ascii = []
    count = 0
    output = ""

    for byte in value:
        if (byte != 0x00):
            ascii.append(chr(byte))
        elif (count < 2):
            return "Error: no name found"
        else:
            output += "".join(ascii[count - (count % 8): count + 1])
            return output

        if (count % 8) == 7:
            output += "".join(ascii[count - 7: count + 1])
        count += 1

    return output
