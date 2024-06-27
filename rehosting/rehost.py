import mmap
import os
import numpy as np
from ctypes import *
import torch
import pdb


def decode_float(i):
    cp = pointer(c_int(i))  # make this into a c integer
    fp = cast(cp, POINTER(c_float))  # cast the int pointer to a float pointer
    return fp.contents.value  # dereference the pointer, get the float


def extract_tensor(mapped_dump, data_buf_addr, dim_1, dim_2, dim_3, dim_4, num_dims, name):
    if num_dims == 1:
        dim_1 = int.from_bytes(dim_1[0:2], byteorder='little')
    elif num_dims == 2:
        dim_1 = int.from_bytes(dim_1[0:2], byteorder='little')
        dim_2 = int.from_bytes(dim_2[0:2], byteorder='little')
    elif num_dims == 3:
        dim_1 = int.from_bytes(dim_1[0:2], byteorder='little')
        dim_2 = int.from_bytes(dim_2[0:2], byteorder='little')
        dim_3 = int.from_bytes(dim_3[0:2], byteorder='little')
    elif num_dims == 4:
        dim_1 = int.from_bytes(dim_1[0:2], byteorder='little')
        dim_2 = int.from_bytes(dim_2[0:2], byteorder='little')
        dim_3 = int.from_bytes(dim_3[0:2], byteorder='little')
        dim_4 = int.from_bytes(dim_4[0:2], byteorder='little')
    else:
        dim_1 = 0
        dim_2 = 0
        dim_3 = 0
        dim_4 = 0
    count = 0
    if dim_1 != 0 and dim_2 != 0 and dim_3 != 0 and dim_4 != 0:
        num_el = dim_1 * dim_2 * dim_3 * dim_4
        np_rep = np.ndarray(shape=(dim_1, dim_2, dim_3, dim_4), dtype=np.float32)
        for w in range(dim_1):
            for x in range(dim_2):
                for y in range(dim_3):
                    for z in range(dim_4):
                        mapped_dump.seek(data_buf_addr + count)
                        flt = mapped_dump.read(4)
                        flt = int.from_bytes(flt, byteorder='little')
                        flt = decode_float(flt)
                        np_rep[w, x, y, z] = flt
                        count += 4  # add 4 bytes
    elif dim_1 != 0 and dim_2 != 0 and dim_3 != 0 and dim_4 == 0:
        num_el = dim_1 * dim_2 * dim_3
        np_rep = np.ndarray(shape=(dim_1, dim_2, dim_3), dtype=np.float32)
        for w in range(dim_1):
            for x in range(dim_2):
                for y in range(dim_3):
                    mapped_dump.seek(data_buf_addr + count)
                    flt = mapped_dump.read(4)
                    flt = int.from_bytes(flt, byteorder='little')
                    flt = decode_float(flt)
                    np_rep[w, x, y] = flt
                    count += 4  # add 4 bytes
    elif dim_1 != 0 and dim_2 != 0 and dim_3 == 0 and dim_4 == 0:
        num_el = dim_1 * dim_2
        np_rep = np.ndarray(shape=(dim_1, dim_2), dtype=np.float32)
        for w in range(dim_1):
            for x in range(dim_2):
                mapped_dump.seek(data_buf_addr + count)
                flt = mapped_dump.read(4)
                flt = int.from_bytes(flt, byteorder='little')
                flt = decode_float(flt)
                np_rep[w, x] = flt
                count += 4  # add 4 bytes
    elif dim_1 != 0 and dim_2 == 0 and dim_3 == 0 and dim_4 == 0:
        num_el = dim_1
        np_rep = np.ndarray(shape=(dim_1,), dtype=np.float32)
        for w in range(dim_1):
            mapped_dump.seek(data_buf_addr + count)
            flt = mapped_dump.read(4)
            flt = int.from_bytes(flt, byteorder='little')
            flt = decode_float(flt)
            np_rep[w] = flt
            count += 4  # add 4 bytes
    elif num_dims == 0:
        num_el = 1
        np_rep = np.ndarray(shape=(1,), dtype=np.int32)
        mapped_dump.seek(data_buf_addr + count)
        flt = mapped_dump.read(4)
        flt = int.from_bytes(flt, byteorder='little')
        np_rep[0] = flt

    else:
        print("undefined shape?")
    if num_el != np_rep.size:
        print("Element size miss match for Tensor recreation: " + str(name))
        return 0
    if ':' in name:
        name, _ = name.split(':')
    tensor = torch.from_numpy(np_rep)
    return tensor


def get_correct_offset(offsets, address):
    last = 0
    gap = 0
    for interval in offsets:
        gap += (interval[0] - last)
        last = interval[1]
        if interval[0] <= address:
            if interval[1] >= address:
                break
    return gap


def get_tensors(dump_path, tensor_addresses):
    dump_handle = open(dump_path, mode="rb+")
    mapped_dump = mmap.mmap(dump_handle.fileno(), length=0, access=mmap.ACCESS_READ, offset=0)
    tensor_addr_handle = open(tensor_addresses, mode="r", encoding="utf8")
    layers = tensor_addr_handle.readlines()
    layer_dict = {}
    nothing = layers.pop(0)
    offsets = layers.pop(0)
    offset, end_offset = offsets.split(' ')
    offset = offset[0:-1]
    offset = int(offset, 16)
    end_offset = end_offset[0:-2]
    end_offset = int(end_offset, 16)
    offsets = [(offset, end_offset)]
    for layer in layers:
        layer_name, address = layer.split(' ')
        if '\n' in address:
            address, _ = address.split('\n')
        if 'L' in layer:
            start_offset = layer_name[0:-1]
            end_offset = address[0:-1]
            start_offset = int(start_offset, 16)
            end_offset = int(end_offset, 16)
            offsets.append((start_offset, end_offset))
            continue
        address = int(address, 16)
        offset = get_correct_offset(offsets, address)
        tensor_address = address - offset
        mapped_dump.seek(tensor_address + 64)
        num_dims = mapped_dump.read(8)
        num_dims = int.from_bytes(num_dims, byteorder='little')
        mapped_dump.seek(tensor_address + 72)
        dim_1 = mapped_dump.read(8)
        dim_2 = 0
        dim_3 = 0
        dim_4 = 0
        if num_dims == 2:
            mapped_dump.seek(tensor_address + 80)
            dim_2 = mapped_dump.read(8)
            dim_3 = 0
            dim_4 = 0
        elif num_dims == 3:
            mapped_dump.seek(tensor_address + 80)
            dim_2 = mapped_dump.read(8)
            mapped_dump.seek(tensor_address + 88)
            dim_3 = mapped_dump.read(8)
        elif num_dims == 4:
            mapped_dump.seek(tensor_address + 80)
            dim_2 = mapped_dump.read(8)
            mapped_dump.seek(tensor_address + 88)
            dim_3 = mapped_dump.read(8)
            mapped_dump.seek(tensor_address + 96)
            dim_4 = mapped_dump.read(8)

        mapped_dump.seek(tensor_address + 24)
        storage_impl_address = mapped_dump.read(8)
        storage_impl_address = int.from_bytes(storage_impl_address, byteorder='little')
        storage_impl_address = storage_impl_address - offset
        mapped_dump.seek(storage_impl_address + 24)
        data_buffer = mapped_dump.read(8)
        data_buffer = int.from_bytes(data_buffer, byteorder='little')
        correct_offset = get_correct_offset(offsets, data_buffer)
        data_buffer = data_buffer - correct_offset

        tensor = extract_tensor(mapped_dump, data_buffer, dim_1, dim_2, dim_3, dim_4, num_dims, layer_name)
        layer_dict[layer_name] = tensor
    return layer_dict


def map_tensors(which_model, model_fn, recovered_tensor_list):
    for layer in recovered_tensor_list:
        if 'model' in layer:
            prefix, layer = layer.split('.', 1)
        for name, param in model_fn.state_dict().items():
            if layer == name:
                layer = str(prefix) + '.' + str(layer)
                if 'tracked' in name:
                    print(param)
                    param = recovered_tensor_list[layer]
                    print(param)
                else:
                    rec_dims = len(recovered_tensor_list[layer].shape)
                    dims = len(param.shape)
                    if rec_dims == dims:
                        print(param)
                        param.copy_(recovered_tensor_list[layer])
                        print(param)