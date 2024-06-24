from volatility3.framework.symbols import intermed
from volatility3.framework import objects, constants

import struct


class PyTorch_1_11_IntermedSymbols(intermed.IntermediateSymbolTable):
    """
    Symbol table for PyTorch types.

    - Developed for PyTorch 1.11.0 on x64 architectures
    - Operability with other versions is not guaranteed
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.set_type_class("Parameter", Parameter)
        self.set_type_class("Tensor", Tensor)
        self.set_type_class("Storage", Storage)
    

class Tensor(objects.StructType):
    def get_type(self):
        """Determines the type of data stored in this Tensor.

        Returns:
            A tuple: (type name, format character)
        """
        type_map = {
            0 : ('byte', 'B'),
            1 : ('char', 'b'),
            2 : ('short', 'h'),
            3 : ('int', 'i'),
            4 : ('long', 'q'),
            5 : ('half', 'l'),
            6 : ('float', 'f'),
            7 : ('double', 'd')
        }
        return ('float', 'f')      # type_map[self.data_type]
    
    def sizeof(self, type):
        """Determines the size (bytes) of a data type.


        Args:
            type: name of the type

        Returns:
            The type's size in bytes.
        """
        size_map = {
            'byte'   : 1,
            'char'   : 1,
            'short'  : 2,
            'int'    : 4,
            'long'   : 8,
            'half'   : 4,
            'float'  : 4,
            'double' : 8
        }
        return size_map[type]
    
    def shape(self):
        """Acquires.

        Returns:
            A.
        """
        curr_layer = self._context.layers[self.vol.layer_name]
        symbol_table_name = self.get_symbol_table_name()

        shape_offset = self._context.symbol_space.get_type(
            symbol_table_name + constants.BANG + 'Tensor'
        ).relative_child_offset('shape')

        dims = self.num_dims
        ret = []
        for i in range(dims):
            curr_offset = self.vol.offset + shape_offset + (8 * i)
            [shape] = struct.unpack('<q', curr_layer.read(curr_offset, 8))
            ret.insert(0, int(shape))
        return ret

    def num_elements(self):
        """Acquires.

        Returns:
            A.
        """
        l = self.shape()
        tot = 1
        for x in l:
            tot *= x
        return tot

    def get_data(self):
        """Acquires this Tensor's data with respect to the data type.

        Returns:
            A list of Tensor values.
        """
        curr_layer = self._context.layers[self.vol.layer_name]
        data_type = ('float', 'f') #self.get_type()
        data_size = self.sizeof(data_type[0])
        num_elements = self.num_elements()

        tensor_data = []
        curr_offset = self.storage
        for i in range(num_elements):
            [item] = struct.unpack('<' + data_type[1], curr_layer.read(curr_offset, data_size))
            tensor_data.append(item)
            curr_offset += data_size
            
        return tensor_data

    def get_data_ptr(self):
        """Acquires this Tensor's data with respect to the data type.

        Returns:
            A list of Tensor values.
        """
        return self.storage.dereference().data


class Parameter(objects.StructType):
    pass


class Storage(objects.StructType):
    pass