from volatility3.framework.symbols import intermed
from volatility3.framework import objects, constants

import struct
import types
import marshal
import pdb

class Python_3_7_13_IntermedSymbols(intermed.IntermediateSymbolTable):
    """
    Symbol table for Python types.

    - Developed for PyTorch 3.7.13 on x64 architectures
    - Operability with other versions is not guaranteed
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.set_type_class("PyGC_Head", PyGC_Head)                  # https://github.com/python/cpython/blob/v3.10.6/Include/internal/pycore_gc.h#L20
        self.set_type_class("PyObject", PyObject)                    # https://github.com/python/cpython/blob/v3.10.6/Include/object.h#L109
        self.set_type_class("PyTypeObject", PyTypeObject)            # https://github.com/python/cpython/blob/v3.7.13/Doc/includes/typestruct.h
        self.set_type_class("PyDictObject", PyDictObject)            # https://github.com/python/cpython/blob/v3.10.6/Include/cpython/dictobject.h#L28
        self.set_type_class("PyDictKeysObject", PyDictKeysObject)    # https://github.com/python/cpython/blob/main/Include/internal/pycore_dict.h#L72
        self.set_type_class("PyDictKeyEntry", PyDictKeyEntry)        # https://github.com/python/cpython/blob/main/Include/internal/pycore_dict.h#L28
        self.set_type_class("PyASCIIObject", PyASCIIObject)          # https://github.com/python/cpython/blob/3.10/Include/cpython/unicodeobject.h#L219
        self.set_type_class("PyBoolObject", PyBoolObject)            # https://github.com/python/cpython/blob/v3.10.6/Include/boolobject.h#L22
        self.set_type_class("PyLongObject", PyLongObject)            # https://github.com/python/cpython/blob/v3.10.6/Include/longintrepr.h#L85
        self.set_type_class("PyTupleObject", PyTupleObject)          # https://github.com/python/cpython/blob/v3.10.6/Include/cpython/tupleobject.h#L11
        self.set_type_class("PyListObject", PyListObject)            # https://github.com/python/cpython/blob/v3.10.6/Include/cpython/listobject.h#L22
        self.set_type_class("PyBytesObject", PyBytesObject)          # https://github.com/python/cpython/blob/v3.10.6/Include/cpython/bytesobject.h#L15
        self.set_type_class("PyFloatObject", PyFloatObject)          # https://github.com/python/cpython/blob/main/Include/cpython/floatobject.h#L8


class PyGC_Head(objects.StructType):
    pass


class PyObject(objects.StructType):
    def get_type(self, name):
        """
        Determines the Python object type given a type name.
        """
        types = {
            'NoneType'      : 'None',
            'str'           : 'PyASCIIObject',
            'int'           : 'PyLongObject',
            'bool'          : 'PyBoolObject',
            'tuple'         : 'PyTupleObject',
            'list'          : 'PyListObject',
            'bytes'         : 'PyBytesObject',
            'Parameter'     : 'PyInstanceObject',
            'dict'          : 'PyDictObject',
            'float'         : 'PyFloatObject',
            'ellipsis'      : 'Ellipsis',
            'type'          : 'PyTypeObject',
            'collections.OrderedDict' : 'PyDictObject',
        }
        return types.get(name, 'PyObject')
    
    def get_value(self, cur_depth = None, max_depth = None):
        """
        Retrieves the object's value according to it's type.
        
        - dict objects will return a Python dict
        - primitive objects will return their raw value
        - other objects will return the general object
        """
        type = self.get_type(self.ob_type.dereference().get_name())
        if (type == 'PyObject'):
            if (self.ob_type.dereference().tp_dictoffset == 16):
                type = 'PyInstanceObject'

        if type == 'None':
            return None
        elif type == 'Ellipsis':
            return Ellipsis

        symbol_table_name = self.get_symbol_table_name()
        obj = self._context.object(
            object_type=symbol_table_name + constants.BANG + type,
            layer_name=self.vol.layer_name,
            offset=self.vol.offset,
        )
        if type == 'PyDictObject':
            return obj.get_dict(cur_depth)
        elif type == 'PyInstanceObject' or type == 'PyObject' or type == 'PyTypeObject':
            return obj
        else:
            try:
                val = obj.get_value()
                return val
            except Exception as error:
                print("Type: not implemented or exception thrown! - " + str(type) + "\n")
                print("An exception occurred: ", error)
                return obj

class PyTypeObject(objects.StructType):
    def get_name(self):
        """
        Gets the object type name.
        """
        curr_layer = self._context.layers[self.vol.layer_name]
        return hex_bytes_to_text(curr_layer.read(self.tp_name, 64, pad=False))
    
    def get_dict(self):
        """
        Gets the dict of the type/class.

        - Note: classes (the blueprint, not the instance) are just PyTypeObjects
        """
        tp_dict = self.tp_dict.dereference().get_dict()
        return tp_dict
    

class PyDictObject(objects.StructType):
    def create_dict(self, keys, values):
        """
        Creates a Python dictionary given lists of keys and values.
        """
        if not keys or not values:
            return {}
        if len(keys) != len(values):
            print("WARNING: Number of keys does not match number of values for this Dict. See below!!!")
            print("Keys: " + str(keys))
            print("Values: " + str(values))
            print()
        
        dict = {}
        for i in range(len(values)):
            dict[keys[i]] = values[i]

        return dict
    
    def get_values(self):
        """
        Retrieves the addresses of values of the dict from memory.
        """
        curr_layer = self._context.layers[self.vol.layer_name]
        addresses = []
        value_ptr = self.ma_values
        for i in range(self.ma_used):
            addr = int.from_bytes(
                curr_layer.read(value_ptr, 8, pad=False),
                byteorder='little'
            )
            addresses.append(addr)
            value_ptr += 8

        return addresses
    
    def get_dict(self, cur_depth = 0, max_depth = None):
        """
        Extracts the dictionary/map from memory.
        
        Returns:
            A dictionary: {name : object}
        """
        if self.ma_values == 0:
            keys, value_addrs = self.ma_keys.dereference().get_keysandvalues()
        else:
            keys = self.ma_keys.dereference().get_keys()
            value_addrs = self.get_values()
        values = create_objects(self.get_symbol_table_name(), self._context, self.vol.layer_name, value_addrs)
        return self.create_dict(keys, values)


class PyDictKeysObject(objects.StructType):
    def get_indices_size(self):
        """
        Returns the size (bytes) of the dynamically sized dk_indices array.

        """
        dk_size = self.dk_log2_size
        if (dk_size <= 0xff):
            size = 1
        elif (dk_size <= 0xffff):
            size = 2
        elif (dk_size <= 0xffffffff):
            size = 4
        else:
            size = 8

        return dk_size * size
    
    def get_base_address(self):
        """
        Returns the base address of the key entries array.
        """
        symbol_table_name = self.get_symbol_table_name()

        indices_offset = self._context.symbol_space.get_type(
            symbol_table_name + constants.BANG + 'PyDictKeysObject'
        ).relative_child_offset('dk_indices')

        dk_indices_size = self.get_indices_size()
        return self.vol.offset + indices_offset + dk_indices_size
    
    def get_keysandvalues(self):
        """
        Retrieves keys and values of the combined dict.
        """
        symbol_table_name = self.get_symbol_table_name()
        keys = []
        values = []
        addr = self.get_base_address()

        for i in range(self.dk_nentries):
            key_entry = self._context.object(
                object_type=symbol_table_name + constants.BANG + 'PyDictKeyEntry',
                layer_name=self.vol.layer_name,
                offset=addr,
            )
            addr += 24
            if (key_entry.me_key == 0):
                #print("Invalid key")
                continue
            keys.append(key_entry.get_key())
            values.append(key_entry.me_value)

        return (keys, values)
    
    def get_keys(self):
        """
        Retrieves keys of the dict (values are separate).
        """
        symbol_table_name = self.get_symbol_table_name()
        keys = []
        addr = self.get_base_address()

        for i in range(self.dk_nentries):
            key_entry = self._context.object(
                object_type=symbol_table_name + constants.BANG + 'PyDictKeyEntry',
                layer_name=self.vol.layer_name,
                offset=addr,
            )

            if (key_entry.me_key == 0):
                print("Invalid key")
                continue
            keys.append(key_entry.get_key())
            addr += 24

        return keys


class PyDictKeyEntry(objects.StructType):
    def get_key(self):
        """
        Retrieves the value of the dict key (ASCII str).
        """
        return self.me_key.dereference().get_value()
    

class PyASCIIObject(objects.StructType):
    def get_value(self):
        """
        Gets the raw ASCII string value.

        https://github.com/python/cpython/blob/v3.7.13/Include/unicodeobject.h#L331
        """
        COMPACT = (self.state >> 5) & 1
        ASCII = (self.state >> 6) & 1
        KIND = (self.state >> 2) & 0b111
        curr_layer = self._context.layers[self.vol.layer_name]

        if ASCII and COMPACT:                               # PyASCIIObject
            string = curr_layer.read(self.vol.offset + self.vol.size, self.length, pad=False)
            try:
                dec = string.decode("utf-8")
            except:
                print(f'Failed to decode: {string}')
                dec = ''
        elif not ASCII and COMPACT:                         # PyCompactUnicodeObject
            string = curr_layer.read(self.vol.offset + 72, self.length * KIND, pad=False)
            if KIND == 1:
                dec = string.decode("utf-8")
            elif KIND == 2:
                dec = string.decode("utf-16")
            elif KIND == 4:
                dec = string.decode("ISO-8859-1")       # this should be utf-32 according to Python spec
                                                        # had to change for the visdrone image
                                                        # was getting error at: dec = string.decode("utf-32")
                                                        # UnicodeDecodeError: 'utf-32-le' codec can't decode bytes in position 0-3: code point not in range(0x110000)
            else:
                print(f"ValueError: PyASCIIObject KIND field is invalid: {KIND}")
                dec = ''
                #raise ValueError(f"PyASCIIObject KIND field is invalid: {KIND}")
        else:
            print(f"Complex str type found at {hex(self.vol.offset)}. COMPACT = "
                + str((self.state >> 5) & 1) + ", ASCII = " + str((self.state >> 6) & 1))
            dec = ''
            #raise TypeError(f"Complex str type found at {hex(self.vol.offset)}. COMPACT = "
            #    + str((self.state >> 5) & 1) + ", ASCII = " + str((self.state >> 6) & 1))
        
        return dec


class PyBoolObject(objects.StructType):
    def get_value(self):
        """
        Gets the raw boolean value.
        """
        return bool(self.ob_digit)
    

class PyLongObject(objects.StructType):
    def get_sign(self, num):
        """
        Returns the sign of the argument.
        """
        return -1 if num < 0 else int(bool(num))
    
    def get_value(self):
        """
        Gets the raw integer value.
        """
        sign = self.get_sign(self.VAR_HEAD.ob_size)
        if sign == 0:
            return 0
        
        symbol_table_name = self.get_symbol_table_name()
        curr_layer = self._context.layers[self.vol.layer_name]
        addr = self.vol.offset + self._context.symbol_space.get_type(
                symbol_table_name + constants.BANG + 'PyVarObject').size
        value = int.from_bytes(
            curr_layer.read(addr, 4, pad=False),
            byteorder='little'
        )

        return sign * value


class PyTupleObject(objects.StructType):
    def get_value(self):
        """
        Retrieves the variable-length Python tuple.
        """
        symbol_table_name = self.get_symbol_table_name()
        curr_layer = self._context.layers[self.vol.layer_name]
        data_offset = self._context.symbol_space.get_type(
            symbol_table_name + constants.BANG + 'PyTupleObject'
        ).relative_child_offset('ob_item')

        addresses = []
        for i in range(self.VAR_HEAD.ob_size):
            addr = int.from_bytes(
                curr_layer.read(self.vol.offset + data_offset + i*8, 8, pad=False),
                byteorder='little'
            )
            addresses.append(addr)

        return tuple(create_objects(symbol_table_name, self._context, self.vol.layer_name, addresses))
    

class PyListObject(objects.StructType):
    def get_value(self):
        """
        Retrieves the variable-length Python list.
        """
        symbol_table_name = self.get_symbol_table_name()
        curr_layer = self._context.layers[self.vol.layer_name]
        data_offset = self.ob_item

        addresses = []
        for i in range(self.VAR_HEAD.ob_size):
            addr = int.from_bytes(
                curr_layer.read(data_offset + i*8, 8, pad=False),
                byteorder='little'
            )
            addresses.append(addr)

        return list(create_objects(symbol_table_name, self._context, self.vol.layer_name, addresses))
class PyBytesObject(objects.StructType):
    def get_value(self):
        """
        Gets the raw bytes.

        """
        symbol_table_name = self.get_symbol_table_name()
        curr_layer = self._context.layers[self.vol.layer_name]
        data_offset = self._context.symbol_space.get_type(
            symbol_table_name + constants.BANG + 'PyBytesObject'
        ).relative_child_offset('ob_sval')

        return curr_layer.read(self.vol.offset + data_offset, self.ob_size, pad=False)
    

class PyFloatObject(objects.StructType):
    def get_value(self):
        """
        Gets the single raw float.

        """
        symbol_table_name = self.get_symbol_table_name()
        curr_layer = self._context.layers[self.vol.layer_name]
        data_offset = self._context.symbol_space.get_type(
            symbol_table_name + constants.BANG + 'PyFloatObject'
        ).relative_child_offset('ob_fval')

        [item] = struct.unpack('<d', curr_layer.read(self.vol.offset + data_offset, 8))
        return item


def create_objects(symbol_table_name, context, layer_name, addresses):
    """
    Given a list of addresses, create a list of Python objects.
    """
    arr = []

    for addr in addresses:
        obj = context.object(
            object_type=symbol_table_name + constants.BANG + 'PyObject',
            layer_name=layer_name,
            offset=addr,
        )
        arr.append(obj.get_value())

    return arr


def hex_bytes_to_text(value):
    """Renders HexBytes as text.

    Args:
        value: A series of bytes

    Returns:
        The ASCII representation of the hexadecimal bytes
    """
    if not isinstance(value, bytes):
        raise TypeError(f"hex_bytes_as_text takes bytes not: {type(value)}")
    
    ascii = []
    count = 0
    output = ""

    for byte in value:
        if (byte != 0x00):
            ascii.append(chr(byte))
        elif (count < 2):
            return "Error: no name found"
        else:
            output += "".join(ascii[count - (count % 8) : count + 1])
            return output
        
        if (count % 8) == 7:
            output += "".join(ascii[count - 7 : count + 1])
        count += 1

    return output