

class MR():
	"""
		The Mathematical representation of the model.
		Takes in recovered layers, elements per layer, layer shapes, and connections.
		Properly orders the model by node, identifies what class it belongs to.
	"""
	def __init__(self, layer_names):
		self.weight_count = 0
		self.layers = {}
		for layer in layer_names:
			self.layers[layer] = {'weights': None, 'shape': None}



class PR():
	"""
		The Programmatical representation of the model.
		Takes in recovered code objects, classes, modules.
		Properly groups objects of the same class/modules.sfhbvnvviio
	"""
	def __init__(self):
		# total code object count
		self.ct_total_codeobj = 0

		perfect_match_names = []
		imperfect_match_names = []
		new_codeobj_names = []
		property_objs = []

		fail_marsh = []  # code objects that failed at marshal
		fail_decom = []  # names of code objects that failed at uncompyle6

class CMR():
	"""
		The Combined Model Representation (CMR).
		Combines the MR, and PR for a recovered ML system.
		Associated model nodes with recovered code objects/classes/etc.
	"""

	MAGIC = '420d0d0a'
	FLAGS = '00000000'
	DATETIME = '00000000'
	SIZE = '00000000'
	def __init__(self):
		#Fill in during generation
		self.model_name = None

		self.name = ""