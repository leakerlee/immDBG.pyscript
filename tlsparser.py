#!/usr/bin/env python

__VERSION__ = '1.0'

import os
import immlib
import pefile

class FileNotExistError(Exception):
	def __init__(self):
		self.message = "file is not existent"

class ObjectNotInitError(Exception):
	def __init__(self):
		self.message = "object is not initialized"

class TLSParser:

	def __init__(self, fileName):
		if(os.path.isfile(fileName)):
			self.fileName = fileName
			self.callback_functions = []
			self.pe = pefile.PE(fileName)
		else:
			raise FileNotExistError

	def parse(self):
		if(isinstance(self.pe, pefile.PE)):
			idx = 0
			self.callback_functions = []
			callback_array_rva = self.pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - self.pe.OPTIONAL_HEADER.ImageBase
			while self.pe.get_dword_from_data(self.pe.get_data(callback_array_rva + 4 * idx, 4), 0):
				self.callback_functions.append(self.pe.get_dword_from_data(self.pe.get_data(callback_array_rva + 4 * idx, 4), 0))
				idx += 1
			return self.callback_functions
		else:
			raise ObjectNotInitError
