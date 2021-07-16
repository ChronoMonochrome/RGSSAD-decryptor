"RPG Maker VX ace games decryptor - loosely based on RGSSAD-RGSS2A-RGSS3A Decryptor"

import struct, array
import os, sys

from numba import njit
from numba.typed import List

DEBUG = 0
INT_MAX = 2**31 - 1

iKey = 0xdeadcafe
iKey_iter_current = 0

def debug_print(s):
	__func__ = sys._getframe().f_back.f_code.co_name
	if DEBUG:
		print("%s: %s" %(__func__, s))

def fprint(s):
	__func__ = sys._getframe().f_back.f_code.co_name
	if DEBUG:
		print("%s: %s" %(__func__, s))
	
def catch():
	__func__ = sys._getframe().f_back.f_code.co_name
	exc_type, exc_obj, exc_tb = sys.exc_info()
	print("%s: %s on line %d: %s" %(__func__, exc_type, exc_tb.tb_lineno, exc_obj))

class BinaryReaderEOFException(Exception):
	def __init__(self):
		pass
	def __str__(self):
		return 'Not enough bytes in file to satisfy read request'

class BinaryReader:
	# Map well-known type names into struct format characters.	
	def __init__(self, fileName):
		self.typeNames = {
		'int8'   :'b',
		'uint8'  :'B',
		'int16'  :'h',
		'uint16' :'H',
		'int32'  :'i',
		'uint32' :'I',
		'int64'  :'q',
		'uint64' :'Q',
		'float'  :'f',
		'double' :'d',
		'char'   :'s'}
		self.fileName = fileName
		self.file = open(fileName, 'rb')
		
	def __enter__(self):
		self.file = open(self.fileName, 'rb')
		return self

	def seek(self, offset, from_what = None):
		if not from_what:
			self.file.seek(offset)
		else:
			self.file.seek(offset, from_what)
		
	def tell(self):
		return self.file.tell()
		
	
	def read(self, typeName):
		# TODO: to implement an optimized version
		typeFormat = self.typeNames[typeName.lower()]
		typeSize = struct.calcsize(typeFormat)
		value = self.file.read(typeSize)
		if typeSize != len(value):
			raise BinaryReaderEOFException
		return struct.unpack(typeFormat, value)[0]
		
	def readBytes(self, numBytes):
		return self.file.read(numBytes)
		
	def readCString(self, iLen = 1):
		res = []
		while True:
			c = self.file.read(1)
			if c == "\x00":
				return "".join(res)
			res.append(c)
	def __del__(self):
		self.file.close()
		
	def __exit__(self, exc_type, exc_value, traceback):
		if exc_type is not None:
			raise
		self.file.close()
		return self
		
@njit
def DecryptFileData(iKey, self_fileData):
	fDecrypt = List()
	tempKey = getBytes(iKey)[::-1]
	j = 0

	for b in self_fileData:
		if (j == 4):
			j = 0
			iKey = next_iKey1(iKey)
			tempKey = getBytes(iKey)[::-1]
		fDecrypt.append(b ^ tempKey[j])
		j += 1
	
	return fDecrypt

class File:
	def __init__(self, sPath, iSize, iOffset, iKey):
		# replace backslashes in a file name with a common slash
		self.path = sPath.replace(b"\\", b"/")
		self.size = iSize
		self.offset = iOffset
		self.key = iKey
		self.fileData = b""

	def ReadFileData(self, sRGSSFilePath):
		f = open(sRGSSFilePath, "rb")
		f.seek(self.offset)
		self.fileData = f.read(self.size)

	def extract(self, sRGSSFilePath, targetDir, suppress_output = False):
		"Extract a given file from the given RGSSAD file (sRGSSFilePath) to targetDir"
		
		basedir = os.path.join(targetDir, os.path.split(self.path)[0])
		if not os.path.exists(basedir):
			os.makedirs(basedir)

		if not suppress_output:
			f = open(os.path.join(targetDir, self.path), "wb")

		self.ReadFileData(sRGSSFilePath)
		filedata = DecryptFileData(self.key, self.fileData)

		if not suppress_output:
			f.write(bytes(filedata))
			f.close()
		
def getBytes_reverse(iValue):
	res = []
	nBits = 0
	while nBits >= 0:
		nBits += 8
		res.insert((iValue >> nBits) & 0xff, 4)

	return res
	
@njit
def getBytes(iValue, nBytes = 4):
	res = List()
	nBits = nBytes * 8
	while nBits > 0:
		nBits -= 8
		res.append((iValue >> nBits) & 0xff)
				
	return res

def getUInt32(bData):
	return (bData[0] << 24) + (bData[1] << 16) + (bData[2] << 8) + bData[3]

def get_iKey(iter_curr, iter_max, iKey):
	global iKey_iter_current
	if (iter_curr == iter_max):
		return iKey
	iKey_iter_current += 1
	return get_iKey(iter_curr + 1, iter_max, (iKey * 7 + 3) & 0xffffffff)
	
@njit
def next_iKey1(iKey):
	return (iKey * 7 + 3) & 0xffffffff

def next_iKey(iKey):
		key = get_iKey(iKey_iter_current, iKey_iter_current + 1, iKey)
		return key
		
def GetVersion(test):
	# not implemented
	return -1
	
def ReadRGSSADV1(sPath, iKey, max_count):
	"Returns a list of File objects, inner files in RGSSAD file"
	file_name = "";
	pos = 0;
	files = []
	s = ""
	intlength = 0
	numFiles = 0

	if max_count < 0: max_count = INT_MAX

	with BinaryReader(sPath) as br:
		br.seek(8, 1)

		while (max_count >= numFiles):
			if (numFiles % 100) == 0: print(numFiles)
			length = br.read("uint32")
			length = DecryptIntV1(length, iKey)
			iKey = next_iKey(iKey)
			assert(length < 256)
			pos = br.tell()
			
			debug_print("iKey = 0x%x, pos=%d, length=%d" % (iKey, pos, length)) 
			file_name = DecryptNameV1(br.readBytes(length), length, iKey, pos)
			debug_print(s + str((length, file_name[:length])))

			file_size = br.read("uint32")
			file_size = DecryptIntV1(file_size, iKey)
			iKey = next_iKey(iKey)

			iOffset = br.tell()

			files.append(File(file_name, file_size, iOffset, iKey))
			br.seek(file_size, os.SEEK_CUR)
			numFiles += 1
			if br.tell() >= os.fstat(br.file.fileno()).st_size:
				debug_print(" - end of file, last file_size = %d" % file_size)
				break
		return files
		
# def DecryptNameV3(bNameEnc, key):
	# bNameDec = [];
	# keyBytes = struct.pack("i", key)
	# j = 0

	# for b in bNameEnc:
		# if (j == 4):
			# j = 0
		# bNameDec.append(ord(b) ^ ord(keyBytes[j]))
		# j += 1

	# return array.array("B", bNameDec).tostring()
	
# cdef object DecryptNameV3(bytes bNameEnc, unsigned int length, unsigned int key):
	# cdef char bNameDec[255];
	# cdef char b;
	# cdef int j = 0;
	# cdef int i = 0;

	# for b in bNameEnc:
		# if (j == 4):
			# j = 0
		# bNameDec[i] = b ^ ((key >> 8 * (4 - j)) & 0xff)
		# j += 1
		# i += 0

	# return array.array("B", bNameDec[:length]).tostring()
	
def DecryptNameV3(bNameEnc, length, key):
	bNameDec = [0] * 255;
	b = 0
	j = 0
	i = 0
	keyBytes = struct.pack("i", key)

	for b in bNameEnc:
		if (j == 4):
			j = 0
		#print("b = %d, key_byte = %d" % (b, keyBytes[j]))
		bNameDec[i] = ((b & 0xff) ^ keyBytes[j])
		j += 1
		i += 1

	return array.array("B", bNameDec[:length]).tostring()

keyV3 = 0

def ReadRGSSADV3(sPath, max_count):
	"Returns a list of File objects, inner files in RGSSAD3 file"
	file_name = "";
	pos = 0;
	files = []
	s = ""
	intlength = 0
	numFiles = 0
	
	if max_count < 0: max_count = INT_MAX

	with BinaryReader(sPath) as br:
		br.seek(8, 1)
		
		iKey = br.read("uint32") * 9 + 3

		while (max_count >= numFiles):
			if (numFiles % 100) == 0: print(numFiles)
	
			file_offset = br.read("uint32")
			file_offset = DecryptIntV3(file_offset, iKey)
			
			if (file_offset == 0):
				break

			file_size = br.read("uint32")
			file_size = DecryptIntV3(file_size, iKey)
			
			file_key = br.read("uint32")
			file_key = DecryptIntV3(file_key, iKey)
			
			length = br.read("uint32")
			pos = br.tell()
			#print("length unenc=%d pos = %d" % (length, pos))
			length = DecryptIntV3(length, iKey)
			
			#debug_print("iKey = 0x%x, pos=%d, length=%d" % (iKey, pos, length))

			assert(length < 256)
			file_name = br.readBytes(length)
			#print(file_name)
			file_name = DecryptNameV3(file_name, length, iKey)
			#print(file_name)
			#break
			#debug_print(s + str((length, file_name[:length])))
			files.append(File(file_name, file_size, file_offset, file_key))

			'''files.append(File(file_name, file_size, file_offset, iKey))
			br.seek(file_size, os.SEEK_CUR)
			numFiles += 1
			if br.tell() >= os.fstat(br.file.fileno()).st_size:
				debug_print(" - end of file, last file_size = %d" % file_size)
				break'''
			numFiles += 1
		return files
		
def decrypt_name(sPath, iKey, pos, length):
	with BinaryReader(sPath) as br:
		br.seek(pos, 1)
		
		print(DecryptNameV1(br.readBytes(length), length, iKey, pos))
	
def DecryptIntV1(value, iKey):
	res = value ^ iKey
	
	return res
	
	
def DecryptIntV3(value, iKey):
	res = value ^ iKey
	
	return res

def DecryptNameV1(bNameEnc, length, iKey, pos):
	bNameDec = [0] * 255;
	b = 0
	i = 0

	for b in bNameEnc:
		bNameDec[i] = b ^ (iKey[0] & 0xff)
		debug_print("iKey = 0x%x, pos=%d, %s(%d) = 0x%x ^ 0x%x" % (iKey[0], pos + i, chr(bNameDec[i] % 256), bNameDec[i], b, (iKey[0] & 0xff))) 
		iKey[0] = next_iKey(iKey[0])
		i += 1

	return array.array("B", bNameDec[:length]).tostring()
