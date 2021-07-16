# cython: language_level=3
"RPG Maker VX ace games decryptor - loosely based on RGSSAD-RGSS2A-RGSS3A Decryptor"


from libc.stdlib cimport malloc, free
from cpython.mem cimport PyMem_Malloc, PyMem_Realloc, PyMem_Free
import struct, array
import os, sys

DEF DEBUG = 0
DEF INT_MAX = 2**31 - 1

cdef unsigned int iKey = 0xdeadcafe
iKey_iter_current = 0

cdef inline void debug_print(str s):
	__func__ = sys._getframe().f_back.f_code.co_name
	IF DEBUG:
		print("%s: %s" %(__func__, s))

cdef inline void fprint(str s):
	__func__ = sys._getframe().f_back.f_code.co_name
	IF DEBUG:
		print("%s: %s" %(__func__, s))
	
cdef inline void catch():
	__func__ = sys._getframe().f_back.f_code.co_name
	exc_type, exc_obj, exc_tb = sys.exc_info()
	print("%s: %s on line %d: %s" %(__func__, exc_type, exc_tb.tb_lineno, exc_obj))

cdef class BinaryReaderEOFException(Exception):
	def __cinit__(self):
		pass
	def __str__(self):
		return 'Not enough bytes in file to satisfy read request'

cdef class BinaryReader:
	# Map well-known type names into struct format characters.
	cdef public dict typeNames;
	cdef public char *fileName;
	cdef public object file;
		
	def __cinit__(self, char *fileName):
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
		
	
	cpdef read(self, typeName):
		# TODO: to implement an optimized version
		typeFormat = self.typeNames[typeName.lower()]
		typeSize = struct.calcsize(typeFormat)
		value = self.file.read(typeSize)
		if typeSize != len(value):
			raise BinaryReaderEOFException
		return struct.unpack(typeFormat, value)[0]
		
	cpdef bytes readBytes(self, unsigned int numBytes):
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
		
from libc.stdlib cimport malloc, free
from libc.string cimport strcpy, memcpy, memset, strlen
from cpython.mem cimport PyMem_Malloc, PyMem_Realloc, PyMem_Free
import numpy

from libc.stdio cimport *

cdef class File:
	cdef object path;
	cdef unsigned int size, offset, key;
	cdef unsigned char *filedata;

	def __cinit__(self, object sPath, unsigned int iSize, unsigned int iOffset, unsigned int iKey):
		# replace backslashes in a file name with a common slash
		self.path = sPath
		self.size = iSize
		self.offset = iOffset
		self.key = iKey
		
	# cdef void readData(self, char *sRGSSFilePath, char **filedata):
		# cdef FILE *f;
		# #ptr_fr = fopen(sRGSSFilePath, "rb")
		# f = fopen(sRGSSFilePath, "rb")
		# #f.seek(self.offset)
		# #memcpy(filedata, <void*>f.read(self.size), self.size)
		# #print(strlen(filedata), self.size)
		# fread(&filedata, 1, self.size, f)
		# #print(self.size, len(filedata))
		# fclose(f)
		# #f.close()
		
	cdef public unsigned char *DecryptFileData(self, char *sRGSSFilePath):
		#cdef char *fDecrypt = <char *> malloc(self.size * sizeof(char));
		cdef unsigned char *fDecrypt = <unsigned char *> PyMem_Malloc(self.size * sizeof(unsigned char));
		cdef unsigned char *filedata = <unsigned char *> PyMem_Malloc(self.size * sizeof(unsigned char));
		
		memset(fDecrypt, 0, self.size * sizeof(unsigned char))
		memset(filedata, 0, self.size * sizeof(unsigned char))
		
		
		#cdef char *tempKey = <char *> PyMem_Malloc(4 * sizeof(char));
		#fDecrypt = numpy.zeros(self.size)
		#cdef unsigned char fDecrypt[65535];
		
		cdef unsigned int iKey = self.key;
		#print("before getBytes")
		cdef list tempKey;
		tempKey = getBytes(iKey)
		#return "test"
		#print("after getBytes = %s" % str(tempKey))
		#strcpy(tempKey, getBytes(iKey));
		cdef int i, j = 0;
		cdef unsigned char b;

		cdef FILE* cfile
		cfile = fopen(sRGSSFilePath, "rb")
		fseek(cfile, self.offset, 1)
		fread(filedata, 1, self.size, cfile)
		fclose(cfile)
		
		#self.readData(sRGSSFilePath, &filedata)
		#print(filedata)

		for i, b in enumerate(filedata):
			if (j == 4):
				j = 0
				iKey = next_iKey(iKey)
				#print("before getBytes (%d)" % i)
				tempKey = getBytes(iKey)
				#print("after getBytes (%d) = %s" % (i, str(tempKey)))
			#fDecrypt[i] = b ^ tempKey[j]
			fDecrypt[i] = b
			j += 1
			
		#self.filedata = fDecrypt
		self.filedata = fDecrypt
		#cdef FILE* cfile
		cfile = fopen(self.path, "wb")
		fwrite(<void*>self.filedata, 1, self.size, cfile)
		fclose(cfile)
		#PyMem_Free(filedata)
		#PyMem_Free(tempKey)
		
		return fDecrypt

	cpdef public void extract(self, char *sRGSSFilePath, char *targetDir, suppress_output):
		"Extract a given file from the given RGSSAD file (sRGSSFilePath) to targetDir"
		
		basedir = os.path.join(targetDir, os.path.split(self.path)[0])
		if not os.path.exists(basedir):
			os.makedirs(basedir)

		#if not suppress_output:
		#	f = open(os.path.join(targetDir, self.path), "wb")

		debug_print("before DecryptFileData")

		cdef unsigned char *filedata = self.DecryptFileData(sRGSSFilePath)
		return
		#output = array.array("B", filedata).tobytes()
		#print(filedata)
		cdef FILE* cfile
		cfile = fopen(self.path, "wb")
		fwrite(<void*>self.filedata, 1, self.size, cfile)
		fclose(cfile)

		debug_print("write data")
		
		#if not suppress_output:
		#f.write(output)
		#f.close()
		#free(filedata)
		debug_print("free memmory")
		PyMem_Free(self.filedata)

def getBytes_reverse(iValue):
	res = [];
	nBits = 0
	while nBits >= 0:
		nBits += 8
		res.insert((iValue >> nBits) & 0xff, 4)

	return res

def getBytes(iValue, nBytes = 4):
	res = [0] * 4;
	nBits = nBytes * 8
	
	for i in range(3, -1, -1):
		nBits -= 8
		res[i] = ((iValue >> nBits) & 0xff)
				
	return res

cpdef public unsigned int getUInt32(char *bData):
	return (bData[0] << 24) + (bData[1] << 16) + (bData[2] << 8) + bData[3]

cpdef public unsigned int get_iKey(unsigned int iter_curr, 
			unsigned int iter_max, unsigned int iKey):
	global iKey_iter_current
	if (iter_curr == iter_max):
		return iKey
	iKey_iter_current += 1
	return get_iKey(iter_curr + 1, iter_max, (iKey * 7 + 3) & 0xffffffff)

cpdef public unsigned int next_iKey(unsigned int iKey):
		key = get_iKey(iKey_iter_current, iKey_iter_current + 1, iKey)
		return key
		
cpdef public int GetVersion(int test):
	# not implemented
	return -1
	
cpdef public object ReadRGSSADV1(char *sPath, unsigned int iKey, int max_count):
	"Returns a list of File objects, inner files in RGSSAD file"
	cdef object file_name;
	cdef int pos;
	files = []
	s = ""
	cdef unsigned intlength = 0
	cdef int numFiles = 0
	
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
			file_name = DecryptNameV1(br.readBytes(length), length,  &iKey, pos)
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

cdef object DecryptNameV3(bytes bNameEnc, unsigned int length, unsigned int key):
	cdef unsigned char bNameDec[255];
	cdef char b;
	cdef int j = 0;
	cdef int i = 0;
	keyBytes = struct.pack("i", key)

	for b in bNameEnc:
		if (j == 4):
			j = 0
		#print("b = %d, key_byte = %d" % (b, keyBytes[j]))
		bNameDec[i] = ((b & 0xff) ^ keyBytes[j])
		j += 1
		i += 1

	return array.array("B", bNameDec[:length]).tobytes()

cdef unsigned int keyV3 = 0

cpdef public object ReadRGSSADV3(char *sPath, int max_count):
	"Returns a list of File objects, inner files in RGSSAD3 file"
	cdef object file_name;
	cdef int pos;
	files = []
	s = ""
	cdef unsigned intlength = 0
	cdef int numFiles = 0
	
	if max_count < 0: max_count = INT_MAX

	with BinaryReader(sPath) as br:
		br.seek(8, 1)
		
		iKey = br.read("uint32") * 9 + 3

		while (max_count >= numFiles):
			#if (numFiles % 100) == 0: print(numFiles)
	
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
		
cpdef decrypt_name(char *sPath, unsigned int iKey, unsigned int pos, unsigned int length):
	with BinaryReader(sPath) as br:
		br.seek(pos, 1)
		
		print(DecryptNameV1(br.readBytes(length), length,  &iKey, pos))
	
cpdef public inline unsigned int DecryptIntV1(unsigned int value, iKey):
	res = value ^ iKey
	
	return res
	
	
cpdef public inline unsigned int DecryptIntV3(unsigned int value, iKey):
	res = value ^ iKey
	
	return res

cdef object DecryptNameV1(bytes bNameEnc, unsigned int length, unsigned int *iKey, unsigned int pos):
	cdef char bNameDec[255];
	cdef char b;
	cdef int i = 0; 

	for b in bNameEnc:
		bNameDec[i] = b ^ (iKey[0] & 0xff)
		debug_print("iKey = 0x%x, pos=%d, %s(%d) = 0x%x ^ 0x%x" % (iKey[0], pos + i, chr(bNameDec[i] % 256), bNameDec[i], b, (iKey[0] & 0xff))) 
		iKey[0] = next_iKey(iKey[0])
		i += 1

	return array.array("B", bNameDec[:length]).tostring()
