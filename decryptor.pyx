"RPG Maker VX ace games decryptor - loosely based on RGSSAD-RGSS2A-RGSS3A Decryptor"


from libc.stdlib cimport malloc, free
from cpython.mem cimport PyMem_Malloc, PyMem_Realloc, PyMem_Free
import struct, array
import os, sys

DEF DEBUG = 0
DEF INT_MAX = 2**32 - 1

#FILE_Name, FILE_Size, FILE_Offset, FILE_Key = [], [], [], []
#FILES = []
cdef unsigned int iKey = 0xdeadcafe
iKey_iter_current = 0

cdef inline void debug_print(str s):
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
		#while True:
		#	c = self.file.read(nBufSize).split(b"\x00")[0]
		#return self.file.read(numBytes)[]
	
	def __del__(self):
		self.file.close()
		
	def __exit__(self, exc_type, exc_value, traceback):
		if exc_type is not None:
			raise
			#print exc_type, exc_value, traceback
		self.file.close()
		return self

class File:
	def __init__(self, sPath, iSize, iOffset, iKey):
		self.path = sPath
		self.size = iSize
		self.offset = iOffset
		self.key = iKey
		
	def DecryptFileData(self, sRGSSFilePath):
		fDecrypt = []
		iKey = self.key
		tempKey = getBytes(iKey)[::-1]
		#tempKey = getBytes_reverse(iKey)
		j = 0
		
		f = open(sRGSSFilePath, "rb")
		f.seek(self.offset)
		bFileData = f.read(self.size)
		f.close()
		for b in bFileData:
			if (j == 4):
				j = 0
				iKey = next_iKey(iKey)
				tempKey = getBytes(iKey)[::-1]
				#tempKey = getBytes_reverse(iKey)
			fDecrypt.append(ord(b) ^ tempKey[j])
			j += 1
		
		return fDecrypt

	def extract(self, sRGSSFilePath, targetDir):
		"Extract a given file from the given RGSSAD file (sRGSSFilePath) to targetDir"
		try:
			basedir = targetDir + "/" + os.path.split(self.path)[0]
			if not os.path.exists(basedir):
				os.makedirs(basedir)
		except:
			pass
		f = open(targetDir + "/" + self.path, "wb")
		try:
			filedata = self.DecryptFileData(sRGSSFilePath)
			f.write(b"".join([chr(b % 256) for b in filedata]))
		finally:
			f.close()
		
def getBytes_reverse(iValue):
	res = []
	nBits = 0
	while nBits >= 0:
		nBits += 8
		res.insert((iValue >> nBits) & 0xff, 4)

	return res
	
def getBytes(iValue, nBytes = 4):
	res = []
	nBits = nBytes * 8
	while nBits > 0:
		nBits -= 8
		res.append((iValue >> nBits) & 0xff)
				
	return res

#cpdef public getBytes_reverse(unsigned int iValue):
#	cdef char res[4];
#	cdef size_t nBits = 32;
#	cdef unsigned int i = 3;
#	while i != 0:
#		nBits -= 8
#		res[i] = (iValue >> nBits) & 0xff
#		i -= 1
#				
#	return res
	
cpdef public unsigned int getUInt32(char *bData):
	return (bData[0] << 24) + (bData[1] << 16) + (bData[2] << 8) + bData[3]
		
#class

cpdef public unsigned int get_iKey(unsigned int iter_curr, 
								unsigned int iter_max, unsigned int iKey):
	global iKey_iter_current
	if (iter_curr == iter_max):
		return iKey
	iKey_iter_current += 1
	return get_iKey(iter_curr + 1, iter_max, (iKey * 7 + 3) & 0xffffffff)

cpdef public unsigned int next_iKey(unsigned int iKey):
		key = get_iKey(iKey_iter_current, iKey_iter_current + 1, iKey)
		#print("iter_count: %d, key=0x%08x" % (iKey_iter_current, key))
		return key
		
cpdef public int GetVersion(int test):
	#cdef int res = -1
	"""with BinaryReader(sPath) as br:
		sign = br.readCString(7)
		if sign == "RGSSAD":
			res = br.read("int8")
		else: print "not found"""
	return -1
	
cpdef public object ReadRGSSADV1(char *sPath, unsigned int iKey, int max_count):
	"Returns a list of File objects, inner files in RGSSAD file"
	cdef object file_name;
	cdef int pos;
	files = []
	s = ""
	cdef unsigned intlength = 0, numFiles = 0
	
	if max_count < 0: max_count = INT_MAX
	with BinaryReader(sPath) as br:
		br.seek(8, -1)

		while (max_count >= numFiles):
			if (numFiles % 100) == 0: print(numFiles)
			length = br.read("uint32")
			length = DecryptIntV1(length, iKey)
			iKey = next_iKey(iKey)
			assert(length < 256)
			#if (length > 255): 
			#	debug_print(" - bug, length > 255")
			#	break
			#s = hex(iKey)
			pos = br.tell()
			
			debug_print("iKey = 0x%x, pos=%d, length=%d" % (iKey, pos, length)) 
			file_name = DecryptNameV1(br.readBytes(length), length,  &iKey, pos)
			debug_print(s + str((length, file_name[:length])))
			#FILE_Name.append(file_name)
			file_size = br.read("uint32")
			file_size = DecryptIntV1(file_size, iKey)
			iKey = next_iKey(iKey)
			#FILE_Size.append(file_size)
			#FILE_Offset.append(br.tell())
			iOffset = br.tell()
			#FILE_Key.append(iKey)
			files.append(File(file_name, file_size, iOffset, iKey))
			br.seek(file_size, os.SEEK_CUR)
			numFiles += 1
			if br.tell() >= os.fstat(br.file.fileno()).st_size:
				debug_print(" - end of file, last file_size = %d" % file_size)
				break
		return files
		
cpdef decrypt_name(char *sPath, unsigned int iKey, unsigned int pos, unsigned int length):
	with BinaryReader(sPath) as br:
		br.seek(pos, -1)
		
		print DecryptNameV1(br.readBytes(length), length,  &iKey, pos)
		
cpdef public inline unsigned int DecryptIntV1(unsigned int value, iKey):
	res = value ^ iKey
	
	return res
	
cdef object DecryptNameV1(bytes bNameEnc, unsigned int length, unsigned int *iKey, unsigned int pos):
	#res = ""
	#endPos = len(bNameEnc) - 1
	#name_dec = [None] * endPos
	cdef char bNameDec[255];
	cdef char b;
	cdef int i = 0; 
	#cdef object res_arr;
	
	for b in bNameEnc:
		bNameDec[i] = b ^ (iKey[0] & 0xff)
		debug_print("iKey = 0x%x, pos=%d, %s(%d) = 0x%x ^ 0x%x" % (iKey[0], pos + i, chr(bNameDec[i] % 256), bNameDec[i], b, (iKey[0] & 0xff))) 
		#print "%s = %d ^ %d" % (bNameDec[i], b,(iKey[0] & 0xff))
		iKey[0] = next_iKey(iKey[0])
		i += 1
	#print bNameDec[:length], length
	#return bNameDec[:length]
	return array.array("B", bNameDec[:length]).tostring()