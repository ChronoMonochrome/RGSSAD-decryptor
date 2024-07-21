/*
 * MIT License
 *
 * Copyright (c) 2024 Victor Shilin
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <algorithm>
#include <array>
#include <cstring>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <unordered_map>

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#define DEBUG 0
#define VERBOSE_DEBUG 0

unsigned int iKey = 0xdeadcafe;
unsigned int iKey_iter_current = 0;

void debug_print(const std::string &s) {
#if DEBUG
    std::cout << s << std::endl;
#endif
}

std::vector<unsigned char> getBytes(unsigned int iValue, unsigned int nBytes = 4) {
    std::vector<unsigned char> res(nBytes);
    for (unsigned int i = 0; i < nBytes; ++i) {
        res[i] = (iValue >> ((nBytes - 1 - i) * 8)) & 0xff;
    }
    return res;
}

unsigned int get_iKey(unsigned int iter_curr, unsigned int iter_max, unsigned int iKey) {
    if (iter_curr == iter_max) {
        return iKey;
    }
    iKey_iter_current++; // Increment the global iteration counter
    return get_iKey(iter_curr + 1, iter_max, (iKey * 7 + 3) & 0xffffffff);
}

unsigned int next_iKey(unsigned int iKey) {
    // Get the new key by passing the current global iteration value
    return get_iKey(iKey_iter_current, iKey_iter_current + 1, iKey);
}

class BinaryReaderEOFException : public std::runtime_error {
public:
    BinaryReaderEOFException() : std::runtime_error("Not enough bytes in file to satisfy read request") {}
};

class BinaryReader {
public:
    BinaryReader(const std::string &fileName) : fileName(fileName), file(fileName, std::ios::binary) {
        if (!file) throw std::runtime_error("Unable to open file: " + fileName);
        typeNames = {
            {"int8", 'b'},
            {"uint8", 'B'},
            {"int16", 'h'},
            {"uint16", 'H'},
            {"int32", 'i'},
            {"uint32", 'I'},
            {"int64", 'q'},
            {"uint64", 'Q'},
            {"float", 'f'},
            {"double", 'd'},
            {"char", 's'}
        };
    }

    ~BinaryReader() {
        if (file.is_open()) {
            file.close();
        }
    }

    void seek(std::streamoff offset, std::ios_base::seekdir way = std::ios::beg) {
        file.seekg(offset, way);
    }

    // Function to return the size of the file
    std::streamoff size() {
        std::streamoff current_position = file.tellg();
        file.seekg(0, std::ios::end); // Move to the end
        std::streamoff length = file.tellg(); // Get the size
        file.seekg(current_position); // Restore the current position
        return length;
    }

    std::streamoff tell() {
        return file.tellg();
    }

    template <typename T>
    T read(const std::string &typeName) {
        size_t typeSize = sizeof(T);
        std::vector<char> buffer(typeSize);

        file.read(buffer.data(), typeSize);
        if (static_cast<size_t>(file.gcount()) != typeSize) {
            throw BinaryReaderEOFException();
        }

        T value;
        std::memcpy(&value, buffer.data(), typeSize);
        return value;
    }

    std::vector<char> readBytes(unsigned int numBytes) {
        std::vector<char> buffer(numBytes);
        file.read(buffer.data(), numBytes);
        return buffer;
    }

    std::string readCString(unsigned int iLen = 1) {
        std::string result;
        char c;
        while (file.read(&c, 1) && c != '\0') {
            result += c;
        }
        return result;
    }

private:
    std::string fileName;
    std::ifstream file;
    std::unordered_map<std::string, char> typeNames;
};

bool CreateDirectoryRecursive(std::string const &dirName, std::error_code &err)
{
    err.clear();
    if (!std::filesystem::create_directories(dirName, err))
    {
        if (std::filesystem::exists(dirName))
        {
            // The folder already exists:
            err.clear();
            return true;
        }
        return false;
    }
    return true;
}

class File {
public:
    File(const std::string &sPath, unsigned int iSize, unsigned int iOffset, unsigned int iKey)
        : path(sPath), size(iSize), offset(iOffset), key(iKey) {
        // Replace backslashes in file name with forward slashes
        std::replace(path.begin(), path.end(), '\\', '/');
    }

    // Decrypts the file data from the RGSSAD file
    std::vector<unsigned char> DecryptFileData(const std::string &sRGSSFilePath) {
        std::vector<unsigned char> fDecrypt;
        unsigned int iKey = key; // Start with the initial key
        std::vector<unsigned char> tempKey = getBytes(iKey);
        std::reverse(tempKey.begin(), tempKey.end());
        unsigned int j = 0;

        // Open the RGSSAD file
        std::ifstream f(sRGSSFilePath, std::ios::binary);
        if (!f) throw std::runtime_error("Unable to open file: " + sRGSSFilePath);

        f.seekg(offset);
        std::vector<unsigned char> bFileData(size);
        f.read(reinterpret_cast<char*>(bFileData.data()), size);

        for (unsigned char b : bFileData) {
            if (j == 4) {
                j = 0;
                iKey = next_iKey(iKey);
                tempKey = getBytes(iKey);
                std::reverse(tempKey.begin(), tempKey.end());
            }
#if DEBUG
            std::cout << "iKey=" << std::hex << iKey << std::dec << std::endl;
#endif
            fDecrypt.push_back(b ^ tempKey[j]);
            j++;
        }

        return fDecrypt;
    }

    // Extracts the decrypted file to the given target directory
    void extract(const std::string &sRGSSFilePath, const std::string &targetDir) {
        // Create the target directory path
        std::string baseDir = targetDir + '/' + path.substr(0, path.find_last_of('/'));
        // Ensure that the directory exists
        std::filesystem::create_directories(baseDir);
        std::error_code err;
        if (!CreateDirectoryRecursive(baseDir, err)) {
	        std::cout << "CreateDirectoryRecursive FAILED, err: " << err.message() << std::endl;
		return;
  	}

        // Open the output file for writing
        std::ofstream outFile(baseDir + '/' + path.substr(path.find_last_of('/') + 1), std::ios::binary);
        auto filedata = DecryptFileData(sRGSSFilePath);
        outFile.write(reinterpret_cast<const char*>(filedata.data()), filedata.size());
        outFile.close();
    }

private:
    std::string path;         // File name
    unsigned int size;       // Size of the file
    unsigned int offset;     // Offset in the RGSSAD file
    unsigned int key;        // Decryption key
};

unsigned int getUInt32(const char *bData) {
    return (bData[0] << 24) + (bData[1] << 16) + (bData[2] << 8) + bData[3];
}

unsigned int DecryptIntV1(unsigned int value, unsigned int iKey) {
    return value ^ iKey;
}

unsigned int DecryptIntV3(unsigned int value, unsigned int iKey) {
    return value ^ iKey;
}

std::vector<unsigned char> DecryptNameV1(const std::vector<unsigned char> &bNameEnc, unsigned int length, unsigned int &iKey, unsigned int pos) {
    std::vector<unsigned char> bNameDec(length);

    for (unsigned int i = 0; i < length; ++i) {
        unsigned char b = bNameEnc[i];
        bNameDec[i] = b ^ (iKey & 0xff);

#if DEBUG
        std::cout << "iKey = 0x" << std::hex << iKey << std::dec
                  << ", pos=" << pos + i
                  << ", " << static_cast<char>(bNameDec[i] % 256) << "("
                  << static_cast<int>(bNameDec[i]) << ") = "
                  << static_cast<unsigned int>(b) << " ^ "
                  << static_cast<unsigned int>(iKey & 0xff) << std::endl;
#endif

        iKey = next_iKey(iKey);
    }

    return bNameDec;
}

std::vector<unsigned char> DecryptNameV3(const std::vector<unsigned char> &bNameEnc, unsigned int length, unsigned int key) {
    unsigned char bNameDec[255];
    unsigned char keyBytes[4];
    int j = 0;
    int i = 0;

    // Pack the key into keyBytes
    keyBytes[0] = static_cast<unsigned char>((key) & 0xFF);
    keyBytes[1] = static_cast<unsigned char>((key >> 8) & 0xFF);
    keyBytes[2] = static_cast<unsigned char>((key >> 16) & 0xFF);
    keyBytes[3] = static_cast<unsigned char>((key >> 24) & 0xFF);

    // Decrypting the name
    for (const auto &b : bNameEnc) {
        if (j == 4)
            j = 0;
#if VERBOSE_DEBUG
        std::cout << "b = " << static_cast<int>(b) << ", key_byte = " << static_cast<int>(keyBytes[j]) << std::endl;
#endif

        bNameDec[i] = (b & 0xFF) ^ keyBytes[j];
        j++;
        i++;
    }

    return std::vector<unsigned char>(bNameDec, bNameDec + length); // Take only the valid portion
}

// The ReadRGSSADV1 function
std::vector<File> ReadRGSSADV1(const std::string &sPath, unsigned int iKey, int max_count) {
    std::vector<File> files;
    std::string s;
    unsigned int length = 0;
    int numFiles = 0;

    if (max_count < 0) max_count = INT_MAX;

    BinaryReader br(sPath);
    br.seek(8, std::ios::cur);  // Skip the first 8 bytes

    while (max_count >= numFiles) {
        // Read file length and decrypt it
        length = br.read<unsigned int>("uint32");
        length = DecryptIntV1(length, iKey);
        iKey = next_iKey(iKey);
#if DEBUG
        std::cout << "length = " << length << std::endl;
        std::cout << "iKey = " << std::hex << iKey << std::endl;
#endif
        // Ensure length is valid
        if (length >= 256) {
            throw std::runtime_error("File length exceeds maximum allowed size.");
        }

        std::streamoff pos = br.tell();
#if DEBUG
        std::cout << "iKey = " << std::hex << iKey << std::dec << ", pos=" << pos << ", length=" << length << std::endl;
#endif

        // Read and decrypt the file name
        std::vector<char> file_name_enc = br.readBytes(length);
        std::vector<unsigned char> file_name_dec = DecryptNameV1(std::vector<unsigned char>(file_name_enc.begin(), file_name_enc.end()), length, iKey, pos);

        debug_print(s + " Decrypted name: " + std::string(file_name_dec.begin(), file_name_dec.end()));

        // Read file size and decrypt it
        unsigned int file_size = br.read<unsigned int>("uint32");
        file_size = DecryptIntV1(file_size, iKey);
        iKey = next_iKey(iKey);

        // Get current offset for the file
        std::streamoff iOffset = br.tell();

        // Create and store the new File object
        files.emplace_back(std::string(file_name_dec.begin(), file_name_dec.end()), file_size, iOffset, iKey);

        // Skip the bytes of the file data that we just accounted
        br.seek(file_size, std::ios::cur);
        numFiles++;

        // Check if we have reached the end of the file
        if (br.tell() >= br.size()) {
            debug_print(" - end of file, last file_size = " + std::to_string(file_size));
            break;
        }
    }
    return files;
}

std::vector<File> ReadRGSSADV3(const std::string &sPath, int max_count) {
    std::vector<File> files;
    unsigned int iKey = 0; // Initialize the decryption key
    int numFiles = 0;

    if (max_count < 0) {
        max_count = std::numeric_limits<int>::max();
    }

    BinaryReader br(sPath);
    br.seek(8, std::ios::cur); // Skip the first 8 bytes

    // Read the key based on the RGSSAD3 spec
    iKey = br.read<unsigned int>("uint32") * 9 + 3;
#if DEBUG
    std::cout << "iKey = " << std::hex << iKey << std::dec << std::endl;
#endif

    while (numFiles < max_count) {
        // Read and decrypt file offset
        unsigned int file_offset = br.read<unsigned int>("uint32");
        file_offset = DecryptIntV3(file_offset, iKey);

        if (file_offset == 0) {
            break; // Stop if we encounter a zero offset
        }

        // Read and decrypt file size
        unsigned int file_size = br.read<unsigned int>("uint32");
        file_size = DecryptIntV3(file_size, iKey);

        // Read and decrypt file key
        unsigned int file_key = br.read<unsigned int>("uint32");
        file_key = DecryptIntV3(file_key, iKey);

        // Read and decrypt file name length
        unsigned int length = br.read<unsigned int>("uint32");
        length = DecryptIntV3(length, iKey);

#if DEBUG
        std::streamoff pos = br.tell(); // Current position in the stream
        std::ostringstream debugStream;
        debugStream << "iKey = 0x" << std::hex << iKey << ", pos=" << pos << ", length=" << length;
        std::cout << debugStream.str() << std::endl;
#endif

        assert(length < 256); // Ensure that length does not exceed 255

        // Read the encrypted file name bytes
        std::vector<char> file_name_enc = br.readBytes(length);

        // Convert to unsigned char vector
        std::vector<unsigned char> file_name_enc_uchar(file_name_enc.begin(), file_name_enc.end());

#if DEBUG
        // Print the encrypted file name bytes
        for (const auto &byte : file_name_enc_uchar) {
            std::cout << static_cast<int>(byte) << ",";
        }
        std::cout << std::endl;
#endif
        // Decrypt the file name
        std::vector<unsigned char> file_name_dec = DecryptNameV3(file_name_enc_uchar, length, iKey);

#if DEBUG
        debugStream.str(""); // Clear the stream for the next message
        debugStream << "Decrypted file name: ";
        for (size_t i = 0; i < length; ++i) {
            debugStream << static_cast<char>(file_name_dec[i]);
        }
        std::cout << debugStream.str() << std::endl;
#endif

        // Create a new File object and add it to the list
        files.emplace_back(std::string(file_name_dec.begin(), file_name_dec.end()), file_size, file_offset, file_key);
        numFiles++; // Increment the file count
    }
    return files; // Return the list of files
}

namespace py = pybind11;

PYBIND11_MODULE(decryptor, m) {
    m.doc() = "Python bindings for the C++ classes and functions";

    // Binding BinaryReader class
    py::class_<BinaryReader>(m, "BinaryReader")
        .def(py::init<const std::string &>())
        .def("seek", &BinaryReader::seek)
        .def("tell", &BinaryReader::tell)
        .def("read", &BinaryReader::read<int>) // Change to appropriate types as needed
        .def("readBytes", &BinaryReader::readBytes)
        .def("readCString", &BinaryReader::readCString);

    // Binding File class
    py::class_<File>(m, "File")
        .def(py::init<const std::string &, unsigned int, unsigned int, unsigned int>())
        .def("DecryptFileData", &File::DecryptFileData)
        .def("extract", &File::extract);

    // Binding utility functions
    m.def("getBytes", &getBytes, "Get bytes from an integer");
    m.def("getUInt32", &getUInt32, "Get unsigned int from bytes");
    m.def("next_iKey", &next_iKey, "Get the next iKey");
    m.def("DecryptIntV1", &DecryptIntV1, "Decrypt integer V1");
    m.def("DecryptIntV3", &DecryptIntV3, "Decrypt integer V3");
    m.def("DecryptNameV1", &DecryptNameV1, "Decrypt name V1");
    m.def("DecryptNameV3", &DecryptNameV3, "Decrypt name V3");
    m.def("ReadRGSSADV1", &ReadRGSSADV1, "ReadRGSSADV1");
    m.def("ReadRGSSADV3", &ReadRGSSADV3, "ReadRGSSADV3");
}
