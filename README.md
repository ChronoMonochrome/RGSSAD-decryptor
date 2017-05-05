# RGSSAD-decryptor
RPG Maker VX ace games decryptor - loosely based on the RGSSAD-RGSS2A-RGSS3A Decryptor

# Building

Requires Cython and mingw GCC compiler to be installed - MS Visual C++ doesn't work for some reason (refer to https://github.com/cython/cython/wiki/CythonExtensionsOnWindows):

python setup.py build_ext --inplace --compiler=mingw32
