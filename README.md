# RGSSAD-decryptor
RPG Maker VX ace games decryptor - loosely based on the RGSSAD-RGSS2A-RGSS3A Decryptor

# Building

Requires Cython and mingw GCC compiler to be installed - MS Visual C++ doesn't work for some reason
(refer to https://github.com/cython/cython/wiki/CythonExtensionsOnWindows):

python setup.py build_ext --inplace --compiler=mingw32

# Installation

Put decryptor.pyd module to the Python modules directory

# Usage

import decryptor
game = "C:/Game/Game.rgss2a"
out_dir = "C:/games"
files = decryptor.ReadRGSSADV1(sPath = game, iKey = 0xdeadcafe, max_count = -1)
[i.extract(game, out_dir) for i in files]
