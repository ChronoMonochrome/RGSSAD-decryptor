# RGSSAD-decryptor
RPG Maker VX ace games decryptor - loosely based on the RGSSAD-RGSS2A-RGSS3A Decryptor

# Build

```
pip install pybind11
python setup.py build_ext --inplace
```

# Installation

Put decryptor.pyd module to the Python modules directory

# Usage

```
import decryptor
game = "C:/Game/Game.rgss2a"
out_dir = "C:/games"
files = decryptor.ReadRGSSADV1(game, 0xdeadcafe, -1)
[i.extract(game, out_dir) for i in files]
```
