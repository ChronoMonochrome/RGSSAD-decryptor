# RGSSAD-decryptor
RPG Maker VX ace games decryptor - loosely based on the RGSSAD-RGSS2A-RGSS3A Decryptor

# Build

```
pip install -r requirements.txt
python setup.py build_ext --inplace --compiler=mingw32 -DMS_WIN64=1
```

# Installation

Put decryptor.pyd module to the Python modules directory

# Usage

```
import decryptor
game = "C:/Game/Game.rgss2a"
out_dir = "C:/games"
files = decryptor.ReadRGSSADV1(sPath = game, iKey = 0xdeadcafe, max_count = -1)
[i.extract(game, out_dir) for i in files]
```
