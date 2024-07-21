import decryptor

VERSION = 3

out="out"

if VERSION == 1:
    game=b"Game.rgss2a"
    files = decryptor.ReadRGSSADV1(game, 0xdeadcafe, -1)
elif VERSION == 3:
    game=b"Game.rgss3a"
    files = decryptor.ReadRGSSADV3(game, -1)
else:
    raise RuntimeError("Unsupported game version")

[i.extract(game, out) for i in files]
