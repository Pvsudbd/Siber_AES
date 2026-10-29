from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

kunci = AESGCM.generate_key(bit_length=256)
nonce = os.urandom(12)

aes = AESGCM(kunci)
hasil = aes.encrypt(nonce, b"Halo Dunia", None)

print("Teks = Halo Dunia", "\n",hasil)
print(hasil.decode("utf-8"))