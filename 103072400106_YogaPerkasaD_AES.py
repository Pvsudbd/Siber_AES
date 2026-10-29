"""Template praktikum: dua fitur enkripsi dan dekripsi teks menggunakan AES-GCM.

Instal dependensi: pip install cryptography
Mahasiswa mengisi bagian TODO pada fungsi enkripsi() dan dekripsi().
"""
import base64
import hashlib
import os
import binascii

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


def turunkan_kunci(kata_sandi: str, salt: bytes) -> bytes:
    """Kunci 32 byte untuk AES-256 dari kata sandi dan salt."""
    return hashlib.pbkdf2_hmac(
        "sha256", kata_sandi.encode("utf-8"), salt, 200_000, dklen=32
    )


def enkripsi(teks: str, kata_sandi: str) -> str:
    """Input: dua teks. Output: satu teks ciphertext Base64."""
    # TODO:
    # 1. Buat salt acak 16 byte dan nonce acak 12 byte.
    salt = os.urandom(16)
    nonce = os.urandom(12)
    # 2. Buat kunci dengan turunkan_kunci().
    kunci = turunkan_kunci(kata_sandi, salt)
    # 3. Enkripsi teks UTF-8 menggunakan AESGCM.
    teks_enkrip = AESGCM(kunci).encrypt(nonce,teks.encode("utf-8"),None)
    # 4. Gabungkan salt + nonce + ciphertext (termasuk tag).
    gabungan = salt + nonce + teks_enkrip
    # 5. Encode gabungan dengan Base64, lalu return sebagai string.
    gabungan_enkrip = base64.b64encode(gabungan).decode("utf-8")
    return gabungan_enkrip



def dekripsi(ciphertext_b64: str, kata_sandi: str) -> str:
    """Input: dua teks. Output: plaintext atau pesan kegagalan."""
    # TODO:
    # 1. Decode ciphertext_b64 dari Base64 menjadi bytes.
    try:
        gabungan = base64.b64decode(ciphertext_b64)
    except (binascii.Error, ValueError):
        return "Dekripsi gagal: ciphertext tidak sesuai."

    # 2. Pisahkan salt (16 byte), nonce (12 byte), dan sisa ciphertext.
    salt = gabungan[:16]
    nonce = gabungan[16:28]
    ciphertext = gabungan[28:]
    # 3. Buat kembali kunci dengan turunkan_kunci().
    kunci = turunkan_kunci(kata_sandi, salt)
    # 4. Dekripsi AESGCM, lalu decode UTF-8 menjadi teks.
    aesgm = AESGCM(kunci)
    # 5. Jika kunci salah / ciphertext dimodifikasi, tangani InvalidTag.
    try:
        teks = aesgm.decrypt(nonce, ciphertext, None).decode("utf-8")
        return teks
    except InvalidTag:
        return "Dekripsi gagal: kata sandi atau ciphertext tidak sesuai."
        


def main():
    while True:
        print("\n=== MENU ENKRIPSI ===")
        print("1. Enkripsi")
        print("2. Dekripsi")
        print("3. Keluar")

        pilihan = input("Pilih menu: ")

        if pilihan == "1":
            teks = input("Masukkan teks: ")
            kata_sandi = input("Masukkan kata sandi: ")

            hasil = enkripsi(teks, kata_sandi)
            print("Ciphertext:", hasil)

        elif pilihan == "2":
            ciphertext = input("Masukkan ciphertext: ").strip()
            kata_sandi = input("Masukkan kata sandi: ")
            hasil = dekripsi(ciphertext, kata_sandi)
            print("Plaintext:", hasil)

        elif pilihan == "3":
            print("Program selesai")
            break

        else:
            print("Pilihan tidak ada")
            break

if __name__ == "__main__":
    main()
