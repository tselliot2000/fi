import argparse
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend

backend = default_backend()

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,
        backend=backend
    )
    return kdf.derive(password.encode())


def encrypt_file(input_file, output_file, password, base64_out=False):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()

    with open(input_file, "rb") as f:
        plaintext = f.read()

    padded = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    output_bytes = salt + iv + ciphertext

    if base64_out:
        output_bytes = base64.b64encode(output_bytes)

    with open(output_file, "wb") as f:
        f.write(output_bytes)


def decrypt_file(input_file, output_file, password, base64_in=False):
    with open(input_file, "rb") as f:
        data = f.read()

    if base64_in:
        data = base64.b64decode(data)

    salt = data[:16]
    iv = data[16:32]
    ciphertext = data[32:]

    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()

    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()

    with open(output_file, "wb") as f:
        f.write(plaintext)


def main():
    parser = argparse.ArgumentParser(description="AES file encrypt/decrypt with optional Base64")
    parser.add_argument("mode", choices=["encrypt", "decrypt"])
    parser.add_argument("input_file")
    parser.add_argument("output_file")
    parser.add_argument("password")

    parser.add_argument("--base64-out", action="store_true",
                        help="Encode encrypted output as Base64")
    parser.add_argument("--base64-in", action="store_true",
                        help="Decode Base64 input before decrypting")

    args = parser.parse_args()

    if args.mode == "encrypt":
        encrypt_file(args.input_file, args.output_file, args.password, args.base64_out)
    else:
        decrypt_file(args.input_file, args.output_file, args.password, args.base64_in)


if __name__ == "__main__":
    main()
