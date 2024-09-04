from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

key_bytes = [
    57,
    193,
    86,
    78,
    153,
    197,
    48,
    29,
    30,
    110,
    66,
    69,
    142,
    163,
    29,
    31,
    158,
    85,
    63,
    51,
    59,
    157,
    80,
    43,
    198,
    155,
    22,
    23,
    170,
    244,
    181,
    109
]

def encrypt(data):
  iv = get_random_bytes(12)
  cipher = AES.new(key=bytearray(key_bytes), mode=AES.MODE_GCM, nonce=iv)
  ciphertext, tag = cipher.encrypt_and_digest(bytearray(data.encode()))
  
  encrypted = ciphertext + tag
  return base64.b64encode(encrypted + iv + b"\x00")

def decrypt(encryptedbase64):
    data = base64.b64decode(encryptedbase64)[:-29]
    iv_ = base64.b64decode(encryptedbase64)[-13:][:-1]
    cipher = AES.new(key=bytearray(key_bytes), mode=AES.MODE_GCM, nonce=bytearray(iv_))
    return cipher.decrypt_and_verify(bytearray(data), bytearray(base64.b64decode(encryptedbase64)[-29:][:-13]))
