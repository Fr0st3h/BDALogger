import base64
import hashlib
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def decrypt(data, key):
    data = json.loads(data)
    dk = key.encode() + bytes.fromhex(data["s"])
    md5 = [hashlib.md5(dk).digest()]
    result = md5[0]
    for i in range(1, 4):
        md5.insert(i, hashlib.md5((md5[i - 1] + dk)).digest())
        result += md5[i]
    aes = AES.new(result[:32], AES.MODE_CBC, bytes.fromhex(data["iv"]))
    data = aes.decrypt(base64.b64decode(data["ct"]))
    return unpad(data, 16)
