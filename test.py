import sys, ast, json, re, os
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
    

if len(sys.argv) < 2:
    print("Missing arguments!")
    exit()

if os.path.exists("/tmp/burp_decrypter_data.txt"):
    with open("/tmp/burp_decrypter_data.txt") as fd:    
        tmp_data = fd.read()
        method = sys.argv[1]
        body, headers = tmp_data.split(" | ")
        body = b64decode(body)
        headers = ast.literal_eval(b64decode(headers).decode())
else:
    exit()
        
    
def run():
    if method == 'e':
        return encrypt()
    elif method == 'd':
        return decrypt()      
    else:
        return None
    
def decrypt_aes(text, key, iv):
    cipher = AES.new(key.encode(), AES.MODE_CBC, iv.encode())
    plaintext = cipher.decrypt(b64decode(text))
    return plaintext

def encrypt_aes(text, key, iv):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
    ciphertext = cipher.encrypt(pad(text, AES.block_size))
    return b64encode(ciphertext)

def decrypt():
    aes_key = "test1234test1234"
    tmp_res = unpad(decrypt_aes(body, aes_key, aes_key), 16).decode().strip("\n")
    print(tmp_res.strip("\n"))
    return tmp_res
    
def encrypt():
    aes_key = "test1234test1234"
    tmp_res = encrypt_aes(body, aes_key, aes_key)
    print(tmp_res.decode())
    return tmp_res
        
run()