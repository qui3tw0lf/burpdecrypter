import sys, ast, os
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
    
aes_key = "test1234test1234"

def decrypt():
    cipher = AES.new(aes_key.encode(), AES.MODE_CBC, aes_key.encode())
    plaintext = unpad(cipher.decrypt(b64decode(body)), 16)
    print(plaintext) # Output of the script will get printed in the Decrypted Data tab.
    return plaintext
    
def encrypt():
    cipher = AES.new(aes_key.encode(), AES.MODE_CBC, aes_key.encode())
    ciphertext = cipher.encrypt(pad(body, AES.block_size))
    ciphertext = b64encode(ciphertext)
    print(ciphertext)  # Output of the script will get printed in the Raw/Pretty tab.
    return ciphertext
        
run()