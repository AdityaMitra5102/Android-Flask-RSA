from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from flask import *
import base64
import rsa


app=Flask(__name__)

def genKey():
    keyPair=RSA.generate(2048)
    pubKey=keyPair.publickey()
    privKey=keyPair

    pubKeyPEM=pubKey.exportKey('PEM').decode('ascii')
    privKeyPEM=privKey.exportKey('PEM').decode('ascii')


    privFile= open('private.pem','w')
    privFile.write(privKeyPEM)
    privFile.close()

    pubFile=open('public.pem','w')
    pubFile.write(pubKeyPEM)
    print(pubKeyPEM)

    
    pubFile.close()

    encryptor = PKCS1_OAEP.new(pubKey)
    decryptor=PKCS1_OAEP.new(privKey)

    msg="Hello Friend!"
    emsg=encryptor.encrypt(msg.encode())
    dmsg=decryptor.decrypt(emsg).decode()

    if msg==dmsg:
        print('Key generation success')

def importKey():

    global encryptor
    global decryptor
    global pubKeyPEM
    global priv2Key

    privFile=open('private.pem','r')
    privKeyPEM=privFile.read()
    privKey=RSA.importKey(privKeyPEM.encode())
    privFile.close()

    priv2Key=rsa.PrivateKey.load_pkcs1(privKeyPEM.encode('utf8'))


    pubFile=open('public.pem','r')
    pubKeyPEM=pubFile.read()
    pubKey=RSA.importKey(pubKeyPEM.encode())

    pub2File=open('public2.pem','r')
    pub2KeyPEM=pub2File.read()

    encryptor = PKCS1_OAEP.new(pubKey)
    decryptor=PKCS1_OAEP.new(privKey)

    msg="Hello Friend!"
    emsg=encryptor.encrypt(msg.encode())
    dmsg=decryptor.decrypt(emsg).decode()

    if msg==dmsg:
        print('Key import success')

@app.route('/getPubKey', methods=["GET","POST"])
def getPublicKey():
    global pubKeyPEM
    return pubKeyPEM

@app.route('/decrypt', methods=["GET","POST"])
def decrypt():
    global decryptor
    global priv2Key    
    ciphertext=request.form['data']
    if ciphertext=="":
        return "Nothing was entered"
    plaintext = rsa.decrypt(base64.b64decode(ciphertext.encode()), priv2Key)
    return plaintext

@app.route('/encrypt', methods=["GET","POST"])
def encrypt():
    global encryptor
    plaintext=request.form['data']
    ciphertext=encryptor.encrypt(plaintext.encode())
    ctxt=base64.b64encode(ciphertext)
    return ctxt

#genKey()
importKey()
app.run(host="0.0.0.0", port=5000)
