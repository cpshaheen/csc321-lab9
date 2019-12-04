from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
import random
import os
import sys
import ast
from Crypto import Random
'''
INCOMPLETE STUCK AT PART ONE
UNABLE TO DECRYPT MESSAGES PROPERLY TO PLAINTEXT
SHAHEEN ALEMI
'''
def rndmNum(bytesize):
    rndmbytes = get_random_bytes(bytesize)
    return int.from_bytes(rndmbytes,"big")

def diffHellman(p,g,amessage,bmessage):
    #alice gets her secret random number
    aPrivate = random.randint(0,p)

    #bob gets his secret random number
    bPrivate = random.randint(0,p)

    #alice "sends" her calculated value to bob
    aCalctoA = pow(g,aPrivate)%p

    #bob "sends" his calculated value to alice
    bCalctoB = pow(g, bPrivate)%p

    #alice calculates the key using bobs message and her private value
    aSecret = pow(bCalctoB, aPrivate)%p
    aSha = SHA256.new()
    aSha.update(bytes(aSecret))
    aKey = bytearray(aSha.digest())
    aKey = aKey[0:16]
    print(len(aKey))
    #aKey[-1] = b'x'
    aKey = bytes(aKey)

    #bob calculates the key using alices message and his private value
    bSecret = pow(aCalctoA, bPrivate)%p
    bSha = SHA256.new()
    bSha.update(bytes(bSecret))
    bKey = bytearray(bSha.digest())
    bKey = bKey[0:16]
    print(len(bKey))
    #bKey[-1] = b'x'
    bKey = bytes(bKey)

    #comparing the keys
    print("")
    print("Diffie-Hellman Key Exchange:")
    print("alice & bob have matching keys:\t" + str(aKey==bKey))
    print("")

    #alice uses aes-cbc to encrypt her message
    # aIV = Random.new().read(AES.block_size)
    aIV = os.urandom(AES.block_size)
    aCipher = AES.new(aKey, AES.MODE_CBC, aIV)
    amessage = bytes(amessage, 'ascii')
    aEnc = aCipher.encrypt(pad(amessage,16))

    #bob uses aes-cbc to encrypt his message
    #bIV = Random.new().read(AES.block_size)
    bIV = os.urandom(AES.block_size)
    bCipher = AES.new(bKey, AES.MODE_CBC, bIV)
    bmessage = bytes(bmessage,'ascii')
    bEnc = bCipher.encrypt(pad(bmessage,16))

    #alice recieves and reads bobs message
    alicesDecryptor = AES.new(bKey, AES.MODE_CBC, bIV)
    bobsMessage = unpad(alicesDecryptor.decrypt(bEnc), 16)
    print("bobs encrypted message:\t" + bobsMessage.decode("ascii"))

    #bob recieves and reads alices message
    bobsDecryptor = AES.new(aKey, AES.MODE_CBC, aIV)
    alicesMessage = unpad(bobsDecryptor.decrypt(aEnc), 16)
    print("alices encrypted message:\t" +alicesMessage.decode("ascii"))

diffHellman(3,17,"Hi Bob!","Hi Alice!")
