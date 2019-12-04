from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
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
    aPrivate = rndmNum(1)

    #bob gets his secret random number
    bPrivate = rndmNum(1)

    #alice "sends" her calculated value to bob
    aCalcToB = (p ** aPrivate)%g

    #bob "sends" his calculated value to alice
    bCalcToA = (p ** bPrivate)%g

    #alice calculates the key using bobs message and her private value
    aSecret = (bCalcToA ** aPrivate)%g
    aSha = SHA256.new()
    aSha.update(bytes(aSecret))
    aKey = bytearray(aSha.digest())
    aKey = aKey[0:16]
    print(len(aKey))
    #aKey[-1] = b'x'
    aKey = bytes(aKey)

    #bob calculates the key using alices message and his private value
    bSecret = (aCalcToB ** bPrivate)%g
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
    aIV = Random.new().read(AES.block_size)
    aCipher = AES.new(aKey, AES.MODE_CBC, aIV)
    amessage = bytes(amessage,"utf-8")
    length = 16 - (len(amessage) % 16)
    amessage += bytes([length])*length
    aEnc = aCipher.encrypt(amessage)

    #bob uses aes-cbc to encrypt his message
    bIV = Random.new().read(AES.block_size)
    bCipher = AES.new(bKey, AES.MODE_CBC, bIV)
    bmessage = bytes(bmessage,"utf-8")
    length = 16 - (len(bmessage) % 16)
    bmessage += bytes([length])*length
    bEnc = bCipher.encrypt(bmessage)

    #alice recieves and reads bobs message
    aIV = Random.new().read(AES.block_size)
    alicesDecryptor = AES.new(aKey, AES.MODE_CBC, aIV)
    bobsMessage = alicesDecryptor.decrypt(bEnc)
    print("bobs encrypted message:\t" + str(bobsMessage))

    #bob recieves and reads alices message
    bIV = Random.new().read(AES.block_size)
    bobsDecryptor = AES.new(bKey, AES.MODE_CBC, bIV)
    alicesMessage = bobsDecryptor.decrypt(aEnc)
    print("alices encrypted message:\t" + str(alicesMessage))

diffHellman(3,17,"Hi Bob!","Hi Alice!")
