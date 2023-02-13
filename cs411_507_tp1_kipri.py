#SUDE BUKET KIPRI
#IMPLEMENTING SIGNAL PROTOCOL

#PHASE 1

import math
import time
import random
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256, HMAC, SHA256
import requests
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import random
import re
import json

API_URL = 'http://10.92.55.4:5000'

stuID = 28368

curve = Curve.get_curve('secp256k1')

#Server's Identity public key (CONVERTED FROM HEXADECIMAL TO DECIMAL)
IKey_Ser = Point(93223115898197558905062012489877327981787036929201444813217704012422483432813, 8985629203225767185464920094198364255740987346743912071843303975587695337619, curve)
def IKRegReq(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json = mes)		
    if((response.ok) == False): print(response.json())
    
def IKRegVerify(code):
    mes = {'ID':stuID, 'CODE': code}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json = mes)
    if((response.ok) == False): raise Exception(response.json())
    else:
        print(response.json())
   
def SPKReg(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'SPKPUB.X': x, 'SPKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SPKReg"), json = mes)		
    if((response.ok) == False): 
        print(response.json())
    else: 
        res = response.json()
        return res['SPKPUB.X'], res['SPKPUB.Y'], res['H'], res['S']

def OTKReg(keyID,x,y,hmac):
    mes = {'ID':stuID, 'KEYID': keyID, 'OTKI.X': x, 'OTKI.Y': y, 'HMACI': hmac}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "OTKReg"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True


def ResetIK(rcode):
    mes = {'ID':stuID, 'RCODE': rcode}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetIK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetSPK(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetSPK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True


def ResetOTK(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetOTK"), json = mes)		
    if((response.ok) == False): print(response.json())
    
P = curve.generator
n = curve.order
m = 28368
m_bytes = m.to_bytes((m.bit_length() + 7) // 8, byteorder='big')

# GENERATE KEYS
def generate_keypair(n, P):
    # SECRET KEY GENERATION (PRIVATE KEY)
    privA = random.randint(0, n-1)
    # PRIVATE KEY GENERATION
    pubA = privA*P
    return privA, pubA

# GENERATE SIGNATURE
def sign(m_bytes, privA, n, P):
    k = random.randint(1, n-2)
    R = k*P
    r = R.x % n
    r_bytes = r.to_bytes((r.bit_length()+7)//8, 'big')
    r_m_BYTES = r_bytes+m_bytes
    hash_rm = SHA3_256.new(r_m_BYTES)
    h = int.from_bytes(hash_rm.digest(), byteorder='big') % n
    s = (k + privA * h) % n
    return h, s

# VERIFY SIGNATURE
def verify_sign(m_bytes, h, s, n, pubA, P):
    V = s * P - h * pubA
    v = V.x % n
    v_bytes = v.to_bytes((v.bit_length()+7)//8, 'big')
    v_m_bytes = v_bytes + m_bytes
    hashed_vm = SHA3_256.new(v_m_bytes).digest()
    h_ver = int.from_bytes(hashed_vm, byteorder='big') % n
    if(h == h_ver):
        print ("Verified. \n")


def main ():
    curve = Curve.get_curve('secp256k1')
    n = curve.order
    P = curve.generator

    # IDENTITY KEY PAIR GENERATION
    privA, pubA = generate_keypair(n,P)

    # PUBLIC KEY X AND Y ON CURVE SECP256K1
    IK_Pub = Point(pubA.x, pubA.y, curve)

    print("Identity key is created: \n IK.Pri : {} \n IK.Pub : {}".format(privA, IK_Pub))

    #Server's Identitiy public key
    IKey_Ser = Point(93223115898197558905062012489877327981787036929201444813217704012422483432813, 8985629203225767185464920094198364255740987346743912071843303975587695337619, curve)

    stuID = 28368
    print("IKey is a long term key and shouldn't be changed and private part should be kept secret. But this is a sample run, so here is my private IKey: \n")
    print("My ID number is {} \n".format(stuID))
    print("+++++++++++++++++++++++++++++++++++++++++++++ \n")

    stuID_bytes = stuID.to_bytes((stuID.bit_length()+7)//8, 'big') #(CONVERTED TO BYTES IN ORDER TO SIGN IT)

    h, s = sign(stuID_bytes, privA, n, P)

    print("Signature of my ID number is:\n h = {} \n s = {} \n".format(h,s))
    print("+++++++++++++++++++++++++++++++++++++++++++++ \n")
    print("Sending signature and my IKEY to server via IKRegReq() function in json format")

    # REGISTER IDENTITY KEY ON SERVER
    IKRegReq(h,s,IK_Pub.x,IK_Pub.y)

    print("+++++++++++++++++++++++++++++++++++++++++++++ \n")
    
    print("Received the verification vcode through email \n")
    print("+++++++++++++++++++++++++++++++++++++++++++++ \n")
    rver_code = int(input("Enter reset code which is sent to you: \n"))
    ResetIK(rver_code) #uncomment to reset #rvercode = 741487
    #GET THE VERIFICATION CODE AND REGISTER ON SERVER
    ver_code = int(input("Enter verification code which is sent to you: \n")) 
    print("+++++++++++++++++++++++++++++++++++++++++++++ \n")
    print("Sending the verification code to server via IKRegVerify() function in json format")
    IKRegVerify(ver_code)
    print("+++++++++++++++++++++++++++++++++++++++++++++ \n")
    
    #RESET IDENTITY KEY IN CASE OF LOSS 
    #rcode = 741487

    # SIGNED PREKEY PAIR GENERATION
    print("Generating SPK...\n")

    SPK_Priv, SPK_Pub = generate_keypair(n,P)
    print("Private SPK: {} \n". format(SPK_Priv))
    print("Public SPK.x: {} \n". format(SPK_Pub.x))
    print("Public SPK.y: {} \n". format(SPK_Pub.y))
    #SPK PUBLIC KEY CONVERSION AND CONCATINATION FOR SIGNING
    SPK_Pub_x_bytes = SPK_Pub.x.to_bytes((SPK_Pub.x.bit_length()+7)//8, 'big')
    SPK_Pub_y_bytes = SPK_Pub.y.to_bytes((SPK_Pub.y.bit_length()+7)//8, 'big')
    SPK_PUB_xy_bytes = SPK_Pub_x_bytes+SPK_Pub_y_bytes

    print("Convert SPK.x and SPK.y to bytes in order to sign them then concatenate them \n result will be like: {} \n ".format(SPK_PUB_xy_bytes))

    SPK_h, SPK_s = sign(SPK_PUB_xy_bytes, privA, n, P)
    print("+++++++++++++++++++++++++++++++++++++++++++++ \n")
    
    print("Signature of SPK is: \n h = {} \n s = {} \n".format(SPK_h,SPK_s))
    print("\n Sending SPK and the signatures to the server via SPKReg() function in json format...")
    

    print("+++++++++++++++++++++++++++++++++++++++++++++ \n")

    #REGISTER SPK ON SERVER

    print("+++++++++++++++++++++++++++++++++++++++++++++ \n")
    
    SPKA_Pub_x,  SPKA_Pub_y, SPKA_h, SPKA_s = SPKReg(SPK_h, SPK_s, SPK_Pub.x, SPK_Pub.y)
    SPKA_Pub = Point(SPKA_Pub_x, SPKA_Pub_y, curve)
    
    print("if server verifies the signature it will send its SPK and corresponding signature. If this is the case SPKReg() function will return those \n")
    print("Server's SPK Verification \n")

    print("Recreating the message(SPK) signed by the server \n")
    print("+++++++++++++++++++++++++++++++++++++++++++++ \n")
    #CONVERT SPKA TO BYTES TO SIGN
    SPKA_Pub_x_bytes = SPKA_Pub.x.to_bytes((SPKA_Pub.x.bit_length()+7)//8, 'big')
    SPKA_Pub_y_bytes = SPKA_Pub.y.to_bytes((SPKA_Pub.y.bit_length()+7)//8, 'big')
    SPKA_PUB_xy_bytes = SPKA_Pub_x_bytes+SPKA_Pub_y_bytes
    #SERVER SPK VERIFICATION
    print("Verifying the server's SPK...")
    print("If server's SPK is verified we can move to the OTK generation step")

    verify_spk = verify_sign(SPKA_PUB_xy_bytes, SPKA_h, SPKA_s, n, IKey_Ser, P)

    print("Is SPK verified?:  {}".format(verify_spk))

    if(verify_sign == False):
        print("Could not verify!")
        ResetSPK(h,s)
        return
    else:
        pass

    print("+++++++++++++++++++++++++++++++++++++++++++++ \n")

    # GENERATE HMAC KEY

    print("Creating HMAC key (Diffie Hellman)")

    T = SPK_Priv*SPKA_Pub
    T_x_bytes = T.x.to_bytes((T.x.bit_length()+7)//8, 'big')
    T_y_bytes = T.y.to_bytes((T.y.bit_length()+7)//8, 'big')
    U = T_x_bytes + T_y_bytes + b'CuriosityIsTheHMACKeyToCreativity'
    HMAC_KEY = SHA3_256.new(U).digest()

    print("T is {}".format(T))
    print("U is {}".format(U))
    print("HMAC key is created {}".format(HMAC_KEY))

    print("+++++++++++++++++++++++++++++++++++++++++++++ \n")

     # OTK GENERATION

    print("Creating OTKs starting from index 0...")

    for i in range(11):
        OTK_Pri, OTK_Pub = generate_keypair(n,P)
        print("{}th key generated. \n" .format(i))
        print("Private Part= \n".format(OTK_Pri))
        print("Public (x coordinate) = {} \n".format(OTK_Pub.x))
        print("Public (y coordinate) = {} \n".format(OTK_Pub.y))

        print("x and y coordinates of the OTK converted to bytes and concatanated")
        OTK_i_Pub_x_bytes = OTK_Pub.x.to_bytes((OTK_Pub.x.bit_length()+7)//8, 'big')
        OTK_i_Pub_y_bytes = OTK_Pub.y.to_bytes((OTK_Pub.y.bit_length()+7)//8, 'big')
        OTK_i_Pub_xy_bytes = OTK_i_Pub_x_bytes + OTK_i_Pub_y_bytes
        
        print("message {}".format(OTK_i_Pub_xy_bytes))

        hmac0 = HMAC.new(key=HMAC_KEY, msg=OTK_i_Pub_xy_bytes, digestmod=SHA256).hexdigest()

        print("hmac is calculated and converted with 'hexdigest()': {} \n".format(hmac0))
        #OTK REGISTRATION
        OTKReg(i, OTK_Pub.x, OTK_Pub.y, hmac0)
        
        print ("OTK with ID number {} is registered successfully \n". format(i))
        print("+++++++++++++++++++++++++++++++++++++++++++++ \n")
        
    else: 
        #CHECK FOR MEMORY TO REGISTER KEYS
        print ("Key memory is full. There are 10 keys registered. No need to register more keys \n")

    print("+++++++++++++++++++++++++++++++++++++++++++++ \n")

    # OTK RESET 
    print("Trying to delete OTKs but sending wrong signatures... \n")
    ResetOTK(h*2,s)
    print ("The server couldn't verify the signature!! \n")
    print("Trying to delete OTKs...")
    ResetOTK(h,s) #uncomment to reset

    print("+++++++++++++++++++++++++++++++++++++++++++++ \n")

    # SPK RESET
    print("Trying to delete SPK...")
    ResetSPK(h,s) #uncomment to reset

    print("+++++++++++++++++++++++++++++++++++++++++++++ \n")
    
    #IDENTITY KEY DELETION
    print("Trying to delete Identity Key...")
    rver_code = int(input("Enter reset code which is sent to you: \n"))
    ResetIK(rver_code) #uncomment to reset #rvercode = 741487

main()
