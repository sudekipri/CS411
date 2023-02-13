#SUDE BUKET KIPRI
#IMPLEMENTING SIGNAL PROTOCOL

#PHASE 2

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

#API_URL = 'http://10.92.52.255:5000/'
API_URL = 'http://10.92.55.4:5000'

stuID = 28368  

curve = Curve.get_curve('secp256k1')
#server's Identitiy public key
IKey_Ser = Point(93223115898197558905062012489877327981787036929201444813217704012422483432813 , 8985629203225767185464920094198364255740987346743912071843303975587695337619, curve)

#Send Public Identitiy Key Coordinates and corresponding signature
def IKRegReq(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json = mes)		
    if((response.ok) == False): print(response.json())

#Send the verification code
def IKRegVerify(code):
    mes = {'ID':stuID, 'CODE': code}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json = mes)
    if((response.ok) == False): raise Exception(response.json())
    print(response.json())

#Send SPK Coordinates and corresponding signature
def SPKReg(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'SPKPUB.X': x, 'SPKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SPKReg"), json = mes)		
    if((response.ok) == False): 
        print(response.json())
    else: 
        res = response.json()
        return res['SPKPUB.X'], res['SPKPUB.Y'], res['H'], res['S']

#Send OTK Coordinates and corresponding hmac
def OTKReg(keyID,x,y,hmac):
    mes = {'ID':stuID, 'KEYID': keyID, 'OTKI.X': x, 'OTKI.Y': y, 'HMACI': hmac}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "OTKReg"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

#Send the reset code to delete your Identitiy Key
def ResetIK(rcode):
    mes = {'ID':stuID, 'RCODE': rcode}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetIK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

#Sign your ID  number and send the signature to delete your SPK
def ResetSPK(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetSPK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

#Send the reset code to delete your Identitiy Key
def ResetOTK(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetOTK"), json = mes)		
    if((response.ok) == False): print(response.json())

############## The new functions of phase 2 ###############

#Pseudo-client will send you 5 messages to your inbox via server when you call this function
def PseudoSendMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsg"), json = mes)		
    print(response.json())

#get your messages. server will send 1 message from your inbox 
def ReqMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json = mes)	
    print(response.json())	
    if((response.ok) == True): 
        res = response.json()
        return res["IDB"], res["OTKID"], res["MSGID"], res["MSG"], res["EK.X"], res["EK.Y"]

#If you decrypted the message, send back the plaintext for grading
def Checker(stuID, stuIDB, msgID, decmsg):
    mes = {'IDA':stuID, 'IDB':stuIDB, 'MSGID': msgID, 'DECMSG': decmsg}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "Checker"), json = mes)		
    print(response.json())

#Get the list of the deleted messages' ids.
def ReqDelMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqDelMsgs"), json = mes)      
    print(response.json())      
    if((response.ok) == True): 
        res = response.json()
        return res["MSGID"]

P = curve.generator
n = curve.order
stuID_bytes = stuID.to_bytes((stuID.bit_length() + 7) // 8, byteorder='big')

# GENERATE KEYS
def generate_keypair(P, n):
    # SECRET KEY GENERATION (PRIVATE KEY)
    privA = random.randint(0, n-1)
    # PUBLIC KEY GENERATION (PUBLIC KEY)
    pubA = privA * P
    return privA, pubA

# GENERATE SIGNATURE
def sign(P, n, privA, stuID_bytes):
    k = Random.new().read(int(math.log(n,2)))
    k = int.from_bytes(k, byteorder='big')%n
    R = k*P
    r = (R.x) % n
    r_bytes = r.to_bytes((r.bit_length() + 7) // 8, byteorder='big')
    temp = r_bytes + stuID_bytes
    hashVal = SHA3_256.new(temp)
    h = int.from_bytes(hashVal.digest(), 'big') % n
    s = (k + privA * h) % n
    print("h= ", h)
    print("s= ",s)
    return h, s

# VERIFY SIGNATURE
def verify_sign(P, n, s, h, pubA, message):
    V = s*P - h*pubA
    v = (V.x) % n
    v_bytes = v.to_bytes((v.bit_length() + 7) // 8, byteorder='big')
    hashVal = SHA3_256.new(v_bytes + message)
    h_ver = int.from_bytes(hashVal.digest(), 'big') % n
    if h_ver == h:
        print("Verified!\n")   

# IDENTITY KEY PAIR GENERATION
privA, pubA = generate_keypair(P, n)
print("Identitiy Key is created")
print("Identity key is created: \n IK.Pri : {} \n IK.Pub : {}".format(privA, pubA))
print("\nMy ID number is: ",stuID)
print("Converted my ID to bytes in order to sign it: ",stuID_bytes)

print("+++++++++++++++++++++++++++++++++++++++++++++ \n")

print("\nSignature of my ID number is:")
h, s = sign(P, n, privA, stuID_bytes)

print("\nSending signature and my IKEY to server via IKRegReq() function in json format")
# REGISTER IDENTITY KEY ON SERVER
IKRegReq(h, s, pubA.x, pubA.y)

print("+++++++++++++++++++++++++++++++++++++++++++++ \n")

#GET THE VERIFICATION CODE AND REGISTER ON SERVER
print("\nReceived the verification code through email")
rver_code = int(input("\n Enter reset code which is sent to you: \n"))
#rver_code = 691361
ResetIK(rver_code)
code = input("Enter verification code which is sent to you: ")
#code = 697472
print("Sending the verification code to server via IKRegVerify() function in json format")
IKRegVerify(int(code)) 

SPK_Priv, SPK_Pub = generate_keypair(P,n)
print("Private SPK: {} \n". format(SPK_Priv))
print("Public SPK.x: {} \n". format(SPK_Pub.x))
print("Public SPK.y: {} \n". format(SPK_Pub.y))

print("+++++++++++++++++++++++++++++++++++++++++++++ \n")

#SPK PUBLIC KEY CONVERSION AND CONCATINATION FOR SIGNING
SPK_Pub_x_bytes = SPK_Pub.x.to_bytes((SPK_Pub.x.bit_length()+7)//8, 'big')
SPK_Pub_y_bytes = SPK_Pub.y.to_bytes((SPK_Pub.y.bit_length()+7)//8, 'big')
SPK_PUB_xy_bytes = SPK_Pub_x_bytes+SPK_Pub_y_bytes

print("Convert SPK.x and SPK.y to bytes in order to sign them then concatenate them \n result will be like: {} \n ".format(SPK_PUB_xy_bytes))

SPK_h, SPK_s = sign(P,n,privA,SPK_PUB_xy_bytes)
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

verify_spk = verify_sign(P, n, SPKA_s, SPKA_h, IKey_Ser, SPKA_PUB_xy_bytes)

print("Is SPK verified?:  {}".format(verify_spk))

if(verify_sign == False):
    print("Could not verify!")
    #ResetSPK(h,s)
else:
    pass

# GENERATE HMAC KEY

print("+++++++++++++++++++++++++++++++++++++++++++++ \n")

print("Creating HMAC key (Diffie Hellman)")

T = SPK_Priv*SPKA_Pub
Tx_bytes = T.x.to_bytes((T.x.bit_length() + 7) // 8, byteorder='big')
Ty_bytes = T.y.to_bytes((T.y.bit_length() + 7) // 8, byteorder='big')
U = b'CuriosityIsTheHMACKeyToCreativity'+Ty_bytes+Tx_bytes
hashVal3 = SHA3_256.new(U)
k_HMAC = int.from_bytes(hashVal3.digest(), 'big') % n
k_HMAC_bytes = k_HMAC.to_bytes((k_HMAC.bit_length() + 7) // 8, byteorder='big')
print("\nT is ({} , {})".format(hex(T.x), hex(T.y)))
print("U is: ",U)
print("HMAC key is created ", k_HMAC_bytes)

print("+++++++++++++++++++++++++++++++++++++++++++++ \n")

OTK_s = {0: '', 1: '', 2: '', 3:'',4:'',5:'',6:'',7:'',8:'',9:''}
OTK_hmacs = {0: '', 1: '', 2: '', 3:'',4:'',5:'',6:'',7:'',8:'',9:''}
print("\nCreating OTK_s starting from index 0...")
for i in range(11):
    OTK0_private, OTK0 = generate_keypair(P, n)
    if i < 10:
        OTK_s[i] = [OTK0_private, OTK0.x, OTK0.y]
    print("\n{}th key generated.".format(i))
    print("Private Part= ", OTK0_private)
    print("Public (x coordinate)=",OTK0.x)
    print("Public (y coordinate)=",OTK0.y)
    OTK0_x_bytes = OTK0.x.to_bytes((OTK0.x.bit_length() + 7) // 8, byteorder='big')
    OTK0_y_bytes = OTK0.y.to_bytes((OTK0.y.bit_length() + 7) // 8, byteorder='big')
    temp = OTK0_x_bytes + OTK0_y_bytes
    print("x and y coordinates of the OTK converted to bytes and concatanated")
    print("message: ", temp)
    hmac0 = HMAC.new(key=k_HMAC_bytes, msg=temp, digestmod=SHA256)
    print("\nhmac is calculated and converted with 'hexdigest()': ", hmac0.hexdigest())
    OTK_hmacs[i] = hmac0.hexdigest()
    #REGISTERING OTK ON SERVER
    OTKReg(i, OTK0.x, OTK0.y, hmac0.hexdigest())

print("+++++++++++++++++++++++++++++++++++++++++++++ \n")

# print("\nTrying to delete OTK_s...")
# h_del, s_del = sign(P,n, privA, stuID_bytes)
# ResetOTK(h_del, s_del)

# print("\nTrying to delete SPK...")
# ResetSPK(h_del, s_del)

print("+++++++++++++++++++++++++++++++++++++++++++++ \n")

#REQUEST PSEUDO CLIENT TO SEND 5 MESSAGES TO INBOX
print("\n Checking the inbox for incoming messages")
print("+++++++++++++++++++++++++++++++++++++++++++++ \n")
print("\nSigning my stuID with my private IK")
h_msg, s_msg = sign(P,n, privA, stuID_bytes)
PseudoSendMsg(h_msg, s_msg)
print("\nYour favourite pseudo-client sent you 5 messages. You can get them from the server")
print("+++++++++++++++++++++++++++++++++++++++++++++ \n")

#DOWNLOAD MESSAGES FROM CLIENT
received_message = []
for i in range(5):
    message = ReqMsg(h_msg,s_msg)
    received_message.append(message)


#KDFs INITIALIZED
KDFs = {0: [], 1: [], 2: [], 3:[], 4:[],5:[],6:[],7:[],8:[],9:[]}

#LIST TO STORE PLAINTEXT MESSAGES
list_plaintext = []

#FOR EACH MESSAGE RECEIVED
for i in range(len(received_message)):
    client_ID = received_message[i][0]
    OTKID = received_message[i][1]
    msgID = received_message[i][2]
    client_message= received_message[i][3]
    EK_x = received_message[i][4]
    EK_y = received_message[i][5]
    print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n")
    print("\nI got this from client {}: {}".format(client_ID, client_message))
    print("Converting Message to bytes to decrypt it...")
    client_message_bytes = client_message.to_bytes((client_message.bit_length() + 7) // 8, byteorder='big')
    print("Converted Message is: ", client_message_bytes)
    
    #SEPERATE NONCE, CIPHERTEXT AND HMAC
    nonce = client_message_bytes[:8]
    ciphertext = client_message_bytes[8:len(client_message_bytes)-32]
    hmac = client_message_bytes[len(client_message_bytes)-32:]

    #GENERATE SESSION KEY
    print("\nGenerating Session Key ks, kenc, khmac and the HMAC value ....\n")
    otk_pri = OTK_s[OTKID][0]
    EK = Point(EK_x, EK_y, curve)
    T = otk_pri * EK
    Tx_bytes = T.x.to_bytes((T.x.bit_length() + 7) // 8, byteorder='big')
    Ty_bytes = T.y.to_bytes((T.y.bit_length() + 7) // 8, byteorder='big')
    U = Tx_bytes + Ty_bytes + b'ToBeOrNotToBe' 
    hashVal3 = SHA3_256.new(U)
    KS = int.from_bytes(hashVal3.digest(), 'big') % n
    KS_bytes = KS.to_bytes((KS.bit_length() + 7) // 8, byteorder='big')
    
    #KEY DERIVATION FUNCTION (KDF) CHAIN
    if msgID == 1:
        KDFs[OTKID].append(KS)

    #COMPUTING OUPUTS OF KDF
    for k in range(len(KDFs[OTKID])):
        kdf = KDFs[OTKID][k]
        kdf_bytes = kdf.to_bytes((kdf.bit_length() + 7) // 8, byteorder='big')

        temp = kdf_bytes + b'YouTalkingToMe'
        hashVal = SHA3_256.new(temp)
        Kenc = int.from_bytes(hashVal.digest(), 'big') % n
        Kenc_bytes = Kenc.to_bytes((Kenc.bit_length() + 7) // 8, byteorder='big')  

        temp =  kdf_bytes + Kenc_bytes + b'YouCannotHandleTheTruth'
        hashVal = SHA3_256.new(temp)
        Khmac = int.from_bytes(hashVal.digest(), 'big') % n
        Khmac_bytes = Khmac.to_bytes((Khmac.bit_length() + 7) // 8, byteorder='big')      

        temp = Kenc_bytes + Khmac_bytes + b'MayTheForceBeWithYou'
        hashVal = SHA3_256.new(temp)
        Knext = int.from_bytes(hashVal.digest(), 'big') % n
        Knext_bytes = Knext.to_bytes((Knext.bit_length() + 7) // 8, byteorder='big')             

    KDFs[OTKID].append(Knext)
    
    #VERIFYING HMAC VALUES OF THE MESSAGES AND DECRYPTING THEM
    val = HMAC.new(Khmac_bytes, ciphertext, digestmod=SHA256)
    calculated_hmac = val.digest()
    print("\nCalculated hmac: ", calculated_hmac)
    if calculated_hmac == hmac:
        print("Hmac verified")
        cipher = AES.new(Kenc_bytes, AES.MODE_CTR, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        print("\nCreate an AES object with Kenc then decrypt the ciphertext:\nPlaintext is:",plaintext.decode('utf-8'))
        Checker(stuID, client_ID, msgID, plaintext.decode("UTF-8"))
        list_plaintext.append(["Message-", i,  plaintext.decode("UTF-8")])
    else:
        #IF HMAC IF INVALID SET DECMSG TO INVALIDHMAC
        print("Hmac couldn't be verified")
        Checker(stuID, client_ID, msgID, "INVALIDHMAC")
        list_plaintext.append(["Message-", i, "Faulty message"])

print("\n +++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
#ASKING THE SERVER IF PSEUDO CLIENT HAS DELETED SOME MESSAGES

message2 = ReqDelMsg(h_msg,s_msg)


#FINAL DISPLAY BLOCK
print("\nChecking whether there were some deleted messages!!! \n")
print("=========================================================== \n")
for j in range(1, 6):
    if j in message2:
        print("Message " + str(j) + "-"  + " Was deleted by sender - X")
    else:
        print("Message " + str(j) + "-" + str(list_plaintext[j-1][2]) + "- Read")

#RESET IK (MUST BE DONE EVERYTHING TIME IN ORDER TO START A NEW RUN!!)
rver_code = int(input("\n Enter reset code which is sent to you: \n"))
#rver_code = 691361
ResetIK(rver_code)
    

    
        


