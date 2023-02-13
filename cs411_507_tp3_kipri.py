#SUDE BUKET KIPRI
#IMPLEMENTING SIGNAL PROTOCOL

#PHASE 2

import math
import time
import random
import sympy
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

def SendMsg(idA, idB, otkID, msgid, msg, ekx, eky):
    mes = {"IDA": idA, "IDB": idB, "OTKID": int(otkID), "MSGID": msgid, "MSG": msg, "EK.X": ekx, "EK.Y": eky}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SendMSG"), json=mes)
    print(response.json())    
        
def reqOTKB(stuID, stuIDB, h, s):
    OTK_request_msg = {'IDA': stuID, 'IDB':stuIDB, 'S': s, 'H': h}
    print("Requesting party B's OTK ...")
    response = requests.get('{}/{}'.format(API_URL, "ReqOTK"), json=OTK_request_msg)
    print(response.json()) 
    if((response.ok) == True):
        print(response.json()) 
        res = response.json()
        return res['KEYID'], res['OTK.X'], res['OTK.Y']
        
    else:
        return -1, 0, 0

def Status(stuID, h, s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "Status"), json=mes)
    print(response.json())
    if (response.ok == True):
        res = response.json()
        return res['numMSG'], res['numOTK'], res['StatusMSG']

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

# GENERATE SIGNATURE
def verify_sign(P, n, s, h, pubA, message):
    V = s*P - h*pubA
    v = (V.x) % n
    v_bytes = v.to_bytes((v.bit_length() + 7) // 8, byteorder='big')
    hashVal = SHA3_256.new(v_bytes + message)
    h_ver = int.from_bytes(hashVal.digest(), 'big') % n
    if h_ver == h:
        print("Verified!\n") 

def create_KDF_chain(chain_no, KS_bytes):

    kenc_array = []
    khmac_array = []
    kdf_bytes = KS_bytes
    for i in range(chain_no):
        #print("GIRDIK")
        temp = kdf_bytes + b'YouTalkingToMe'
        hashVal = SHA3_256.new(temp)
        Kenc = int.from_bytes(hashVal.digest(), 'big') % n
        Kenc_bytes = Kenc.to_bytes((Kenc.bit_length() + 7) // 8, byteorder='big')   
        #print("Kenc{} is: {}".format(i+1, Kenc_bytes))

        temp =  kdf_bytes + Kenc_bytes + b'YouCannotHandleTheTruth'
        hashVal = SHA3_256.new(temp)
        Khmac = int.from_bytes(hashVal.digest(), 'big') % n
        Khmac_bytes = Khmac.to_bytes((Khmac.bit_length() + 7) // 8, byteorder='big')      
        #print("Khmac{} is: {}".format(i+1, Khmac_bytes))

        temp = Kenc_bytes + Khmac_bytes + b'MayTheForceBeWithYou'
        hashVal = SHA3_256.new(temp)
        Knext = int.from_bytes(hashVal.digest(), 'big') % n
        Knext_bytes = Knext.to_bytes((Knext.bit_length() + 7) // 8, byteorder='big')  
        
        kdf_bytes = Knext_bytes
        kenc_array.append(Kenc_bytes)
        khmac_array.append(Khmac_bytes)

    return kenc_array, khmac_array

def Encryption(message, kenc, khmac):
    
    cipher = AES.new(kenc, AES.MODE_CTR)
    ciphertext = cipher.encrypt(message)
    hmac = HMAC.new(key=khmac, msg=ciphertext, digestmod=SHA256)
    hmac_ = hmac.digest()
    result = cipher.nonce + ciphertext + hmac_
    
    return int.from_bytes(result, byteorder="big")  

# IDENTITY KEY PAIR GENERATION
privA, pubA = generate_keypair(P, n)
print("Identitiy Key is created")
print("Identity key is created: \n IK.Pri : {} \n IK.Pub : {}".format(privA, pubA))
print("\nMy ID number is: ",stuID)

print("+++++++++++++++++++++++++++++++++++++++++++++ \n")

print("\nSignature of my ID number is:")
h, s = sign(P, n, privA, stuID_bytes)

print("\nSending signature and my IKEY to server via IKRegReq() function in json format")
# REGISTER IDENTITY KEY ON SERVER
IKRegReq(h, s, pubA.x, pubA.y)

print("+++++++++++++++++++++++++++++++++++++++++++++ \n")
print("\nReceived the verification code through email")
code = input("Enter verification code which is sent to you: ")
print("Sending the verification code to server via IKRegVerify() function in json format")
IKRegVerify(int(code)) #code = 148951

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
hashval = SHA3_256.new(U)
k_HMAC = int.from_bytes(hashval.digest(), 'big') % n
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
    OTKID_last = 9

print("+++++++++++++++++++++++++++++++++++++++++++++ \n")
Status(stuID, h,s)
# print("\nTrying to delete OTK_s...")
#h_del, s_del = sign(P,n, privA, stuID_bytes)
# ResetOTK(h_del, s_del)
#print("\nNew Feature: Checking the status of the inbox and keys! Just send your signature of ID number and your ID via Status method")
#Status(stuID_bytes, h_del, s_del)

# print("\nTrying to delete SPK...")
# ResetSPK(h_del, s_del)

print("+++++++++++++++++++++++++++++++++++++++++++++ \n")

#REQUEST PSEUDO CLIENT TO SEND 5 MESSAGES TO INBOX
print("\nTelling pseudoclient to send me messages using PseudoSendMsg")
print("\nSigning my stuID with my private IK")
h_msg, s_msg = sign(P,n, privA, stuID_bytes)
PseudoSendMsg(h_msg, s_msg)

print("\nChecking the status of the inbox and keys...")
Status(stuID, h_msg ,s_msg)

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
    client_msg= received_message[i][3]
    EK_x = received_message[i][4]
    EK_y = received_message[i][5]
    print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n")
    print("\nI got this from client {}: {}".format(client_ID, client_msg))
    print("Converting Message to bytes to decrypt it...")
    client_msg_bytes = client_msg.to_bytes((client_msg.bit_length() + 7) // 8, byteorder='big')
    print("Converted Message is: ", client_msg_bytes)
    
    #SEPERATE NONCE, CIPHERTEXT AND HMAC
    nonce = client_msg_bytes[:8]
    ciphertext = client_msg_bytes[8:len(client_msg_bytes)-32]
    hmac = client_msg_bytes[len(client_msg_bytes)-32:]

    #GENERATE SESSION KEY
    print("\nGenerating Session Key ks, kenc, khmac and the HMAC value ....\n")
    otk_priv = OTK_s[OTKID][0]
    EK = Point(EK_x, EK_y, curve)
    T = otk_priv * EK
    Tx_bytes = T.x.to_bytes((T.x.bit_length() + 7) // 8, byteorder='big')
    Ty_bytes = T.y.to_bytes((T.y.bit_length() + 7) // 8, byteorder='big')
    U = Tx_bytes + Ty_bytes + b'ToBeOrNotToBe' 
    #print("U is: ", U)
    hash_val = SHA3_256.new(U)
    KS = int.from_bytes(hash_val.digest(), 'big') % n
    KS_bytes = KS.to_bytes((KS.bit_length() + 7) // 8, byteorder='big')
    #print("Ks is:",KS_bytes)
    
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
        #print("Kenc{} is: {}".format(k+1, Kenc_bytes))

        temp =  kdf_bytes + Kenc_bytes + b'YouCannotHandleTheTruth'
        hashVal = SHA3_256.new(temp)
        Khmac = int.from_bytes(hashVal.digest(), 'big') % n
        Khmac_bytes = Khmac.to_bytes((Khmac.bit_length() + 7) // 8, byteorder='big')      
        #print("Khmac{} is: {}".format(k+1, Khmac_bytes))

        temp = Kenc_bytes + Khmac_bytes + b'MayTheForceBeWithYou'
        hashVal = SHA3_256.new(temp)
        Knext = int.from_bytes(hashVal.digest(), 'big') % n
        Knext_bytes = Knext.to_bytes((Knext.bit_length() + 7) // 8, byteorder='big')             
        #print("Kkdf{} is: {}".format(k+1, Knext_bytes))

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
#START OF PHASE 3
Status(stuID, h_msg, s_msg)
print("\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
print("\nStart of Phase 3")
#COMMUNCATING WITH PSEUDO-CLIENT
FriendID = 26045
FriendID_bytes = FriendID.to_bytes((FriendID.bit_length() + 7) // 8, byteorder='big')
print("\nNow I want to send messages to the pseudo-client since i have no group mate. the id is 26045.")
print("Signing The stuIDB of party B with my private IK")
h_friend, s_friend = sign(P,n, privA, FriendID_bytes)
#REQUESTING THE OTHER PARTY'S OTK PUBLIC KEY
friend_return = reqOTKB(stuID, FriendID, h_friend, s_friend)
print("The other party's OTK public key is acquired from the server ...")
FriendOTKID = friend_return[0]
FriendOTK_X = friend_return[1]
fFriendOTK_Y = friend_return[2]
#GENERATING MY EPHEMERAL KEY
print("\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
print("Generating Ephemeral key")
priv_EK = random.randint(1, n-2)
my_EK = priv_EK * P
Sending_Msg = "Dormammu, I have come to bargain"
print("This is the message i want to send:", Sending_Msg)
Sending_Msg = b"Dormammu, I have come to bargain"

friend_OTK_pub = Point(FriendOTK_X,fFriendOTK_Y, curve)
#GENERATING THE KDF CHAIN AND SESSION KEY
print("Generating the KDF chain for the encryption and the MAC value generation")
print("Generating session key using my EK and pseudo-client's Public OTK/ Phase 3...")
T = friend_OTK_pub * priv_EK
Tx_bytes = T.x.to_bytes((T.x.bit_length() + 7) // 8, byteorder='big')
Ty_bytes = T.y.to_bytes((T.y.bit_length() + 7) // 8, byteorder='big')
U = Tx_bytes + Ty_bytes + b'ToBeOrNotToBe'    

hash_val2 = SHA3_256.new(U)
KS = int.from_bytes(hash_val2.digest(), 'big') % n
KS_bytes = KS.to_bytes((KS.bit_length() + 7) // 8, byteorder='big')

kenc_array, khmac_array = create_KDF_chain(2, KS_bytes)
#for i in range(1, len(kenc_array)):
    #print("Kenc{} is: {}".format(i+1, kenc_array[i]))
    #print("Khmac{} is: {}".format(i+1, khmac_array[i]))

#ENCRYPTING THE MESSAGE
print("\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
my_message = Encryption(Sending_Msg, kenc_array[0], khmac_array[0])
print("\nSending the message to the server, so it would deliver it to my friend whenever she is active ...")
SendMsg(stuID, FriendID, FriendOTKID, 1, my_message, my_EK.x, my_EK.y)

#SENDING ONE MORE MESSAGE
print("\nI will send one more message")
Sending_Msg = "I've come to talk with you again"
print("The message i want to send:", Sending_Msg)
Sending_Msg = b"I've come to talk with you again"
print("Generating the KDF chain for the encryption and the MAC value generation")
my_message = Encryption(Sending_Msg, kenc_array[1], khmac_array[1])
print("Sending the message to the server, so it would deliver it to pseudo-client/user whenever it is active ...")
SendMsg(stuID, FriendID, FriendOTKID, 2, my_message, my_EK.x, my_EK.y)

#eNCRYPTING THE NESSAGES PREVIOUSLY RECEIVED IN PHASE 2 AND SENDING THEM TO CLIENT
print("\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
print("\nNow I'll encrypt the messages I retrieved initially from the server and send it to pseudo-client (26045)")
print("Since i am not working in a group i am communicating with the pseudo-client directly")
print("Generating the KDF chain for the encryption and the MAC value generation")
kenc_array, khmac_array = create_KDF_chain(5, KS_bytes)

print("\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
print("\n Get the message from the list of previously retrieved messages")
#print("U is:", U)
#print("Ks is:",KS_bytes)
#SINCE I AM COMMUNICATING WITH THE PSEUDO-CLIENT AGAIN, I WILL NOT BE GENERATING A NEW EPHEMERAL KEY AND SESSION KEY
for i in range(len(kenc_array)):
    print("\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    print("Ephemeral key already generated and the session key is already generated")
    print("Sending the message to the server, so it would deliver it to pseudo-client/user whenever it is active ...")
    Sending_Msg = bytes(list_plaintext[i][2], 'utf-8')
    my_message = Encryption(Sending_Msg, kenc_array[i], khmac_array[i])
    #print("Kenc{} is: {}".format(i+1, kenc_array[i]))
    #print("Khmac{} is: {}".format(i+1, khmac_array[i]))
    SendMsg(stuID, FriendID, FriendOTKID, i+1, my_message, my_EK.x, my_EK.y)

#OTK MANAGEMENT AND STATUS CHECK
print("\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
print("\nChecking the status of the inbox and keys...")
status_check = Status(stuID, h_msg, s_msg)
if status_check[1] != 10:
    for i in range(10-status_check[1]):
        OTK0_private, OTK0 = generate_keypair(P, n)
        OTK_s[OTKID_last+1] = [OTK0_private, OTK0.x, OTK0.y]
        OTK0_x_bytes = OTK0.x.to_bytes((OTK0.x.bit_length() + 7) // 8, byteorder='big')
        OTK0_y_bytes = OTK0.y.to_bytes((OTK0.y.bit_length() + 7) // 8, byteorder='big')
        temp = OTK0_x_bytes + OTK0_y_bytes
        hmac0 = HMAC.new(key=k_HMAC_bytes, msg=temp, digestmod=SHA256)
        OTKReg(OTKID_last+1, OTK0.x, OTK0.y, hmac0.hexdigest())
        OTKID_last += 1

# SINCE I USED ONE OTK, I GENERATED A NEW ONE, MAKING THE TOTAL 10 OTKS
#print(OTK_s)
print("\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
print("Checking the status of the inbox")
Status(stuID, h_msg, s_msg)
print("\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
#RESET IK (MUST BE DONE EVERYTHING TIME IN ORDER TO START A NEW RUN!!)
rver_code = int(input("\n Enter reset code which is sent to you: \n"))
ResetIK(rver_code) #rver_code = 202957
    

    
        


