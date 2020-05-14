#!/usr/bin/python3
from Crypto.Cipher import AES
from Crypto import Random
import os,hashlib,binascii,base64,random,ast,sys

class MerkleTreeNode:
    def __init__(self,value):
        self.left = None
        self.right = None
        self.value = value
        self.hashValue = hashlib.sha256(value.encode('utf-8')).hexdigest()

candidates = {"1":"Candidate 1","2":"Candidate 2"}
mode = AES.MODE_CFB

def createKeys(filePath):
    key = random.SystemRandom().randrange(2**(51),2**(52))
    Iv = Random.new().read(AES.block_size)
    f1 = open(filePath,"w")
    f1.write(str(key)+"\n")
    f1.write(base64.b64encode(Iv).decode('utf-8'))
    f1.close()
    return key,Iv

def readKeys(filePath):
    with open(filePath) as f:
        d1 = f.readlines()
    key = int(d1[0])
    b1 = d1[1]
    Iv = base64.b64decode(b1.encode('utf-8'))
    return key,Iv

def alreadyRegistered(uniqueId):
    voterId = hashlib.sha256(uniqueId.encode('utf-8')).hexdigest()
    return checkInVoterId(voterId)

def register(uniqueId):
    uniqueIdHash = hashlib.sha256(uniqueId.encode('utf-8')).hexdigest()
    path = "voterIds.txt"
    if os.path.exists(path):
        voterIdKey,voterIdIv = readKeys("voterIdKey.txt")
        with open(path) as f:
            d = f.readlines()
        encDistString = d[0]
        
        try:
            e = base64.b64decode(encDistString.encode('utf-8'))
        except binascii.Error:
            print("The voterIds file was modified. This incident has been noted!!")
            sys.exit("Integrity check failed")
        
        dCipher = AES.new(str(voterIdKey).encode("utf8"), mode, voterIdIv)
        plaintext = dCipher.decrypt(e)
        plaintext = plaintext.decode('utf-8').strip('\x10\x04\r\x08')
        voterIds = ast.literal_eval(plaintext)
        voterIds[uniqueId] = uniqueIdHash
        f1 = open(path,"w")
        eCipher = AES.new(str(voterIdKey).encode("utf8"), mode, voterIdIv)
        enc = eCipher.encrypt(str(voterIds).encode('utf-8'))
        f1.write(base64.b64encode(enc).decode('utf-8'))
        f1.close()
    else:
        voterIdKey,voterIdIv = createKeys("voterIdKey.txt")
        voterIds = {}
        voterIds[uniqueId] = uniqueIdHash
        f1 = open(path,"w")
        eCipher = AES.new(str(voterIdKey).encode("utf8"), mode, voterIdIv)
        enc = eCipher.encrypt(str(voterIds).encode('utf-8'))
        f1.write(base64.b64encode(enc).decode('utf-8'))
        f1.close()

    return uniqueIdHash

def checkInVoterId(voterId):
    path = "voterIds.txt"
    if os.path.exists(path): 
        voterIdKey,voterIdIv = readKeys("voterIdKey.txt")
        with open(path) as f:
            d = f.readlines()
        encDistString = d[0]
        
        try:
            e = base64.b64decode(encDistString.encode('utf-8'))
        except binascii.Error:
            print("The voterIds file was modified. This incident has been noted!!")
            sys.exit("Integrity check failed")
        
        dCipher = AES.new(str(voterIdKey).encode("utf8"), mode, voterIdIv)
        plaintext = dCipher.decrypt(e)
        plaintext = plaintext.decode('utf-8').strip('\x10\x04\r\x08')
        
        voterIds = ast.literal_eval(plaintext)
        return voterId in voterIds.values() 
    else:
        return False

def alreadyVoted(voterId):
    path = "votes.txt"
    if os.path.exists(path):
        votesKey,votesIv = readKeys("votesKey.txt")
        with open(path) as f:
            d = f.readlines()
        encDistString = d[0]
        
        try:
            e = base64.b64decode(encDistString.encode('utf-8'))
        except binascii.Error:
            print("The votes file was modified. This incident has been noted!!")
            sys.exit("Integrity check failed")  
        
        dCipher = AES.new(str(votesKey).encode("utf8"), mode, votesIv)
        plaintext = dCipher.decrypt(e)
        plaintext = plaintext.decode('utf-8').strip('\x10\x04\r\x08')
        votes = ast.literal_eval(plaintext)
        for value in votes.values():
            if voterId in value:
                return True
        return False
    else:
        return False

def vote(candidateNumber,voterId):
    string = "merkleNodeList"+candidateNumber+".txt"
    merkleFile = "merkle"+candidateNumber+".tree"
    if os.path.exists(string):
        nodeListKey,nodeListIv = readKeys("nodeListKey.txt")
        with open(string) as f2:
            d = f2.readlines()
        encListString = d[0]
        e = base64.b64decode(encListString.encode('utf-8'))
        dCipher = AES.new(str(nodeListKey).encode("utf8"), mode, nodeListIv)
        plaintext = dCipher.decrypt(e)
        plaintext = plaintext.decode('utf-8').strip('\x10\x04\r\x08')
        merkleNodeList = ast.literal_eval(plaintext)
        merkleNodeList.append(voterId)
        buildTree(merkleNodeList,merkleFile)
        f1 = open(string,"w")
        eCipher = AES.new(str(nodeListKey).encode("utf8"), mode, nodeListIv)
        enc = eCipher.encrypt(str(merkleNodeList).encode('utf-8'))
        f1.write(base64.b64encode(enc).decode('utf-8'))
        f1.close()
    else:
        nodeListKey,nodeListIv = createKeys("nodeListKey.txt")
        treeKey,treeIv = createKeys("treeKey.txt")
        f1 = open(string,"w")
        l = []
        l.append(voterId)
        voterIdHash = hashlib.sha256(voterId.encode('utf-8')).hexdigest()
        eCipher = AES.new(str(nodeListKey).encode("utf8"), mode, nodeListIv)
        enc = eCipher.encrypt(str(l).encode('utf-8'))
        f1.write(base64.b64encode(enc).decode('utf-8'))
        f1.close()
        f = open(merkleFile,"w")
        string = "Merkle Tree Node : "+voterId + " | Hash : " + voterIdHash
        eCipher = AES.new(str(treeKey).encode("utf8"), mode, treeIv)
        mEnc = eCipher.encrypt(string.encode('utf-8'))
        f.write(base64.b64encode(mEnc).decode('utf-8'))
        f.write("\n")
        f.close()

    candidate = candidates[candidateNumber]
    writeToVotesArray(candidate,voterId)


def writeToVotesArray(candidate,voterId):
    path = "votes.txt"
    if os.path.exists(path):
        votesKey,votesIv = readKeys("votesKey.txt")
        with open(path) as f:
            d = f.readlines()
        encDistString = d[0]
        
        try:
            e = base64.b64decode(encDistString.encode('utf-8'))
        except binascii.Error:
            print("The vote tally file was modified. This incident has been noted!!")
            sys.exit("Integrity check failed")  

        dCipher = AES.new(str(votesKey).encode("utf8"), mode, votesIv)
        plaintext = dCipher.decrypt(e)
        plaintext = plaintext.decode('utf-8').strip('\x10\x04\r\x08')
        votes = ast.literal_eval(plaintext)
        votes[candidate].append(voterId)
        f1 = open(path,"w")
        eCipher = AES.new(str(votesKey).encode("utf8"), mode, votesIv)
        enc = eCipher.encrypt(str(votes).encode('utf-8'))
        f1.write(base64.b64encode(enc).decode('utf-8'))
        f1.close()
    else:
        votesKey,votesIv = createKeys("votesKey.txt")
        votes = {"Candidate 1":[],"Candidate 2":[]}
        votes[candidate].append(voterId)
        f1 = open(path,"w")
        eCipher = AES.new(str(votesKey).encode("utf8"), mode, votesIv)
        enc = eCipher.encrypt(str(votes).encode('utf-8'))
        f1.write(base64.b64encode(enc).decode('utf-8'))
        f1.close()


def buildTree(leaves,merkleFile):
    f = open(merkleFile, "w")
    nodes = []
    for i in leaves:
        nodes.append(MerkleTreeNode(i))
    treeKey,treeIv= readKeys("treeKey.txt")
    while len(nodes)!=1:
        temp = []
        for i in range(0,len(nodes),2):
            node1 = nodes[i]
            if i+1 < len(nodes):
                node2 = nodes[i+1]
            else:
                temp.append(nodes[i])
                break
            lcString = "Left child : "+ node1.value + " | Hash : " + node1.hashValue
            rcString = "Right child : "+ node2.value + " | Hash : " + node2.hashValue
            eCipher = AES.new(str(treeKey).encode("utf8"), mode, treeIv)
            lcEnc = eCipher.encrypt(lcString.encode('utf-8'))
            rcEnc =  eCipher.encrypt(rcString.encode('utf-8'))
            f.write(base64.b64encode(lcEnc).decode('utf-8'))
            f.write("\n")
            f.write(base64.b64encode(rcEnc).decode('utf-8'))
            f.write("\n")
            concatenatedHash = node1.hashValue + node2.hashValue
            parent = MerkleTreeNode(concatenatedHash)
            parent.left = node1
            parent.right = node2
            parentString = "Parent(concatenation of "+ node1.value + " and " + node2.value + ") : " +parent.value + " | Hash : " + parent.hashValue
            parentEnc =  eCipher.encrypt(parentString.encode('utf-8'))
            f.write(base64.b64encode(parentEnc).decode('utf-8'))
            f.write("\n")
            temp.append(parent)
        nodes = temp
    f.close() 
    
def readMerkleNode(candidateNumber):
    filePath = "merkle"+candidateNumber+".tree"
    with open(filePath) as f:
        data = f.readlines()
    tree ={}
    treeKey,treeIv= readKeys("treeKey.txt")
    dCipher = AES.new(str(treeKey).encode("utf8"), mode, treeIv)
    for i in range(len(data)):
        if data[i]!="\n":
            try:
                e = base64.b64decode(data[i].encode('utf-8'))
            except binascii.Error:
                print("The votes file was modified. This incident has been noted!!")
                sys.exit("Integrity check failed")  

            plaintext = dCipher.decrypt(e)
            plaintext = plaintext.decode('utf-8').strip('\x10\x04\r\x08')
            lineArray = plaintext.split(" ")
            tree[lineArray[4]] = lineArray[8]
    return tree

def parseFile(candidateNumber):
    filePath = "merkle"+candidateNumber+".tree"
    with open(filePath) as f:
        data = f.readlines()
    tree ={}
    treeKey,treeIv= readKeys("treeKey.txt")
    dCipher = AES.new(str(treeKey).encode("utf8"), mode, treeIv)
    for i in range(len(data)):
        if data[i] !="\n":
            try:
                e = base64.b64decode(data[i].encode('utf-8'))
            except binascii.Error:
                print("The votes file was modified. This incident has been noted!!")
                sys.exit("Integrity check failed")  

            plaintext = dCipher.decrypt(e)
            plaintext = plaintext.decode('utf-8').strip('\x10\x04\r\x08')
            lineArray = plaintext.split(" ")
            if lineArray[0] == 'Parent(concatenation':
                tree[lineArray[6]] = lineArray[10]
            else:
                tree[lineArray[3]] = lineArray[7]
    return tree

def validate(voterId):
    path = "votes.txt"
    votesKey,votesIv = readKeys("votesKey.txt")
    with open(path) as f:
        d = f.readlines()
    encDistString = d[0]
     
    try:
        e = base64.b64decode(encDistString.encode('utf-8'))
    except binascii.Error:
        print("The vote tally file was modified. This incident has been noted!!")
        sys.exit("Integrity check failed")  

    dCipher = AES.new(str(votesKey).encode("utf8"), mode, votesIv)
    plaintext = dCipher.decrypt(e)
    plaintext = plaintext.decode('utf-8').strip('\x10\x04\r\x08')
    votes = ast.literal_eval(plaintext)
    candidate = ""
    votesLength = 0
    for key,value in votes.items():
        if voterId in value:
            candidate = key
            votesLength = len(value)
            break
    candidateNumber = ""
    for key,value in candidates.items():
        if candidate in value:
            candidateNumber = key
            break
    tree = None
    if votesLength ==1:
        tree = readMerkleNode(candidateNumber)
    else:
        tree = parseFile(candidateNumber)
    
    op = []
    for key,value in tree.items():
        if voterId in key:
            op.append(value)
            voterId = value
    return op

def printMerkleTree(candidateNumber):
    filePath = "merkle"+candidateNumber+".tree"
    with open(filePath) as f:
        data = f.readlines()
    treeKey,treeIv= readKeys("treeKey.txt")
    dCipher = AES.new(str(treeKey).encode("utf8"), mode, treeIv)
    for i in range(len(data)):
        if data[i]!="\n":
            try:
                e = base64.b64decode(data[i].encode('utf-8'))
            except binascii.Error:
                print("The votes file was modified. This incident has been noted!!")
                sys.exit("Integrity check failed")

            plaintext = dCipher.decrypt(e)
            plaintext = plaintext.decode('utf-8').strip('\x10\x04\r\x08')
            print(plaintext)
    f.close()

def viewVotes():
    path = "votes.txt"
    if os.path.exists(path):
        votesKey,votesIv = readKeys("votesKey.txt")
        with open(path) as f:
            d = f.readlines()
        encDistString = d[0]
        
        try:
            e = base64.b64decode(encDistString.encode('utf-8'))
        except binascii.Error:
            print("The vote tally file was modified. This incident has been noted!!")
            sys.exit("Integrity check failed") 
        
        dCipher = AES.new(str(votesKey).encode("utf8"), mode, votesIv)
        plaintext = dCipher.decrypt(e)
        plaintext = plaintext.decode('utf-8').strip('\x10\x04\r\x08')
        votes = ast.literal_eval(plaintext)
        for key,value in votes.items():
            print(key+" : "+str(len(value)))
    else:
        temp = {"Candidate 1":[],"Candidate 2":[]}
        for key,value in temp.items():
            print(key+" : "+str(len(value)))



if __name__ == "__main__":
    menu = {"1":"Register voter","2": "Vote","3":"Validate votes","4":"View votes","5":"Verify vote tally","6":"Exit"}

    print("Welcome to the Future of Voting!!")
    print("__________________________________")
    print()
    while True:    
        print("Please enter your option")
        for key,value in menu.items():
            print(key+"  :  "+value)
        selection = input()
        if selection=="1":
            uniqueId = input("Please enter your unique identification number : ")
            if alreadyRegistered(uniqueId):
                print("You have already registered in our system with this id. Please use the voter id received for voting")
            else:
                voterId = register(uniqueId)
                print("Your unique voter id number is : "+voterId)
                print("Please use this unique voter id number for voting. Thank you!!")
        elif selection=="2":
            voterId = input("Please enter your unique voter id number : ")
            if not checkInVoterId(voterId):
                print("Please enter a valid voter id number or register for casting vote")
            elif alreadyVoted(voterId):
                print("You have already voted in this election. Thank you for doing your part!!")
            else:
                print("Please choose the option number of the candidates")
                for key,value in candidates.items():
                    print(key+" : "+value)
                candidateNumber = input()
                if candidateNumber not in candidates.keys():
                    print("You have chosen a candidate that does not exist. Please choose the correct candidate!!")
                else:
                    vote(candidateNumber,voterId)
                    print("You have successfully cast your vote for "+candidates[candidateNumber])
                    print("Thank you for voting!!")
        elif selection=="3":
            voterId = input("Please enter your voter id number : ")
            if not checkInVoterId(voterId):
                print("Please enter a valid voter id number or register for casting vote")
            else:
                validation = validate(voterId)
                if len(validation)>0:
                    print("Your vote was successfully cast and recorded in our database")
                    print("The vote trail is ",validation)
                else:
                    print("Your vote was not validated. Please verify that you have voted properly!!")
        elif selection=="4":
            print("The vote tally currently is")
            viewVotes()
        elif selection == "5":
            candidateNumber = input("Please enter the candidate number whose votes need to be tallied : ")
            printMerkleTree(candidateNumber)
        elif selection=="6":
            print("Thank you for using our system.Bye!!")
            break
        else:
            print("You have selected a wrong option. Please choose the option from the given list of options")
