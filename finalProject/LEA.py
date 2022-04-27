"""
Lightweight Encryption Algorithm (LEA)
    by Michel Qu
"""

### Test value for a 128-bit key
plaintext128 = 0x101112131415161718191a1b1c1d1e1f
key128 = 0x0f1e2d3c4b5a69788796a5b4c3d2e1f0

### Test value for a 192-bit key
plaintext192 = 0x202122232425262728292a2b2c2d2e2f
key192 = 0x0f1e2d3c4b5a69788796a5b4c3d2e1f0f0e1d2c3b4a59687

### Test value for a 256-bit key
plaintext256 = 0x303132333435363738393a3b3c3d3e3f
key256 = 0x0f1e2d3c4b5a69788796a5b4c3d2e1f0f0e1d2c3b4a5968778695a4b3c2d1e0f

### Constant values 
deltaList = [0xc3efe9db,0x44626b02,0x79e27c8a,0x78df30ec,0x715ea49e,0xc785da0a,0xe04ef22a,0xe5c40957]

def conversion(key,keysize):
    "Convert the 128-key in 4 32-bit block"
    string = bin(key)
    list1 = []
    list1[:0]=string
    list1 = list1[2:] 
    
    "For a 4/6/8 number of 32-bit block"
    result = []
    n = len(list1)
    temp = ''
    ### ------------------------------------
    " 128-bit lenght key "
    ### ------------------------------------
    if(keysize == 128) : 
        "4 blocks of 32-bit"
        a = 128 - n  #number of zero to add
        for i in range (a) :
            temp = temp + '0'
            if (len(temp) == 32) : 
                result.append(int(temp,2))
                temp = ''
        for i in range (n) : 
            temp = temp + list1[i]
            if (len(temp) == 32) : 
                result.append(int(temp,2))
                temp = ''
                

    ### ------------------------------------
    " 192-bit lenght key "
    ### ------------------------------------
    if(keysize == 192) : 
        "5 blocks of 32-bit"
        a = 192 - n  #number of zero to add
        for i in range (a) :
            temp = temp + '0'
            if (len(temp) == 32) : 
                result.append(int(temp,2))
                temp = ''
        for i in range (n) : 
            temp = temp + list1[i]
            if (len(temp) == 32) : 
                result.append(int(temp,2))
                temp = ''
                
                
    ### ------------------------------------
    " 256-bit lenght key "
    ### ------------------------------------
    if(keysize == 256) : 
        "6 blocks of 32-bit"
        a = 256 - n  #number of zero to add
        for i in range (a) :
            temp = temp + '0'
            if (len(temp) == 32) : 
                result.append(int(temp,2))
                temp = ''
        for i in range (n) : 
            temp = temp + list1[i]
            if (len(temp) == 32) : 
                result.append(int(temp,2))
                temp = ''
    return result

def deconversion(blockList) : 
    "Convert the 4 32-bit blocks in a 128-bit key"
    a = bin(blockList[0])
    b = bin(blockList[1])[2:] # Remove the '0b'
    c = bin(blockList[2])[2:] # Remove the '0b'
    d = bin(blockList[3])[2:] # Remove the '0b'
    
    # We assure that the four block are 32-bit lenght
    while len(b) < 32 : 
        b = '0'+b
    while len(c) < 32 : 
        c = '0'+c
    while len(d) < 32 : 
        d = '0'+d
    
    # We concatenate the four blocks into one 128-bit lenght block
    result = a+b+c+d
    result = int(result,2)
    return result

def roundKeyGeneration(key,keysize):
    "This function generates the list of roundKeys"
    n_round = 0
    K = []
    "Key-schedule for LEA-128"
    if (keysize == 128) : 
        n_round = 24
        T = conversion(key,keysize)
        for i in range (n_round) :
            T[0] = bitwiseRotation(modularAddition(T[0], bitwiseRotation(deltaList[i%4],-1,i)),-1,1)
            T[1] = bitwiseRotation(modularAddition(T[1], bitwiseRotation(deltaList[i%4],-1,i+1)),-1,3)
            T[2] = bitwiseRotation(modularAddition(T[2], bitwiseRotation(deltaList[i%4],-1,i+2)),-1,6)
            T[3] = bitwiseRotation(modularAddition(T[3], bitwiseRotation(deltaList[i%4],-1,i+3)),-1,11)
            temp = [T[0],T[1],T[2],T[1],T[3],T[1]]
            K.append(temp)
    "Key-schedule for LEA-192"
    if (keysize == 192) : 
        n_round = 28
        T = conversion(key,keysize)
        for i in range (n_round) : 
            T[0] = bitwiseRotation(modularAddition(T[0], bitwiseRotation(deltaList[i%6],-1,i)),-1,1)
            T[1] = bitwiseRotation(modularAddition(T[1], bitwiseRotation(deltaList[i%6],-1,i+1)),-1,3)
            T[2] = bitwiseRotation(modularAddition(T[2], bitwiseRotation(deltaList[i%6],-1,i+2)),-1,6)
            T[3] = bitwiseRotation(modularAddition(T[3], bitwiseRotation(deltaList[i%6],-1,i+3)),-1,11)
            T[4] = bitwiseRotation(modularAddition(T[4], bitwiseRotation(deltaList[i%6],-1,i+4)),-1,13)
            T[5] = bitwiseRotation(modularAddition(T[5], bitwiseRotation(deltaList[i%6],-1,(i+5)%32)),-1,17)
            temp = [T[0],T[1],T[2],T[3],T[4],T[5]]
            K.append(temp)
    "Key-schedule for LEA-256"
    if (keysize == 256) : 
        n_round = 32
        T = conversion(key,keysize)
        for i in range (n_round) : 
            T[(6*i)%8] = bitwiseRotation(modularAddition(T[(6*i)%8], bitwiseRotation(deltaList[i%8],-1,i%32)),-1,1)
            T[((6*i)+1)%8] = bitwiseRotation(modularAddition(T[((6*i)+1)%8], bitwiseRotation(deltaList[i%8],-1,(i+1)%32)),-1,3)
            T[((6*i)+2)%8] = bitwiseRotation(modularAddition(T[((6*i)+2)%8], bitwiseRotation(deltaList[i%8],-1,(i+2)%32)),-1,6)
            T[((6*i)+3)%8] = bitwiseRotation(modularAddition(T[((6*i)+3)%8], bitwiseRotation(deltaList[i%8],-1,(i+3)%32)),-1,11)
            T[((6*i)+4)%8] = bitwiseRotation(modularAddition(T[((6*i)+4)%8], bitwiseRotation(deltaList[i%8],-1,(i+4)%32)),-1,13)
            T[((6*i)+5)%8] = bitwiseRotation(modularAddition(T[((6*i)+5)%8], bitwiseRotation(deltaList[i%8],-1,(i+5)%32)),-1,17)
            temp = [T[(6*i)%8],T[((6*i)+1)%8],T[((6*i)+2)%8],T[((6*i)+3)%8],T[((6*i)+4)%8],T[((6*i)+5)%8]]
            K.append(temp)
    return (K)
    
def encryption(plaintext,key,keysize) : 
    "This function encrypts the plaintext with the key"
    X = conversion(plaintext,128) # The plaintext is always 128-bit
    K = roundKeyGeneration(key,keysize) # Generates all the roundkey associated to the key lenght
    #print(f'The lenght of Roundkey is : {len(K)}')
    Nr = len(K)
    for i in range(Nr) : 
        temp = []
        temp.append( bitwiseRotation(modularAddition(bitwiseXOR(X[0],K[i][0]),bitwiseXOR(X[1],K[i][1])),-1,9) )
        temp.append( bitwiseRotation(modularAddition(bitwiseXOR(X[1],K[i][2]),bitwiseXOR(X[2],K[i][3])),1,5) )
        temp.append( bitwiseRotation(modularAddition(bitwiseXOR(X[2],K[i][4]),bitwiseXOR(X[3],K[i][5])),1,3) )
        temp.append( X[0] )
        X = temp
    C = deconversion(X) # Rebuild a 128-bit ciphertext
    return(C)

def decryption(ciphertext,key,keysize) : 
    "This function decrypts the ciphertext with the key"
    X = conversion(ciphertext,128) # The ciphertext is always 128-bit
    K = roundKeyGeneration(key,keysize) # Generates all the roundkey associated to the key lenght
    Nr = len(K)
    for i in range (Nr-1,-1,-1) : 
        temp = []
        temp.append( X[3] )
        temp.append( bitwiseXOR(modularDifference(bitwiseRotation(X[0],1,9),bitwiseXOR(temp[0],K[i][0])), K[i][1]))
        temp.append( bitwiseXOR(modularDifference(bitwiseRotation(X[1],-1,5),bitwiseXOR(temp[1],K[i][2])), K[i][3]))
        temp.append( bitwiseXOR(modularDifference(bitwiseRotation(X[2],-1,3),bitwiseXOR(temp[2],K[i][4])), K[i][5]))
        X = temp
    P = deconversion(X) # Rebuild a 128-bit plaintext
    return (P)
        
def bitwiseXOR(blockA,blockB) :
    "This function makes a bitwise XOR on a 32-bit block"
    return (blockA^blockB)

def bitwiseRotation(block,rotation,number) :
    "This function makes a bitwise rotation on a 32-bit block"
    if (rotation == -1) : 
        "Left rotation "
        block = rotate_left(block, number)
    elif (rotation == 1) :
        "Right rotation "
        block = rotate_right(block, number)
    else :
        print("Wrong Rotation Input !")
    return (block)

def modularAddition(blockA,blockB) :
    "This function makes a modular addition on a 32-bit block"
    block = (blockA + blockB) % (0xffffffff)
    return (block)

def modularDifference(blockA,blockB) :
    "This function makes a modular difference on a 32-bit block"
    block = (blockA - blockB) % (0xffffffff)
    return (block)

def rotate_right(x, n):
    "This function makes a right bitwise rotation of n-bit on a 32-bit block"
    a = x >> n
    b = x << (32-n)
    c = a|b 
    d = c & 0xffffffff
    return (d)

def rotate_left(x, n):
    "This function makes a left bitwise rotation of n-bit on a 32-bit block"
    a = rotate_right(x, 32-n)
    return a
    
def test () : 
    "For 128 bit length key"
    c = encryption(plaintext128,key128,128)
    m = decryption(c,key128,128)
    print('----------------------')
    print(f'The plaintext to cipher is {plaintext128}')
    print(f'The encryption for plaintext128 by key128 gives c = {c}')
    print(f'The decryption of the ciphertext gives m = {m}')
    print(f'We verify if m = plaintext128 : {m == plaintext128}')
    
    "For 192 bit length key"
    c = encryption(plaintext192,key192,192)
    m = decryption(c,key192,192)
    print('----------------------')
    print(f'The plaintext to cipher is {plaintext192}')
    print(f'The encryption for plaintext192 by key192 gives c = {c}')
    print(f'The decryption of the ciphertext gives m = {m}')
    print(f'We verify if m = plaintext192 : {m == plaintext192}')
    
    "For 256 bit length key"
    c = encryption(plaintext256,key256,256)
    m = decryption(c,key256,256)
    print('----------------------')
    print(f'The plaintext to cipher is {plaintext256}')
    print(f'The encryption for plaintext256 by key256 gives c = {c}')
    print(f'The decryption of the ciphertext gives m = {m}')
    print(f'We verify if m = plaintext256 : {m == plaintext256}')
    return 0

if __name__ == "__main__":
    test()