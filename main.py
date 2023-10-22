import random

#NOTE: Decryption algorythm is unfinished yet, specifically computation of reverse os S-Box

class cipher:
    #in __init__() there is an initialization of plaintext, key and text transformed to bin string
    def __init__(self, plaintext):
        self.plaintext = plaintext
        self.binstring = ''
        for i in plaintext:
            self.binstring += bin(ord(i))[2:].zfill(8)
        numofblocks = len(self.binstring)//128 + 1
        expbinstr = self.binstring
        for i in range(len(self.binstring), numofblocks*128):
            expbinstr = '0' + expbinstr
        keyblock = []
        for i in range(0, numofblocks):
            keyi = ''
            for i in range(0, 128):
                keyi += str(random.randint(0,99) % 2)
            keyblock.append(keyi)
        keypr = keyblock[0]
        self.key = ''
        #desired key length is 128 bits, if it's more than 128, then we generate multiple keys and finaly key is xor of all keys.
        if len(keyblock) > 1:
            for i in range(1, len(keyblock)):
                keyxor = ''
                for j in range(0, 128):
                    if (str(keypr[j]) == '1' and str(keyblock[i][j]) == '0') or (str(keypr[j]) == '0' and str(keyblock[i][j]) == '1'):
                        keyxor += '1'
                    else:
                        keyxor += '0'
                keypr = keyxor
        self.key = keypr
        self.roundkeys = [self.key, self.key[16:128 - 16], self.key[28:128 - 28], self.key[37:128 - 37]]
        self.encmessage = ''
        self.contrsum = []
    #initialize S-Box
    Sbox = {'00': ['011000', '111110', '011011', '101101', '100000', '001011', '011010', '001001', '000000', '111101', '000100', '010111', '010010', '011100', '101010', '111111', '110011', '110010', '000110', '010000', '111100', '011111', '110000', '100111', '011001', '110101', '110100', '001100', '000001', '111010', '111001', '100001', '100101', '001010', '100010', '110110', '000111', '011101', '101111', '001000', '100110', '010011', '000010', '101100', '111011', '001111', '011110', '101000', '111000', '110111', '100011', '100100', '001110', '010101', '010001', '001101', '010110', '000011', '101110', '101001', '000101', '110001', '101011', '010100'],
            '01': ['000111', '101101', '001011', '100000', '000110', '010100', '011110', '011111', '111011', '101100', '101001', '001001', '001111', '100001', '110000', '111001', '001000', '010111', '010001', '010010', '000100', '110011', '110110', '011100', '111010', '101011', '001101', '010101', '110101', '011001', '100010', '101000', '111111', '000000', '010011', '000101', '110001', '100100', '100110', '101110', '110111', '110100', '011010', '011101', '000011', '111100', '010000', '001110', '111110', '111000', '110010', '011000', '000010', '010110', '011011', '100011', '001010', '101111', '001100', '100101', '101010', '000001', '111101', '100111'],
            '10': ['010000', '000100', '111110', '101010', '000111', '101110', '100001', '110111', '001001', '110001', '011110', '011111', '111011', '100100', '101001', '111010', '011000', '000010', '111101', '000000', '100110', '100101', '010111', '101101', '010010', '010110', '100011', '101100', '000001', '000011', '011001', '101000', '110000', '100000', '111000', '100010', '110010', '010001', '110110', '001000', '111100', '011010', '000110', '010011', '011100', '110100', '101111', '010100', '110101', '001101', '001100', '100111', '001011', '111001', '010101', '001111', '001110', '110011', '011011', '001010', '111111', '101011', '011101', '000101'],
            '11': ['100110', '101101', '101111', '001110', '001001', '101110', '010111', '111101', '011101', '010100', '101010', '001111', '100100', '110011', '001100', '001000', '101000', '111100', '110010', '110001', '111011', '100111', '000000', '110111', '000110', '101100', '100011', '011110', '100010', '011010', '111010', '101011', '000101', '000011', '011011', '110101', '010011', '011000', '011001', '111001', '111000', '011111', '001010', '000100', '010101', '111111', '000001', '110000', '100101', '001101', '000111', '010010', '000010', '011100', '110100', '111110', '010000', '110110', '101001', '010001', '010110', '100000', '001011', '100001']}
    #XOR is widely used in this encryption method thus it's better to make xor separate function
    def XOR(self, str1, str2):
        xor_res = ''
        for i in range(0, len(str1)):
            if (str1[i] == '1' and str2 == '0') or (str1[i] == '0' and str2[i] == '1'):
                xor_res += '1'
            else:
                xor_res += '0'
        return xor_res
    #if we're unsatisfied with current s-box new can be generated in a random way, note, that it may not be secure enough
    def GenerateNewSBox(self):
        id = [[], [], [], []]
        for i in range(0, 4):
            for j in range(0, 64):
                value = random.randint(0, 63)
                while bin(value)[2:].zfill(8) in id[i]:
                    value = random.randint(0, 63)
                id[i].append(bin(value)[2:].zfill(6))
            for k in range(0, 64):
                if bin(k)[2:].zfill(6) not in id[i]:
                    id[i].append(bin(k)[2:].zfill(6))
        Sbox = {'00': id[0],
                '01': id[1],
                '10': id[2],
                '11': id[3]}
        return Sbox
    #it's easier to initialize reverse of s box than directly type it into program, also, it is extremely useful in case a new s-box is generated
    def ReverseSBox(self):
        id = []
        for k in range(0, 64):
            id.append([])
            for i in range(0, 4):
                for j in range(0, 64):
                    if bin(k)[2:].zfill(6) == self.Sbox[bin(i)[2:].zfill(2)][j]:
                        id[k].append(bin(j)[2:].zfill(6))
                        break
        RevSbox = {}
        for i in range(0, 64):
            RevSbox.update({bin(i)[2:].zfill(6): id[i]})
        return RevSbox

    def getSBox(self):
        return self.Sbox
        
    #this method returns word after substitution transformation
    def SBoxEnc(self, word):
        blocklist = []
        for i in range(0, len(word), 8):
            blocklist.append(word[i:i + 8])
        sblock_out = []
        for i in range(len(blocklist)):
            block_key = blocklist[i][0] + blocklist[i][7]
            block_number = int(blocklist[i][1:7], 2)
            sblock_out.append(self.Sbox[block_key][block_number])
            #NOTE: control sum is not explicitly used in encryption algorithm, it's here only because I've tried to decrypt using it, however, it doesn't work yet
            cont_sum = 0
            for j in range(1, len(blocklist[i])-1):
                if blocklist[i][j] == '1':
                    cont_sum += 1
            self.contrsum.append(self.XOR(bin(cont_sum)[2:].zfill(4), self.key[:4]))
        return sblock_out
    
    
    def PBoxEnc(self, sblock_out):
        pblock_out = []
        for i in range(0, len(sblock_out)):
            pblock_out.append([])
        pbox_out = ''
        if len(pblock_out) == 16:
            pblock_out[0] = sblock_out[9]
            for i in range(1, 8):
                pblock_out[(i+1)**2 % 17 - 1] = sblock_out[i]
            pblock_out[1] = sblock_out[5]
            pblock_out[2] = sblock_out[14]
            pblock_out[4] = sblock_out[12]
            pblock_out[5] = sblock_out[15]
            pblock_out[6] = sblock_out[13]
            pblock_out[9] = sblock_out[11]
            pblock_out[10] = sblock_out[0]
            pblock_out[11] = sblock_out[10]
            pblock_out[13] = sblock_out[8]
        if len(pblock_out) == 12:
            pblock_out[0] = sblock_out[9]
            for i in range(1, 6):
                pblock_out[(i+1)**2 % 13 - 1] = sblock_out[i]
            pblock_out[1] = sblock_out[11]
            pblock_out[4] = sblock_out[7]
            pblock_out[5] = sblock_out[10]
            pblock_out[6] = sblock_out[8]
            pblock_out[7] = sblock_out[0]
            pblock_out[10] = sblock_out[6]
        if len(pblock_out) == 9:
            pblock_out[0] = sblock_out[6]
            for i in range(1, 6):
                pblock_out[(i+1)**2 % 11 - 1] = sblock_out[i]
            pblock_out[1] = sblock_out[7]
            pblock_out[5] = sblock_out[8]
            pblock_out[6] = sblock_out[0]
            pblock_out[7] = sblock_out[5]
        for i in range(0, len(pblock_out)):
            pbox_out += pblock_out[i]
        return pbox_out
    #here we use P-box, S-box and XOR to encrypt message. Also, control sum is added in the end of ciphertext
    def encrypt(self):
        numofblocks = len(self.binstring) // 128 + 1
        expbinstr = self.binstring
        for i in range(len(self.binstring), numofblocks * 128):
            expbinstr = '0' + expbinstr
        encblocks = []
        for i in range(0, numofblocks):
            encblocks.append(expbinstr[i*128:(i+1)*128])
        for i in range(0, len(encblocks)):
            ciphertext = encblocks[i]
            for j in range(0, 3):
                ciphertext = self.XOR(ciphertext, self.roundkeys[i])
                ciphertext = self.PBoxEnc(self.SBoxEnc(ciphertext))
            ciphertext = self.XOR(ciphertext, self.roundkeys[3])
            encblocks[i] = ciphertext
        ciphertext = ''
        for i in range(len(encblocks)):
            ciphertext += encblocks[i]
        sum = ''
        for i in range(len(self.contrsum)):
            sum += self.contrsum[i]
        self.encmessage = ciphertext + sum
        return self.encmessage
    #reverse of p-box
    def PBoxDec(self, word):
        blocks = []
        for i in range(0, len(word), 6):
            blocks.append(word[i:i + 6])
        orig_order = []
        if len(blocks) == 9:
            orig_order.append(blocks[6])
            orig_order.append(blocks[3])
            orig_order.append(blocks[8])
            orig_order.append(blocks[4])
            orig_order.append(blocks[2])
            orig_order.append(blocks[7])
            orig_order.append(blocks[0])
            orig_order.append(blocks[1])
            orig_order.append(blocks[5])
        if len(blocks) == 12:
            orig_order.append(blocks[9])
            orig_order.append(blocks[11])
            orig_order.append(blocks[3])
            orig_order.append(blocks[1])
            orig_order.append(blocks[7])
            orig_order.append(blocks[10])
            orig_order.append(blocks[8])
            orig_order.append(blocks[0])
            orig_order.append(blocks[2])
            orig_order.append(blocks[5])
            orig_order.append(blocks[6])
            orig_order.append(blocks[4])
        if len(blocks) == 16:
            orig_order.append(blocks[9])
            orig_order.append(blocks[5])
            orig_order.append(blocks[14])
            orig_order.append(blocks[1])
            orig_order.append(blocks[12])
            orig_order.append(blocks[15])
            orig_order.append(blocks[13])
            orig_order.append(blocks[4])
            orig_order.append(blocks[2])
            orig_order.append(blocks[11])
            orig_order.append(blocks[0])
            orig_order.append(blocks[10])
            orig_order.append(blocks[7])
            orig_order.append(blocks[8])
            orig_order.append(blocks[6])
            orig_order.append(blocks[3])
        return orig_order
    #reverse of s-box. currently not functioning
    def SBoxDec(self, pblocks, contrsum_init):
        RevSBox = self.ReverseSBox()
        res = ''
        if len(pblocks) == 16:
            contrsum = contrsum_init[0:16]
        elif len(pblocks) == 12:
            contrsum = contrsum_init[16:28]
        elif len(pblocks) == 9:
            contrsum = contrsum_init[28:37]
        for i in range(0, len(pblocks)):
            sboxrev = RevSBox[pblocks[i]]
            options_sum = []
            for j in range(0, 4):
                summ = 0
                for k in range(0, 6):
                    if sboxrev[j][k] == '1':
                        summ += 1
                options_sum.append(summ)
            for j in range(0, 4):
                if int(contrsum[i], 2) == options_sum[j]:
                    binj = bin(j)[2:].zfill(2)
                    res += binj[0]+sboxrev[j]+binj[1]
        return res
    #decrypt method which gathers reverse of s-box, p-box and xors values. also it passes control sum to the s-box
    def decrypt(self):
        contrsum = []
        for i in range(54, len(self.encmessage), 4):
            contrsum.append(self.XOR(self.encmessage[i:i + 4], self.key[:4]))
        ciphertext = self.encmessage[:54]
        for i in range(3, 0, -1):
            ciphertext = self.XOR(ciphertext, self.roundkeys[i])
            ciphertext = self.SBoxDec(self.PBoxDec(ciphertext), contrsum)
        ciphertext = self.XOR(ciphertext, self.roundkeys[0])
        text = ''
        for i in range(0, len(ciphertext), 7):
            text += chr(int(ciphertext[i:i + 7], 2))
        return text

    def getKey(self):
        return self.key


text1 = cipher('adaaads')
text2 = cipher('fkdkgfgkdf')
text3 = cipher('attack at dawn')
text4 = cipher('attack at dawn from the west side of the river, head to the south-west of the city')
print(text1.encrypt())
text1.ReverseSBox()
text5 = cipher('')
text5 = text1.decrypt()
