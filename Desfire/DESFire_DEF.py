from enum import Enum
import struct
from Crypto.Cipher import DES, DES3, AES
from Crypto import Random
from Crypto.Util.strxor import strxor
from .util import *

def chunks(data, n):
    i = 0
    while i < len(data):
        yield data[i:i+n]
        i += n

class DESFireCommand(Enum):
     MAX_FRAME_SIZE         =60 # The maximum total length of a packet that is transfered to / from the card

#------- Desfire legacy instructions --------

     DF_INS_AUTHENTICATE_LEGACY        =0x0A
     DF_INS_CHANGE_KEY_SETTINGS        =0x54
     DF_INS_GET_KEY_SETTINGS           =0x45
     DF_INS_CHANGE_KEY                 =0xC4
     DF_INS_GET_KEY_VERSION            =0x64

     DF_INS_CREATE_APPLICATION         =0xCA
     DF_INS_DELETE_APPLICATION         =0xDA
     DF_INS_GET_APPLICATION_IDS        =0x6A
     DF_INS_SELECT_APPLICATION         =0x5A

     DF_INS_FORMAT_PICC                =0xFC
     DF_INS_GET_VERSION                =0x60

     DF_INS_GET_FILE_IDS               =0x6F
     DF_INS_GET_FILE_SETTINGS          =0xF5
     DF_INS_CHANGE_FILE_SETTINGS       =0x5F
     DF_INS_CREATE_STD_DATA_FILE       =0xCD
     DF_INS_CREATE_BACKUP_DATA_FILE    =0xCB
     DF_INS_CREATE_VALUE_FILE          =0xCC
     DF_INS_CREATE_LINEAR_RECORD_FILE  =0xC1
     DF_INS_CREATE_CYCLIC_RECORD_FILE  =0xC0
     DF_INS_DELETE_FILE                =0xDF

     DF_INS_READ_DATA                  =0xBD
     DF_INS_WRITE_DATA                 =0x3D
     DF_INS_GET_VALUE                  =0x6C
     DF_INS_CREDIT                     =0x0C
     DF_INS_DEBIT                      =0xDC
     DF_INS_LIMITED_CREDIT             =0x1C
     DF_INS_WRITE_RECORD               =0x3B
     DF_INS_READ_RECORDS               =0xBB
     DF_INS_CLEAR_RECORD_FILE          =0xEB
     DF_COMMIT_TRANSACTION             =0xC7
     DF_INS_ABORT_TRANSACTION          =0xA7

     DF_INS_ADDITIONAL_FRAME           =0xAF # data did not fit into a frame, another frame will follow

# -------- Desfire EV1 instructions ----------

     DFEV1_INS_AUTHENTICATE_ISO        =0x1A
     DFEV1_INS_AUTHENTICATE_AES        =0xAA
     DFEV1_INS_FREE_MEM                =0x6E
     DFEV1_INS_GET_DF_NAMES            =0x6D
     DFEV1_INS_GET_CARD_UID            =0x51
     DFEV1_INS_GET_ISO_FILE_IDS        =0x61
     DFEV1_INS_SET_CONFIGURATION       =0x5C

# ---------- ISO7816 instructions ------------

     ISO7816_INS_EXTERNAL_AUTHENTICATE =0x82
     ISO7816_INS_INTERNAL_AUTHENTICATE =0x88
     ISO7816_INS_APPEND_RECORD         =0xE2
     ISO7816_INS_GET_CHALLENGE         =0x84
     ISO7816_INS_READ_RECORDS          =0xB2
     ISO7816_INS_SELECT_FILE           =0xA4
     ISO7816_INS_READ_BINARY           =0xB0
     ISO7816_INS_UPDATE_BINARY         =0xD6

class DESFire_STATUS(Enum):
    ST_Success               = 0x00
    ST_NoChanges             = 0x0C
    ST_OutOfMemory           = 0x0E
    ST_IllegalCommand        = 0x1C
    ST_IntegrityError        = 0x1E
    ST_KeyDoesNotExist       = 0x40
    ST_WrongCommandLen       = 0x7E
    ST_PermissionDenied      = 0x9D
    ST_IncorrectParam        = 0x9E
    ST_AppNotFound           = 0xA0
    ST_AppIntegrityError     = 0xA1
    ST_AuthentError          = 0xAE
    ST_MoreFrames            = 0xAF # data did not fit into a frame, another frame will follow
    ST_LimitExceeded         = 0xBE
    ST_CardIntegrityError    = 0xC1
    ST_CommandAborted        = 0xCA
    ST_CardDisabled          = 0xCD
    ST_InvalidApp            = 0xCE
    ST_DuplicateAidFiles     = 0xDE
    ST_EepromError           = 0xEE
    ST_FileNotFound          = 0xF0
    ST_FileIntegrityError    = 0xF1

class DESFire_FILE_CRYPT(Enum):
    CM_PLAIN   = 0x00,
    CM_MAC     = 0x01,   # not implemented (Plain data transfer with additional MAC)

class DESFire_File_Type(Enum):
    MDFT_STANDARD_DATA_FILE             = 0x00
    MDFT_BACKUP_DATA_FILE               = 0x01 # not implemented
    MDFT_VALUE_FILE_WITH_BACKUP         = 0x02 # not implemented
    MDFT_LINEAR_RECORD_FILE_WITH_BACKUP = 0x03 # not implemented
    MDFT_CYCLIC_RECORD_FILE_WITH_BACKUP = 0x04 # not implemented

class DESFireCmac(Enum):
    MAC_None   = 0,
    # Transmit data:
    MAC_Tmac   = 1, # The CMAC must be calculated for the TX data sent to the card although this Tx CMAC is not transmitted
    MAC_Tcrypt = 2, # To the parameters sent to the card a CRC32 must be appended and then they must be encrypted with the session key
    # Receive data:
    MAC_Rmac   = 4, # The CMAC must be calculated for the RX data received from the card. If status == ST_Success -> verify the CMAC in the response
    MAC_Rcrypt = 8, # The data received from the card must be decrypted with the session key

class DESFireKeyType(Enum):
    DF_KEY_2K3DES  = 0x00 # for DFEV1_INS_AUTHENTICATE_ISO + DF_INS_AUTHENTICATE_LEGACY
    DF_KEY_3K3DES  = 0x40 # for DFEV1_INS_AUTHENTICATE_ISO
    DF_KEY_AES     = 0x80 # for DFEV1_INS_AUTHENTICATE_AES
    DF_KEY_INVALID = 0xFF

class DESFireCBC(Enum):
    CBC_SEND=0
    CBC_RECEIVE=1



class DESFireKeySettings(Enum):
    # ------------ BITS 0-3 ---------------
    KS_ALLOW_CHANGE_MK                = 0x01 # If this bit is set, the MK can be changed, otherwise it is frozen.
    KS_LISTING_WITHOUT_MK             = 0x02 # Picc key: If this bit is set, GetApplicationIDs, GetKeySettings do not require MK authentication.
                                             # App  key: If this bit is set, GetFileIDs, GetFileSettings, GetKeySettings do not require MK authentication.
    KS_CREATE_DELETE_WITHOUT_MK       = 0x04 # Picc key: If this bit is set, CreateApplication does not require MK authentication.
                                             # App  key: If this bit is set, CreateFile, DeleteFile do not require MK authentication.
    KS_CONFIGURATION_CHANGEABLE       = 0x08 # If this bit is set, the configuration settings of the MK can be changed, otherwise they are frozen.
    
    # ------------ BITS 4-7 (not used for the PICC master key) -------------
    KS_CHANGE_KEY_WITH_MK             = 0x00 # A key change requires MK authentication
    KS_CHANGE_KEY_WITH_KEY_1          = 0x10 # A key change requires authentication with key 1
    KS_CHANGE_KEY_WITH_KEY_2          = 0x20 # A key change requires authentication with key 2
    KS_CHANGE_KEY_WITH_KEY_3          = 0x30 # A key change requires authentication with key 3
    KS_CHANGE_KEY_WITH_KEY_4          = 0x40 # A key change requires authentication with key 4 
    KS_CHANGE_KEY_WITH_KEY_5          = 0x50 # A key change requires authentication with key 5
    KS_CHANGE_KEY_WITH_KEY_6          = 0x60 # A key change requires authentication with key 6
    KS_CHANGE_KEY_WITH_KEY_7          = 0x70 # A key change requires authentication with key 7
    KS_CHANGE_KEY_WITH_KEY_8          = 0x80 # A key change requires authentication with key 8
    KS_CHANGE_KEY_WITH_KEY_9          = 0x90 # A key change requires authentication with key 9
    KS_CHANGE_KEY_WITH_KEY_A          = 0xA0 # A key change requires authentication with key 10
    KS_CHANGE_KEY_WITH_KEY_B          = 0xB0 # A key change requires authentication with key 11
    KS_CHANGE_KEY_WITH_KEY_C          = 0xC0 # A key change requires authentication with key 12
    KS_CHANGE_KEY_WITH_KEY_D          = 0xD0 # A key change requires authentication with key 13
    KS_CHANGE_KEY_WITH_TARGETED_KEY   = 0xE0 # A key change requires authentication with the same key that is to be changed
    KS_CHANGE_KEY_FROZEN              = 0xF0 # All keys are frozen
    
    # -------------------------------------
    KS_FACTORY_DEFAULT                = 0x0F


class DESFireKeySet:
     master=DESFireKeySettings.KS_FACTORY_DEFAULT
     change=DESFireKeySettings.KS_FACTORY_DEFAULT
     def __repr__(self):
         return 'master:' + master.name + "\nchange:" + change.name

class DESFireKey():
    def __init__(self):
        self.keyType = None
        self.keyBytes = None
        self.keySize = 0
        self.keyVersion = 0

        self.IV = None
        self.Cipher = None
        self.CipherBlocksize = None

        self.cmac = None
        self.cmac1 = None
        self.cmac2 = None
        self.keySettings = 0
        self.keyNumbers = 0
        self.chiperMode = None


    def listHumanKeySettings(self):
        settings=[]
        for i in range(0,16):
            if (self.keySettings & (1 << i)) != 0:
                settings.append(DESFireKeySettings(1 << i).name)
        return settings

    def ClearIV(self):
        self.IV=b"\00" * self.CipherBlocksize
    
    def CiperInit(self):
        if self.keySize == 0:
            if self.keyBytes == None:
                self.keySize=8
            else:
                self.keySize=len(self.keyBytes)
        self.setDefaultKeyNotSet()
        if self.CipherBlocksize == None:
            self.CipherBlocksize=self.keySize
        #todo assert on key length!
        if self.keyType == DESFireKeyType.DF_KEY_AES:
            #AES is used
            self.keySize == 16
            self.CipherBlocksize = 16
            self.ClearIV()
            self.chiperMode = AES
            self.Cipher = AES.new(bytes(self.keyBytes), AES.MODE_CBC, bytes(self.IV))

        elif self.keyType == DESFireKeyType.DF_KEY_2K3DES:
        #DES is used
            if self.keySize == 8:
                self.CipherBlocksize = 8
                self.ClearIV()
                self.chiperMode = DES
                self.Cipher = DES.new(bytes(self.keyBytes), DES.MODE_CBC, bytes(self.IV))
        #2DES is used (3DES with 2 keys only)
            elif self.keySize == 16:
                self.CipherBlocksize = 8
                self.chiperMode = DES3
                self.ClearIV()
                self.Cipher = DES3.new(bytes(self.keyBytes), DES.MODE_CBC, bytes(self.IV))

            else:
                raise Exception('Key length error!')
                        
        elif self.keyType == DESFireKeyType.DF_KEY_3K3DES:
            assert self.keySize == 24
            #3DES is used
            self.CipherBlocksize = 8
            self.ClearIV()
            self.Cipher = DES3.new(bytes(self.keyBytes), DES.MODE_CBC, bytes(self.IV))

        else:
            raise Exception('Unknown key type!')
       

    def setDefaultKeyNotSet(self):
        if self.keyBytes == None:
            self.keyBytes=b'\00' * self.keySize
   

    def GetKeyType(self):
        return self.keyType

    def getKey(self):
        return self.keyBytes

    def setKey(self,key):
        if isinstance(key,str):
            self.keyBytes=bytes(bytearray.fromhex(key))
        else:
            self.keyBytes=key
        self.CipherBlocksize=len(self.keyBytes)
        self.keySize=len(self.keyBytes)



    def setKeySettings(self,keyNumbers,keyType,keySettings):
        self.keyNumbers=keyNumbers
        self.keyType=keyType
        self.keySettings=keySettings


    def Encrypt(self, data):
        #todo assert on blocksize
        self.IV = data[-self.CipherBlocksize:]
        return list(bytearray(self.Cipher.encrypt(bytes(data))))

    def EncryptMsg(self, data, withCRC=False, encryptBegin=1):
            sdata=data.copy()
            if withCRC:
                data+=bytearray(CRC32(data).to_bytes(4, byteorder='little'))
            
            data+=[0x00] * ((-(len(data)-encryptBegin)%self.CipherBlocksize))

            #c=self.chiperMode.new(bytes(self.keyBytes), self.chiperMode.MODE_CBC, bytes(self.IV))
            print('crypt:',byte_array_to_human_readable_hex(data[encryptBegin:]))
            ret = bytearray(data[0:encryptBegin])+self.cmac.Encrypt(data[encryptBegin:])
            #self.GenerateCmac()
            #self.CalculateCmac(bytearray(data))
            return ret  

    def Decrypt(self, dataEnc):
        #todo assert on blocksize
        block = self.Cipher.decrypt(bytes(dataEnc))
        self.IV = block[-self.CipherBlocksize:]
        return list(bytearray(block))


    #Generates the two subkeys mu8_Cmac1 and mu8_Cmac2 that are used for CMAC calulation with the session key
    def GenerateCmac(self,key): 
        self.cmac=CMAC.new(bytes(key),ciphermod=self.chiperMode)
    #Calculate the CMAC (Cipher-based Message Authentication Code) from the given data.
    #The CMAC is the initialization vector (IV) after a CBC encryption of the given data.
    def CalculateCmac(self, data):
        cmac_enc=b''
        cmac_enc = self.cmac.CalculateCmac(data)
        #cmac_enc = self.cmac.digest()
        self.IV=cmac_enc
        return cmac_enc
    
    def VerifyCmac(self,tag):
        self.cmac.verify(tag)

    def __repr__(self):
        return "--- Desfire Key Details ---\r\n"+'keyNumbers:'+ str(self.keyNumbers) + '\r\nkeySize:' + str(self.keySize)  + "\r\nversion:" + str(self.keyVersion) + "\nkeyType:" + self.keyType.name + "\r\n" + "keySettings:" + str(self.listHumanKeySettings())


    
class DESFireCardVersion():

    def __init__(self,data):
        self.rawBytes = data
        self.hardwareVendorId    = data[0]
        self.hardwareType        = data[1]
        self.hardwareSubType     = data[2]
        self.hardwareMajVersion  = data[3]
        self.hardwareMinVersion  = data[4]
        self.hardwareStorageSize = data[5]
        self.hardwareProtocol    = data[6]

        self.softwareVendorId    = data[7]
        self.softwareType        = data[8]
        self.softwareSubType     = data[9]
        self.softwareMajVersion  = data[10]
        self.softwareMinVersion  = data[11]
        self.softwareStorageSize = data[12]
        self.softwareProtocol    = data[13]

        self.UID      = data[14:21]        # The serial card number
        self.batchNo  = data[21:25]        # The batch number
        self.cwProd   = data[26]           # The production week (BCD)
        self.yearProd = data[27]           # The production year (BCD)

    def __repr__(self):
        temp =  "--- Desfire Card Details ---\r\n"
        temp += "Hardware Version: %d.%d\r\n"% (self.hardwareMajVersion, self.hardwareMinVersion)
        temp += "Software Version: %d.%d\r\n"% (self.softwareMajVersion, self.softwareMinVersion)
        temp += "EEPROM size:      %d bytes\r\n"% (1 << (self.hardwareStorageSize-1))
        temp += "Production :       week %X, year 20%02X\r\n" % (self.cwProd, self.yearProd)
        temp += "UID no  : %s\r\n" % (byte_array_to_human_readable_hex(self.UID),)
        temp += "Batch no: %s\r\n" % (byte_array_to_human_readable_hex(self.batchNo),)
        return temp

    def toDict(self):
         temp = {}
         temp['rawBytes']            = self.rawByte
         temp['hardwareVendorId']    = self.hardwareVendorId
         temp['hardwareType']        = self.hardwareType
         temp['hardwareSubType']     = self.hardwareSubType
         temp['hardwareMajVersion']  = self.hardwareMajVersion
         temp['hardwareMinVersion']  = self.hardwareMinVersion
         temp['hardwareStorageSize'] = self.hardwareStorageSize
         temp['hardwareProtocol']    = self.hardwareProtocol
         temp['softwareVendorId']    = self.softwareVendorId
         temp['softwareType']        = self.softwareType
         temp['softwareSubType']     = self.softwareSubType
         temp['softwareMajVersion']  = self.softwareMajVersion
         temp['softwareMinVersion']  = self.softwareMinVersion
         temp['softwareStorageSize'] = self.softwareStorageSize
         temp['softwareProtocol']    = self.softwareProtocol
         temp['UID']      = self.UID
         temp['batchNo']  = self.batchNo
         temp['cwProd']   = self.cwProd
         temp['yearProd'] = self.yearProd
         return temp


class DESFireFilePermissions():

    def __init__(self):
        self.ReadAccess         = None
        self.WriteAccess        = None
        self.ReadAndWriteAccess = None
        self.ChangeAccess       = None

    def pack(self):
        return (self.ReadAccess << 12) | (self.WriteAccess <<  8) | (self.ReadAndWriteAccess <<  4) | self.ChangeAccess;
    
    def unpack(self, data):
        self.ReadAccess         = bool((data >> 12) & 0x0F)
        self.WriteAccess        = bool((data >>  8) & 0x0F)
        self.ReadAndWriteAccess = bool((data >>  4) & 0x0F)
        self.ChangeAccess       = bool((data      ) & 0x0F)

    def __repr__(self):
        temp =  '----- DESFireFilePermissions ---\r\n'
        if self.ReadAccess:
            temp += 'READ|'
        if self.WriteAccess:
            temp += 'WRITE|'
        if self.ReadAndWriteAccess:
            temp += 'READWRITE|'
        if self.ReadAndWriteAccess:
            temp += 'CHANGE|'
        return temp

    def toDict(self):
        temp = {}
        temp['ReadAccess']         = self.ReadAccess
        temp['WriteAccess']        = self.WriteAccess
        temp['ReadAndWriteAccess'] = self.ReadAndWriteAccess
        temp['ChangeAccess']       = self.ChangeAccess
        return temp
    





class DESFireFileSettings:

    def __init__(self):

        self.FileType    = None #DESFireFileType
        self.Encryption  = None #DESFireFileEncryption
        self.Permissions = DESFireFilePermissions()
        # ----------------------------
        # used only for MDFT_STANDARD_DATA_FILE and MDFT_BACKUP_DATA_FILE
        self.FileSize    = None #uint32_t
        # -----------------------------
        # used only for MDFT_VALUE_FILE_WITH_BACKUP
        self.LowerLimit  = None #uint32_t
        self.UpperLimit  = None #uint32_t
        self.LimitedCreditValue   = None
        self.LimitedCreditEnabled = None #bool
        # -----------------------------
        # used only for MDFT_LINEAR_RECORD_FILE_WITH_BACKUP and MDFT_CYCLIC_RECORD_FILE_WITH_BACKUP
        self.RecordSize           = None #uint32_t
        self.MaxNumberRecords     = None #uint32_t
        self.CurrentNumberRecords = None        #uint32_t

    def parse(self, data):
        self.FileType   = DESFireFileType(hex2int(data[0]))
        self.Encryption = DESFireFileEncryption(hex2int(data[1]))
        self.Permissions.unpack(struct.unpack('>H',data[2:4])[0])
        
        if self.FileType == DESFireFileType.MDFT_LINEAR_RECORD_FILE_WITH_BACKUP:
            self.RecordSize = struct.unpack('<I', data[4:6] + '\x00\x00')[0]  
            self.MaxNumberRecords = struct.unpack('<I', data[6:8] + '\x00\x00')[0]
            self.CurrentNumberRecords = struct.unpack('<I', data[8:10] + '\x00\x00')[0]

        elif self.FileType == DESFireFileType.MDFT_STANDARD_DATA_FILE:
            self.FileSize = struct.unpack('<I', data[4:6] + '\x00\x00')[0]


        else:
            # TODO: We can still access common attributes
            # raise NotImplementedError("Please fill in logic for file type {:02X}".format(resp[0]))
            pass

    def __repr__(self):
        temp = ' ----- DESFireFileSettings ----\r\n'
        temp += 'File type: %s\r\n' % (self.FileType.name)
        temp += 'Encryption: %s\r\n' % (self.Encryption.name)
        temp += 'Permissions: %s\r\n' % (repr(self.Permissions))
        if self.FileType == DESFireFileType.MDFT_LINEAR_RECORD_FILE_WITH_BACKUP:
            temp += 'RecordSize: %d\r\n' % (self.RecordSize)
            temp += 'MaxNumberRecords: %d\r\n' % (self.MaxNumberRecords)
            temp += 'CurrentNumberRecords: %d\r\n' % (self.CurrentNumberRecords)

        elif self.FileType == DESFireFileType.MDFT_STANDARD_DATA_FILE:
            temp += 'File size: %d\r\n' % (self.FileSize)

        return temp

    def toDict(self):
        temp = {}
        temp['FileType'] = self.FileType.name
        temp['Encryption'] = self.Encryption.name
        temp['Permissions'] = self.Permissions.toDict()
        temp['LowerLimit'] = self.LowerLimit
        temp['UpperLimit'] = self.UpperLimit
        temp['LimitedCreditValue'] = self.LimitedCreditValue
        temp['LimitedCreditEnabled'] = self.LimitedCreditEnabled
        if self.FileType == DESFireFileType.MDFT_LINEAR_RECORD_FILE_WITH_BACKUP:
            temp['RecordSize'] = self.RecordSize
            temp['MaxNumberRecords'] = self.MaxNumberRecords
            temp['CurrentNumberRecords'] = self.CurrentNumberRecords
        elif self.FileType == DESFireFileType.MDFT_STANDARD_DATA_FILE:
            temp['FileSize'] = self.FileSize
        return temp







def calc_key_settings(mask):
    if type(mask) is list:
        #not parsing, but calculating
        res = 0
        for keysetting in mask:
            res += keysetting.value
        return res & 0xFF


    a=2147483648
    result = []
    while a>>1:
        a = a>>1
        masked = mask&a
        if masked:
            if DESFireKeySettings(masked):
                result.append(DESFireKeySettings(masked))
    return result
