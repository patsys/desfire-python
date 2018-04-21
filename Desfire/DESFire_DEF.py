from enum import Enum
class DESFire_DEF(Enum):
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
     master=DESFireKeySettings['KS_FACTORY_DEFAULT']
     change=DESFireKeySettings['KS_FACTORY_DEFAULT']
     def __repr__(self):
         return 'master:' + master.name + "\nchange:" + change.name

class DESFireKeyOpt:
     key_size   = 0
     block_size = 0
     version   = 0
     key_type  = DESFireKeyType['DF_KEY_INVALID']
     key_settings = 0 
     def list_human_key_settings(self):
         settings=[]
         for i in range(0,16):
             if (self.key_settings & (1 << i)) != 0:
                 settings.append(DESFireKeySettings(1 << i).name)
         return settings

     def __repr__(self):
         return 'keysize:' + str(self.key_size) + "\nblock_size:" + str(self.block_size) + "\nversion:" + str(self.version) + "\nkey_type:" + self.key_type.name + "\n" + "key_settings:" + str(self.list_human_key_settings())
