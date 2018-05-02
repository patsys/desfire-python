from __future__ import print_function

import json
import logging
import time

import random
import pyDes
from .device import Device
from .DESFire_DEF import *
from .util import byte_array_to_human_readable_hex


_logger = logging.getLogger(__name__)
class DESFireCommunicationError(Exception):
    """Outgoing DESFire command received a non-OK reply.
    The exception message is human readable translation of the error code if available. The ``status_code`` carries the original status word error byte.
    """


    def __init__(self, msg, status_code):
        super(DESFireCommunicationError, self).__init__(msg)
        self.status_code = status_code

class DESFire:
    def __init__(self, device, logger=None):
        self.isAuthenticated = False
        self.sessionKey = None
        self.cmac = None
        self.MaxFrameSize=60
        """
        :param device: :py:class:`desfire.device.Device` implementation
        :param logger: Python :py:class:`logging.Logger` used for logging output. Overrides the default logger. Extensively uses ``INFO`` logging level.
        """

        #assert isinstance(device, Device), "Not a compatible device instance: {}".format(device)

        self.device = device

        #: 8 bytes of session key after authenticate()
        self.session_key = None
        self.lastSelectedApplication = None
        if logger:
            self.logger = logger
        else:
            self.logger = _logger


    def decrypt_response(self, response, private_key=b"\00" * 16, session_key=None):
        """Decrypt the autheticated session answer from the card.
        .. warn ::
            Does not check CMAC.
        """

        initial_value = b"\00" * 8
        k = pyDes.triple_des(bytes(private_key), pyDes.CBC, initial_value, pad=None, padmode=pyDes.PAD_NORMAL)

        decrypted = [b for b in (k.decrypt(bytes(response)))]
        import pdb ; pdb.set_trace()

    def authenticate(self, key_id, key, challenge = None):
        """Does authentication to the currently selected application with keyid (key_id)
        Authentication is NEVER needed to call this function.
        Args:
                key_id  (int)         : Key number
                key (DESFireKey)      : The key used for authentication
                challenge (DESFireKey): The challenge supplied by the reader to the card on the challenge-response authentication. 
                                                                It will determine half of the session Key bytes (optional)
                                                                It's there for testing and crypto thiunkering purposes
        
        Returns:
                DESFireKey : the session key used for future communications with the card in the same session
        """
        sessionKey = None
        self.logger.debug('Authenticating')
        self.isAuthenticated = False
        cmd = None
        keyType = key.GetKeyType()
        if keyType == DESFireKeyType.DF_KEY_AES:
            cmd = DESFireCommand.DFEV1_INS_AUTHENTICATE_AES.value
            params = [ key_id ]
        elif keyType == DESFireKeyType.DF_KEY_2K3DES or keyType == DESFireKeyType.DF_KEY_3K3DES:
            cmd = DESFireCommand.DFEV1_INS_AUTHENTICATE_ISO.value
            params = [ key_id ]
        else:
            raise Exception('Invalid key type!')

        raw_data = self.communicate(self.command(cmd,params),"Authenticating key {:02X}".format(key_id),True, allow_continue_fallthrough=True)
        RndB_enc = raw_data
        self.logger.debug( 'Random B (enc):'+ byte_array_to_human_readable_hex(RndB_enc))
        if keyType == DESFireKeyType.DF_KEY_3K3DES or keyType == DESFireKeyType.DF_KEY_AES:
            if len(RndB_enc) != 16:
                raise DESFireAuthException('Card expects a different key type. (enc B size is less than the blocksize of the key you specified)')

        key.CiperInit()
        RndB = key.Decrypt(RndB_enc)
        self.logger.debug( 'Random B (dec): ' + byte_array_to_human_readable_hex(RndB))
        RndB_rot = RndB[1:]+[RndB[0]]
        self.logger.debug( 'Random B (dec, rot): ' + byte_array_to_human_readable_hex(RndB_rot))

        if challenge != None:
            RndA = bytes(bytearray.fromhex(challenge))
        else:
            RndA = Random.get_random_bytes(len(RndB))
        self.logger.debug( 'Random A: ' + byte_array_to_human_readable_hex(RndA))
        RndAB = list(RndA) + RndB_rot
        self.logger.debug( 'Random AB: ' + byte_array_to_human_readable_hex(RndAB))
        RndAB_enc = key.Encrypt(RndAB)
        self.logger.debug( 'Random AB (enc): ' + byte_array_to_human_readable_hex(RndAB_enc))

        params = RndAB_enc 
        cmd = DESFireCommand.DF_INS_ADDITIONAL_FRAME.value
        raw_data = self.communicate(self.command(cmd,params),"Authenticating random {:02X}".format(key_id),True, allow_continue_fallthrough=True)
        #raw_data = hexstr2bytelist('91 3C 6D ED 84 22 1C 41')
        RndA_enc = raw_data
        self.logger.debug('Random A (enc): ' + byte_array_to_human_readable_hex(RndA_enc))
        RndA_dec = key.Decrypt(RndA_enc)
        self.logger.debug( 'Random A (dec): ' + byte_array_to_human_readable_hex(RndA_dec))
        RndA_dec_rot = RndA_dec[-1:] + RndA_dec[0:-1] 
        self.logger.debug( 'Random A (dec, rot): ' + byte_array_to_human_readable_hex(RndA_dec_rot))

        if bytes(RndA) != bytes(RndA_dec_rot):
            raise Exception('Authentication FAILED!')

        self.logger.debug( 'Authentication succsess!')
        self.isAuthenticated = True
        self.lastAuthKeyNo = key_id

        self.logger.debug( 'Calculating Session key')
        RndA = list(RndA)
        sessionKeyBytes  = RndA[:4]
        sessionKeyBytes += RndB[:4]

        if key.keySize > 8:
            if keyType == DESFireKeyType.DF_KEY_2K3DES:
                sessionKeyBytes += RndA[4:8]
                sessionKeyBytes += RndB[4:8]
            elif keyType == DESFireKeyType.DF_KEY_3K3DES:
                sessionKeyBytes += RndA[6:10]
                sessionKeyBytes += RndB[6:10]
                sessionKeyBytes += RndA[12:16]
                sessionKeyBytes += RndB[12:16]
            elif keyType == DESFireKeyType.DF_KEY_AES:
                sessionKeyBytes += RndA[12:16]
                sessionKeyBytes += RndB[12:16]

        if keyType == DESFireKeyType.DF_KEY_2K3DES or keyType == DESFireKeyType.DF_KEY_3K3DES:
            sessionKeyBytes = [( a & 0b11111110 ) for a in sessionKeyBytes ]    
        ## now we have the session key, so we reinitialize the crypto!!!
        key.GenerateCmac(sessionKeyBytes)
        self.sessionKey = key
        return self.sessionKey 

    def _communicate(self, apdu_cmd, description,nativ=False, allow_continue_fallthrough=False):
        """Communicate with a NFC tag.
        Send in outgoing request and waith for a card reply.
        TODO: Handle additional framing via 0xaf
        :param apdu_cmd: Outgoing APDU command as array of bytes
        :param description: Command description for logging purposes
        :param allow_continue_fallthrough: If True 0xAF response (incoming more data, need mode data) is instantly returned to the called instead of trying to handle it internally
        :raise: :py:class:`desfire.protocol.DESFireCommunicationError` on any error
        :return: tuple(APDU response as list of bytes, bool if additional frames are inbound)
        """

        result = []
        additional_framing_needed = True

        # TODO: Clean this up so readgwrite implementations have similar mechanisms and all continue is handled internally
        while additional_framing_needed:

            self.logger.debug("Running APDU command %s, sending: %s", description, byte_array_to_human_readable_hex(apdu_cmd))

            resp = self.device.transceive(apdu_cmd)
            self.logger.debug("Received APDU response: %s", byte_array_to_human_readable_hex(resp))


            if not nativ:
                if resp[-2] != 0x91:
                    raise DESFireCommunicationError("Received invalid response for command: {}".format(description), resp[-2:])
            # Possible status words: https:g/github.com/jekkos/android-hce-desfire/blob/master/hceappletdesfire/src/main/java/net/jpeelaer/hce/desfire/DesfireStatusWord.java
                status = resp[-1]
                unframed = list(resp[0:-2]) 

            status = resp[0] 
            # Check for known error interpretation
            if status == 0xaf:
                if allow_continue_fallthrough:
                    additional_framing_needed = False
                else:
                    # Need to loop more cycles to fill in receive buffer
                    additional_framing_needed = True
                    apdu_cmd = self.command(0xaf)  # Continue
            elif status != 0x00:
                raise DESFireCommunicationError(DESFire_STATUS(status).name, status)
            else:
                additional_framing_needed = False

            # This will un-memoryview this object as there seems to be some pyjnius
            # bug getting this corrupted down along the line
            unframed = list(resp[1:])
            result += unframed

        return result

    def communicate(self, apdu_cmd,description, nativ=False, allow_continue_fallthrough=False, isEncryptedComm = False, withTXCMAC = False, withCRC=False,withRXCMAC=True, encryptBegin=1):
        """
        cmd : the DESFire instruction byte (in hex format)
        data: optional parameters (in hex format)
        isEncryptedComm: bool indicates if the communication should be sent encrypted
        withTXCMAC: bool indicates if CMAC should be calculated
        autorecieve: bool indicates if the receptions should implement paging in case there is more deata to be sent by the card back then the max message size
        """
        result = []

        #sanity check
        if withTXCMAC or isEncryptedComm:
            if not self.isAuthenticated:
                raise Exception('Cant perform CMAC calc without authantication!')
        
        #encrypt the communication
        if isEncryptedComm:
            apdu_cmd=self.sessionKey.EncryptMsg(apdu_cmd,withCRC,encryptBegin)
        #communication with the card is not encrypted, but CMAC might need to be calculated
            #calculate cmac for outgoing message
        if withTXCMAC:
            TXCMAC = self.sessionKey.CalculateCmac(apdu_cmd)
            self.logger.debug("TXCMAC      : " + byte_array_to_human_readable_hex(TXCMAC))
        response = self._communicate(apdu_cmd,description,nativ, allow_continue_fallthrough)
        
        if self.isAuthenticated and len(response) >= 8 and withRXCMAC:
            #after authentication, there is always an 8 bytes long CMAC coming from the card, to ensure message integrity
            #todo: verify CMAC
            if len(response) == 8:
                #if self.sessionKey.keyType == DESFireKeyType.DF_KEY_3DES or self.sessionKey.keyType == DESFireKeyType.DF_KEY_2K3DES or self.sessionKey.keyType == DESFireKeyType.DF_KEY_3K3DES:
                RXCMAC = response
                response = []
                #else:
                #    #there is no CMAC
                #    return response
            else:
                RXCMAC = response[-8:]
                response = response[:-8]

            #if response == "":
            #    response = []
            cmacdata = response + [0x00]
            RXCMAC_CALC = self.sessionKey.CalculateCmac(cmacdata)
            self.logger.debug("RXCMAC      : " + byte_array_to_human_readable_hex(RXCMAC))
            self.logger.debug("RXCMAC_CALC: " + byte_array_to_human_readable_hex(RXCMAC_CALC))
            self.cmac=RXCMAC_CALC
            if bytes(RXCMAC) != bytes(RXCMAC_CALC[0:len(RXCMAC)]):
                raise Exception("RXCMAC not equal")

        return response
    @classmethod
    def wrap_command(cls, command, parameters=None):
        """Wrap a command to native DES framing.
        :param command: Command byte
        :param parameters: Command parameters as list of bytes
        https:g/github.com/greenbird/workshops/blob/master/mobile/Android/Near%20Field%20Communications/HelloWorldNFC%20Desfire%20Base/src/com/desfire/nfc/DesfireReader.java#L129
        """
        if parameters:
            return [0x90, command, 0x00, 0x00, len(parameters)] + parameters + [0x00]
        else:
            return [0x90,command,0x00,0x00,0x00]

    @classmethod
    def command(cls,command,parameters=None):
        if parameters:
            l=[command]
            l=l+parameters
            return l 
        else:
            return [command]



    def getApplicationIDs(self):
        """Lists all application on the card
        Authentication is NOT needed to call this function
        Args:
                None
        Returns:
                list: A list of application IDs, in a 4 byte hex form
        """
        self.logger.debug("GetApplicationIDs")
        appids = []
        cmd = DESFireCommand.DF_INS_GET_APPLICATION_IDS.value
        raw_data = self.communicate([cmd], 'Get Application IDs',nativ=True, withTXCMAC=self.isAuthenticated)

        pointer = 0
        apps = []
        while pointer < len(raw_data):
                appid = [raw_data[pointer+2]] + [raw_data[pointer+1]] + [raw_data[pointer]]
                self.logger.debug("Reading %s", byte_array_to_human_readable_hex(appid))
                apps.append(appid)
                pointer += 3

        return apps


    def getKeySetting(self):
        ret=DESFireKey()
        parameters=[]
        #apdu_command = self.command(DESFire_DEF.DF_INS_GET_KEY_SETTINGS.value)
        resp=self.communicate([DESFireCommand.DF_INS_GET_KEY_SETTINGS.value], "get key settings", nativ=True, withTXCMAC=self.isAuthenticated)
        ret.setKeySettings(resp[1] & 0x0f,DESFireKeyType(resp[1] & 0xf0),resp[0] & 0x07)
        return ret

    def getCardVersion(self):
        """Gets card version info blob
        Version info contains the UID, Batch number, production week, production year, .... of the card
        Authentication is NOT needed to call this function
        BEWARE: DESFire card has a security feature called "Random UID" which means that without authentication it will give you a random UID each time you call this function!
        Args:
                None
        Returns:
                DESFireCardVersion: Object containing all card version info parsed
        """
        self.logger.debug('Getting card version info')
        cmd = DESFireCommand.DF_INS_GET_VERSION.value
        raw_data = self.communicate([cmd], 'GetCardVersion',nativ=True, withTXCMAC=self.isAuthenticated) 
        return DESFireCardVersion(raw_data)



    def formatCard(self):
        """Formats the card
        WARNING! THIS COMPLETELY WIPES THE CARD AND RESETS IF TO A BLANK CARD!!
        Authentication is needed to call this function
        Args:
            None
        Returns:
            None
        """
        self.logger.debug('Formatting card')
        cmd = DESFireCommand.DF_INS_FORMAT_PICC.value
        self.communicate([cmd], 'Format Card',nativ=True, withTXCMAC=self.isAuthenticated)


    ###### Application related


    def selectApplication(self, appid):
        """Choose application on a card on which all the following commands will apply.
        Authentication is NOT ALWAYS needed to call this function. Depends on the application settings.
        Args:
            appid (int): The application ID of the app to be selected
        Returns:
            None
        """
        appid = getList(appid,3,'big')
        self.logger.debug('Selecting application with AppID %s' % (byte_array_to_human_readable_hex(appid),))
        
        parameters =  [ appid[2], appid[1], appid[0] ]
        

        cmd = DESFireCommand.DF_INS_SELECT_APPLICATION.value
        self.communicate(self.command(cmd, parameters),'select Application',nativ=True)
        #if new application is selected, authentication needs to be carried out again
        self.isAuthenticated = False
        self.lastSelectedApplication = appid

    def createApplication(self, appid, keysettings, keycount, type):
        """Creates application on the card with the specified settings
        Authentication is ALWAYS needed to call this function.
        Args:
            appid (int)       : The application ID of the app to be created
            keysettings (list): Key settings to be applied to the application to be created. MUST contain entryes derived from the DESFireKeySettings enum
            keycount (int)    : 
            type (int)        : Key type that will specify the encryption used for authenticating to this application and communication with it. MUST be coming from the DESFireKeyType enum
        Returns:
            None
        """
        appid = getList(appid,3,'big')
        self.logger.debug('Creating application with appid: %s, ' %(byte_array_to_human_readable_hex(appid)))
        appid = [appid[2],appid[1],appid[0]]
        keycount=getInt(keycount,'big')
        params = appid + [calc_key_settings(keysettings)] + [keycount|type.value]
        cmd = DESFireCommand.DF_INS_CREATE_APPLICATION.value
        self.communicate(self.command(cmd, params),'cereate application',nativ=True, withTXCMAC=self.isAuthenticated)

    def deleteApplication(self, appid):
        """Deletes the application specified by appid
        Authentication is ALWAYS needed to call this function.
        Args:
            appid (int)       : The application ID of the app to be deleted
        Returns:
            None
        """
        appid = getList(appid,3,'big')
        self.logger.debug('Deleting application for AppID %s', byte_array_to_human_readable_hex(appid))

        appid = [ appid[2], appid[1], appid[0] ]

        params = appid
        cmd = DESFireCommand.DF_INS_DELETE_APPLICATION.value
        self.communicate(self.command(cmd, params),'delete Application',nativ=True, withTXCMAC=self.isAuthenticated)

###################################################################################################################
### This Function is not refecored 
###################################################################################################################

    ###### FILE FUNTCIONS

    def getFileIDs(self):
        """Lists all files belonging to the application currently selected. (SelectApplication needs to be called first)
        Authentication is NOT ALWAYS needed to call this function. Depends on the application/card settings.
        Args:
            None
        Returns:
            list: A list of file IDs, in a 4 byte hex form
        """
        self.logger.debug('Enumerating all files for the selected application')
        fileIDs = []

        cmd = DESFireCommand.DF_INS_GET_FILE_IDS.value
        raw_data = self.communicate([cmd], 'get File ID\'s',nativ=True, withTXCMAC=self.isAuthenticated)
        if len(raw_data) == 0:
            self.logger.debug("No files found")
        else:
            for byte in raw_data:
                fileIDs.append(byte)
            self.logger.debug("File ids: %s" % (''.join([byte_array_to_human_readable_hex(bytearray([id])) for id in fileIDs]),))
        return fileIDs

    def getFileSettings(self, fileid):
        """Gets file settings for the File identified by fileid.(SelectApplication needs to be called first)
        Authentication is NOT ALWAYS needed to call this function. Depends on the application/card settings.
        Args:
            fileid (int): FileID to get the settings for
        
        Returns:
            DESFireFileSettings: An object describing all settings for the file
        """
        fileid=getList(fileid,1,'big')
        self.logger.debug('Getting file settings for file %s' % (byte_array_to_human_readable_hex(fileid),))

        cmd = DESFireCommand.DF_INS_GET_FILE_SETTINGS.value
        raw_data = raw_data = self.communicate(self.command(cmd, fileid),'Get File Settings',nativ=True, withTXCMAC=self.isAuthenticated)

        file_settings = DESFireFileSettings()
        file_settings.parse(raw_data)
        return file_settings

    def readFileData(self,fileId,offset,length):
        """Read file data for fileID (SelectApplication needs to be called first)
        Authentication is NOT ALWAYS needed to call this function. Depends on the application/card settings.
        Args:
            fileid (int): FileID to get the settings for
        Returns:
            str: the file data bytes
        """
        fileId=getList(fileId,1)
        offset=getInt(offset,'big')
        length=getInt(length,'big')
        ioffset=0
        ret=[]
        
        while (length > 0):
            count=min(length, 48)
            cmd=DESFireCommand.DF_INS_READ_DATA.value
            params=fileId+getList(offset+ioffset,3,'little')+getList(count,3,'little')
            ret+=self.communicate(self.command(cmd, params),'Read file data', nativ=True, withTXCMAC=self.isAuthenticated)
            ioffset+=count
            length-=count
        
        return ret

    def writeFileData(self,fileId,offset,length,data):
        fileId=getList(fileId,1)
        offset=getInt(offset,'big')
        length=getInt(length,'big')
        data=getList(data)
        ioffset=0
        
        while (length > 0):
            count=min(length, self.MaxFrameSize-8)
            cmd=DESFireCommand.DF_INS_WRITE_DATA.value
            params=fileId+getList(offset+ioffset,3,'little')+getList(count,3,'little')+data[ioffset:(ioffset+count)]
            self.communicate(self.command(cmd, params),'write file data', nativ=True, withTXCMAC=self.isAuthenticated)
            ioffset+=count
            length-=count

    def deleteFile(self,fileId):
         return self.communicate(self.command(DESFireCommand.DF_INS_DELETE_FILE.value, getList(fileId,1,'little')),'Delete File', nativ=True, withTXCMAC=self.isAuthenticated)

    def createStdDataFile(self, fileId, filePermissions, fileSize):
         params=getList(fileId,1,'big')
         params+=[0x00]
         params+=getList(filePermissions.pack(),2,'big')
         params+=getList(getInt(fileSize,'big'),3, 'little')
         apdu_command=self.command(DESFireCommand.DF_INS_CREATE_STD_DATA_FILE.value,params)
         self.communicate(apdu_command,'createStdDataFile', nativ=True, withTXCMAC=self.isAuthenticated)
         return
    
    
    ###### CRYPTO KEYS RELATED FUNCTIONS



    def getKeyVersion(self, keyNo):
        """Gets the key version for the key identified by keyno. (SelectApplication needs to be called first, otherwise it's getting the settings for the Master Key)
        Authentication is ALWAYS needed to call this function.
        Args:
            keyNo (int) : The key number
        Returns:
            str: key version byte
        """
        self.logger.debug('Getting key version for keyid %x' %(keyNo,))

        params = getList(keyNo,1,'big')
        cmd = DESFireCommand.DF_INS_GET_KEY_VERSION.value
        raw_data = self.communicate(self.command(cmd, params),'get key version',nativ=True, withTXCMAC=self.isAuthenticated)
        self.logger.debug('Got key version 0x%s for keyid %x' + str(keyNo))
        return raw_data

    def changeKeySettings(self, newKeySettings):
        """Changes key settings for the key that was used to authenticate with in the current session.
        Authentication is ALWAYS needed to call this function.
        Args:
            newKeySettings (list) : A list with DESFireKeySettings enum value
        
        Returns:
            None
        """
        #self.logger.debug('Changing key settings to %s' %('|'.join(a.name for a in newKeySettings),))
        params = [calc_key_settings(newKeySettings)]
        cmd = DESFireCommand.DF_INS_CHANGE_KEY_SETTINGS.value
        raw_data = self.communicate(self.command(cmd,params),'change key settings', nativ=True, isEncryptedComm=True, withCRC=True)


    def changeKey(self, keyNo, newKey, curKey):
        """Changes current key (curKey) to a new one (newKey) in specified keyslot (keyno)
        Authentication is ALWAYS needed to call this function.
        Args:
            keyNo  (int) : Key number
            newKey (DESFireKey)    : The new key
            curKey (DESFireKey)    : The current key for that keyslot
        
        Returns:
            None
        """

        keyNo=getInt(keyNo,'big')
        self.logger.debug(' -- Changing key --')
        #self.logger.debug('Changing key No: %s from %s to %s' % (keyNo, newKey, curKey))
        if not self.isAuthenticated:
            raise Exception('Not authenticated!')

        self.logger.debug('curKey : ' +  byte_array_to_human_readable_hex(curKey.getKey()))
        self.logger.debug('newKey : ' +  byte_array_to_human_readable_hex(newKey.getKey()))

        isSameKey = (keyNo == self.lastAuthKeyNo)
        #self.logger.debug('isSameKey : ' + str(isSameKey))
        

        # The type of key can only be changed for the PICC master key.
        # Applications must define their key type in CreateApplication().
        if self.lastSelectedApplication == 0x00:
            keyNo = keyNo | newKey.keyType.value
        
        cryptogram = self.command(DESFireCommand.DF_INS_CHANGE_KEY.value, [keyNo])
        #The following if() applies only to application keys.
        #For the PICC master key b_SameKey is always true because there is only ONE key (#0) at the PICC level.
        if not isSameKey:
            keyData_xor=[]
            if len(newKey.getKey())>len(curKey.getKey()):
                 keyData_xor = bytearray(strxor(bytes(newKey.getKey()), bytes(curKey.getKey()*2)))
            else:
                 keyData_xor = bytearray(strxor(bytes(newKey.getKey()), bytes(curKey.getKey())))
            cryptogram += keyData_xor
        else:
            cryptogram += newKey.getKey()
         
        if newKey.keyType == DESFireKeyType.DF_KEY_AES:
            cryptogram += [newKey.keyVersion]


        cryptogram += bytearray(CRC32(cryptogram).to_bytes(4, byteorder='little'))
        if not isSameKey:
            cryptogram += bytearray(CRC32(newKey.getKey()).to_bytes(4, byteorder='little'))

        #self.logger.debug( (int2hex(DESFireCommand.DF_INS_CHANGE_KEY.value) + int2hex(keyNo) + cryptogram).encode('hex'))
        raw_data = self.communicate(cryptogram,'change key',nativ=True, isEncryptedComm = True, withRXCMAC = not isSameKey, withTXCMAC = False, withCRC= False, encryptBegin=2)

        #If we changed the currently active key, then re-auth is needed!
        if isSameKey:
            self.isAuthenticated = False
            self.sessionKey = None

        return


#######################################################################################################################################
### Helper function
#######################################################################################################################################

    def createKeySetting(self,key, keyNumbers, keyType, keySettings):
        ret=DESFireKey()
        ret.setKeySettings(getInt(keyNumbers,'big'),keyType,calc_key_settings(keySettings))
        ret.setKey(getList(key))
        return ret


