from __future__ import print_function

import json
import logging
import time

import random
import pyDes
from .device import Device
from .DESFire_DEF import *
from .util import byte_array_to_human_readable_hex, dword_to_byte_array, word_to_byte_array


_logger = logging.getLogger(__name__)
class DESFireCommunicationError(Exception):
    """Outgoing DESFire command received a non-OK reply.
    The exception message is human readable translation of the error code if available. The ``status_code`` carries the original status word error byte.
    """


    def __init__(self, msg, status_code):
        super(DESFireCommunicationError, self).__init__(msg)
        self.status_code = status_code

class DESFire:
    isAuthenticated = False
    
    def __init__(self, device, logger=None):
        """
        :param device: :py:class:`desfire.device.Device` implementation
        :param logger: Python :py:class:`logging.Logger` used for logging output. Overrides the default logger. Extensively uses ``INFO`` logging level.
        """

        #assert isinstance(device, Device), "Not a compatible device instance: {}".format(device)

        self.device = device

        #: 8 bytes of session key after authenticate()
        self.session_key = None

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
            RndA = challenge
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

        #if keyType == DESFireKeyType.DF_KEY_2K3DES or keyType == DESFireKeyType.DF_KEY_3K3DES:
        #    sessionKeyBytes = intlist2hex([a & 0b11111110 for a in hex2bytelist(sessionKeyBytes)])
    
        ## now we have the session key, so we reinitialize the crypto!!!
        key.setKey(sessionKeyBytes)
        key.CiperInit()
        key.GenerateCmacSubkeys()

        self.logger.debug( 'Cmac1: ' + sessionKey.Cmac1.encode('hex').upper())
        self.logger.debug( 'Cmac2: ' + sessionKey.Cmac2.encode('hex').upper())
        self.logger.debug( 'sessionKey: ' + sessionKey.keyBytes.encode('hex').upper())
        self.sessionKey = sessionKey
        return sessionKey 

    def communicate(self, apdu_cmd, description,nativ=False, allow_continue_fallthrough=False):
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

            apdu_cmd_hex = [hex(c) for c in apdu_cmd]
            self.logger.debug("Running APDU command %s, sending: %s", description, apdu_cmd_hex)

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
                    apdu_cmd = self.wrap_command(0xaf)  # Continue
            elif status != 0x00:
                raise DESFireCommunicationError(DESFire_STATUS(status).name, status)
            else:
                additional_framing_needed = False

            # This will un-memoryview this object as there seems to be some pyjnius
            # bug getting this corrupted down along the line
            unframed = list(resp[1:])
            result += unframed

        return result

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


    def shift_bytes(self, resp,count):
        """Handle response for command 0x6a list applications.
        DESFire application ids are 24-bit integers.
        :param resp: DESFire response as byte array
        :return: List of parsed application ids
        """
        pointer = 0
        apps = []
        while pointer < len(resp):
            shift=count*8
            appid=0
            for i in range(0,count):
                app_id = (resp[pointer] << shift)
                pointer+=1
                shift-=8
            apps.append(app_id)
            self.logger.debug("Reading %d %08x", pointer, app_id)
        return apps

    def get_applications(self):
        """Get all applications listed in Desfire root.
        :return: List of 24-bit integer
        :raise: :py:class:`desfire.protocol.DESFireCommunicationError` on any error
        """

        # https:g/ridrix.wordpress.com/2009/09/19/mifare-desfire-communication-example/
        cmd = self.wrap_command(DESFireCommand.DF_INS_GET_APPLICATION_IDS.value)
        resp = self.communicate(cmd,  "Read applications")
        apps = self.shift_bytes(resp,3)
        return apps


    def select_application(self, app_id):
        """Choose application on a card on which all the following file commands will apply.
        :param app_id: 24-bit int
        :raise: :py:class:`desfire.protocol.DESFireCommunicationError` on any error
        """
        # https:g/github.com/greenbird/workshops/blob/master/mobile/Android/Near%20Field%20Communications/HelloWorldNFC%20Desfire%20Base/src/com/desfire/nfc/DesfireReader.java#L53
        parameters = [
            (app_id >> 16) & 0xff,
            (app_id >> 8) & 0xff,
            (app_id >> 0) & 0xff,
        ]

        apdu_command = self.wrap_command(DESFireCommand.DF_INS_SELECT_APPLICATION.value, parameters)

        self.communicate(apdu_command, "Selecting application {:06X}".format(app_id))



    def getKeySetting(self):
        ret=DESFireKey()
        parameters=[]
        #apdu_command = self.command(DESFire_DEF.DF_INS_GET_KEY_SETTINGS.value)
        resp=self.communicate([DESFireCommand.DF_INS_GET_KEY_SETTINGS.value], "get key settings", True)
        ret.setKeySettings(resp[1] & 0x0f,DESFireKeyType(resp[1] & 0xf0),resp[0] & 0x07)
        return ret
