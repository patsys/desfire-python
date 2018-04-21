from __future__ import print_function

import logging
import time

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
    def __init__(self, device, logger=None):
        """
        :param device: :py:class:`desfire.device.Device` implementation
        :param logger: Python :py:class:`logging.Logger` used for logging output. Overrides the default logger. Extensively uses ``INFO`` logging level.
        """

        assert isinstance(device, Device), "Not a compatible device instance: {}".format(device)

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

        # TODO: Clean this up so read/write implementations have similar mechanisms and all continue is handled internally
        while additional_framing_needed:

            apdu_cmd_hex = [hex(c) for c in apdu_cmd]
            self.logger.debug("Running APDU command %s, sending: %s", description, apdu_cmd_hex)

            resp = self.device.transceive(apdu_cmd)
            self.logger.debug("Received APDU response: %s", byte_array_to_human_readable_hex(resp))


            if not nativ:
                if resp[-2] != 0x91:
                    raise DESFireCommunicationError("Received invalid response for command: {}".format(description), resp[-2:])
            # Possible status words: https://github.com/jekkos/android-hce-desfire/blob/master/hceappletdesfire/src/main/java/net/jpeelaer/hce/desfire/DesfireStatusWord.java
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
        https://github.com/greenbird/workshops/blob/master/mobile/Android/Near%20Field%20Communications/HelloWorldNFC%20Desfire%20Base/src/com/desfire/nfc/DesfireReader.java#L129
        """
        if parameters:
            return [0x90, command, 0x00, 0x00, len(parameters)] + parameters + [0x00]
        else:
            return [0x90,command,0x00,0x00,0x00]

    @classmethod
    def command(command):
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

        # https://ridrix.wordpress.com/2009/09/19/mifare-desfire-communication-example/
        cmd = self.wrap_command(DESFire_DEF.DF_INS_GET_APPLICATION_IDS.value)
        resp = self.communicate(cmd,  "Read applications")
        apps = self.shift_bytes(resp,3)
        return apps


    def select_application(self, app_id):
        """Choose application on a card on which all the following file commands will apply.
        :param app_id: 24-bit int
        :raise: :py:class:`desfire.protocol.DESFireCommunicationError` on any error
        """
        # https://github.com/greenbird/workshops/blob/master/mobile/Android/Near%20Field%20Communications/HelloWorldNFC%20Desfire%20Base/src/com/desfire/nfc/DesfireReader.java#L53
        parameters = [
            (app_id >> 16) & 0xff,
            (app_id >> 8) & 0xff,
            (app_id >> 0) & 0xff,
        ]

        apdu_command = self.wrap_command(DESFire_DEF.DF_INS_SELECT_APPLICATION.value, parameters)

        self.communicate(apdu_command, "Selecting application {:06X}".format(app_id))



    def get_key_setting(self):
        ret=DESFireKeyOpt()
        parameters=[]
        #apdu_command = self.command(DESFire_DEF.DF_INS_GET_KEY_SETTINGS.value)
        resp=self.communicate([DESFire_DEF.DF_INS_GET_KEY_SETTINGS.value], "get key settings", True)
        ret.key_size=resp[1] & 0x0f
        ret.key_type=DESFireKeyType(resp[1] & 0xf0)
        ret.key_settings=resp[0] & 0x07
        return ret
