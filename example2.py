###############################################################################
### This example need a card with default Masterkey
### Than do the follow things
### - Format card       all data will be lost
### - Create app        with ID 00AE16
### - Select app
### - Change key        0, app masterkey
### - Change setting    key 1 need to change other keys
### - Change key        1
### - Auth key          1
### - Change key        2,3,4
### - Create file       ID 0
### - Auth key          3
### - Write data        file ID 0
### - Auth key          4
### - Read data         file ID 0

from __future__ import print_function

import functools
import logging
import time
import sys

from smartcard.System import readers
from smartcard.CardMonitoring import CardMonitor, CardObserver
from smartcard.util import toHexString
from smartcard.CardConnectionObserver import ConsoleCardConnectionObserver

from Desfire.DESFire import *
from Desfire.util import byte_array_to_human_readable_hex
from Desfire.pcsc import PCSCDevice

IGNORE_EXCEPTIONS = (KeyboardInterrupt, MemoryError,)


def catch_gracefully():
    """Function decorator to show any Python exceptions occured inside a function.

    Use when the underlying thread main loop does not provide satisfying exception output.
    """
    def _outer(func):

        @functools.wraps(func)
        def _inner(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if isinstance(e, IGNORE_EXCEPTIONS):
                    raise
                else:
                    logger.error("Catched exception %s when running %s", e, func)
                    logger.exception(e)

        return _inner

    return _outer


class MyObserver(CardObserver):
    """Observe when a card is inserted. Then try to run DESFire application listing against it."""

    # We need to have our own exception handling for this as the
    # # main loop of pyscard doesn't seem to do any exception output by default
    @catch_gracefully()
    def update(self, observable, actions):

        (addedcards, removedcards) = actions

        for card in addedcards:
            logger.info("+ Inserted: %s", toHexString(card.atr))

            connection = card.createConnection()
            connection.connect()

            # This will log raw card traffic to console
            connection.addObserver(ConsoleCardConnectionObserver())
            # connection object itself is CardConnectionDecorator wrapper
            # and we need to address the underlying connection object
            # directly
            logger.info("Opened connection %s", connection.component)
            desfire = DESFire(PCSCDevice(connection.component))
            key_setting=desfire.getKeySetting()
            logger.info('Auth Key %d',0)
            info=desfire.getCardVersion()
            logger.info(info)
            default_key=desfire.createKeySetting('00 00 00 00 00 00 00 00',0,DESFireKeyType.DF_KEY_2K3DES,[])
            try:
                desfire.authenticate(0,default_key)
            except  DESFireCommunicationError as DCE:
                key = input('Key in Hex:')
                default_key=desfire.createKeySetting(key,0,DESFireKeyType.DF_KEY_2K3DES,[])
                desfire.authenticate(0,default_key)
            logger.info('Format card')
            desfire.formatCard()
            new_picc=desfire.getKeySetting()
            default_key_1=desfire.createKeySetting('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',0,DESFireKeyType.DF_KEY_2K3DES,[])

            new_picc.setKey('01 23 45 67 89 AB CD EF 02 13 46 57 8A 9B CE DF')
            desfire.changeKey(0,new_picc,default_key_1)
            logger.info('Create application with ID 00AE16')
            desfire.createApplication("00 AE 16",[DESFireKeySettings.KS_ALLOW_CHANGE_MK,DESFireKeySettings.KS_LISTING_WITHOUT_MK,DESFireKeySettings.KS_CONFIGURATION_CHANGEABLE],14,DESFireKeyType.DF_KEY_AES)
            logger.info('Select application with ID 00AE16')
            desfire.selectApplication('00 AE 16')
            default_app_key=desfire.createKeySetting('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',0,DESFireKeyType.DF_KEY_AES,[])
            app_key=desfire.createKeySetting('00 10 20 31 40 50 60 70 80 90 A0 B0 B0 A0 90 80',0,DESFireKeyType.DF_KEY_AES,[])
            logger.info('Auth Key %d',0)
            try:
                desfire.authenticate(0,default_app_key)
            except  DESFireCommunicationError as DCE:
                key = input('Key in Hex:')
                default_app_key=desfire.createKeySetting(key,0,DESFireKeyType.DF_KEY_AES,[])
                desfire.authenticate(0,default_key)

            logger.info('Cange Key %d',0)
            desfire.changeKey(0,app_key,default_app_key)
            logger.info('Auth Key %d',0)
            desfire.authenticate(0,app_key)
            desfire.changeKeySettings([ DESFireKeySettings.KS_ALLOW_CHANGE_MK, DESFireKeySettings.KS_CONFIGURATION_CHANGEABLE, DESFireKeySettings.KS_CHANGE_KEY_WITH_KEY_1])
            app_key_1=desfire.createKeySetting('11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00',0,DESFireKeyType.DF_KEY_AES,[])
            logger.info('Cange Key %d',1)
            desfire.changeKey(1,app_key_1,default_app_key)
            logger.info('Auth Key %d',1)
            desfire.authenticate(1,app_key_1)
            app_key_2=desfire.createKeySetting('22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00 11',0,DESFireKeyType.DF_KEY_AES,[])
            logger.info('Cange Key %d',2)
            desfire.changeKey(2,app_key_2,default_app_key)
            app_key_3=desfire.createKeySetting('33 44 55 66 77 88 99 AA BB CC DD EE FF 00 11 22',0,DESFireKeyType.DF_KEY_AES,[])
            logger.info('Cange Key %d',3)
            desfire.changeKey(3,app_key_3,default_app_key)
            app_key_4=desfire.createKeySetting('44 55 66 77 88 99 AA BB CC DD EE FF 00 11 22 33',0,DESFireKeyType.DF_KEY_AES,[])
            logger.info('Cange Key %d',4)
            desfire.changeKey(4,app_key_4,default_app_key)
            logger.info('Auth Key %d',0)
            desfire.authenticate(0,app_key)
            filePerm=DESFireFilePermissions()
            filePerm.setPerm(0x04,0x03,0x0F,0x02) # key 4 read, key3 write, no key read and write, key2 change permissions
            logger.info('Creat File with ID %d and %d byte',0,32)
            desfire.createStdDataFile(0,filePerm,32) # file Id 0, length 32 byte
            logger.info('Auth Key %d',3)
            desfire.authenticate(3,app_key_3)
            write='00 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20'
            logger.info('Data write %s',write)
            desfire.writeFileData(0,0,32,write)
            logger.info('Auth Key %d',4)
            desfire.authenticate(4,app_key_4)
            read=desfire.readFileData(0,0,32)
            logger.info('Data read %s',byte_array_to_human_readable_hex(read))







def main():
    global logger

    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger(__name__)

    logger.info("Insert MIFARE Desfire card to any reader to get its applications.")

    available_reader = readers()
    logger.info("Available readers: %s", available_reader)
    if not available_reader:
        sys.exit("No smartcard readers detected")

    cardmonitor = CardMonitor()
    cardobserver = MyObserver()
    cardmonitor.addObserver(cardobserver)

    while True:
        time.sleep(1)

    # don't forget to remove§ observer, or the
    # monitor will poll forever...
    cardmonitor.deleteObserver(cardobserver)



if __name__ == "__main__":
    main()
