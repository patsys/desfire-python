###############################################################################
### This example need a card with default Masterkey
### Than do the follow things
### - Format card          all data will be lost
### - Create app           with ID 00AE17
### - Select app   
### - Change key           0, app masterkey
### - Change setting       key 1 need to change other keys
### - Change key           1
### - Auth key             1
### - Change key           2
### - Create value-file    ID 0
### - Auth key             2
### - Prepare debit        file ID 0, amount 100
### - Auth key             2
### - Read value           file ID 0
### - Commit transaction   
### - Read value           file ID 0

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
            if card.reader.startswith('Yubico'):
                logger.info("Ignore Yubikey %s", toHexString(card.atr))
                return
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
            desfire.authenticate(0,key_setting)
            info=desfire.getCardVersion()
            logger.info(info)
            logger.info('Format card')
            desfire.formatCard()
            logger.info('Create application with ID 00AE17')
            desfire.createApplication("00 AE 17",[DESFireKeySettings.KS_ALLOW_CHANGE_MK,DESFireKeySettings.KS_LISTING_WITHOUT_MK,DESFireKeySettings.KS_CONFIGURATION_CHANGEABLE],14,DESFireKeyType.DF_KEY_AES)
            logger.info('Select application with ID 00AE17')
            desfire.selectApplication('00 AE 17')
            default_key=desfire.createKeySetting('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',0,DESFireKeyType.DF_KEY_AES,[])            
            app_key=desfire.createKeySetting('00 10 20 31 40 50 60 70 80 90 A0 B0 B0 A0 90 80',0,DESFireKeyType.DF_KEY_AES,[])
            logger.info('Auth Key %d',0)
            desfire.authenticate(0,default_key)
            logger.info('Cange Key %d',0)
            desfire.changeKey(0,app_key,default_key)
            logger.info('Auth Key %d',0)
            desfire.authenticate(0,app_key)
            desfire.changeKeySettings([ DESFireKeySettings.KS_ALLOW_CHANGE_MK, DESFireKeySettings.KS_CONFIGURATION_CHANGEABLE, DESFireKeySettings.KS_CHANGE_KEY_WITH_KEY_1])
            app_key_1=desfire.createKeySetting('11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00',0,DESFireKeyType.DF_KEY_AES,[])
            logger.info('Cange Key %d',1)
            desfire.changeKey(1,app_key_1,default_key)
            logger.info('Auth Key %d',1)
            desfire.authenticate(1,app_key_1)
            app_key_2=desfire.createKeySetting('22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00 11',0,DESFireKeyType.DF_KEY_AES,[])
            logger.info('Cange Key %d',2)
            desfire.changeKey(2,app_key_2,default_key)
            logger.info('Auth Key %d',0)
            desfire.authenticate(0,app_key)
            filePerm=DESFireFilePermissions()
            filePerm.setPerm(0x0F,0x0F,0x02,0x01) # no key read, no key write, key 2 read and write, key1 change permissions
            logger.info('Creat Value-File with ID %d and start-amount of 1,000',0)
            desfire.createValueFile(0,filePerm,value=1_000) # file Id 0, start-amount 1000
            logger.info('Auth Key %d',2)
            desfire.authenticate(2,app_key_2)
            logger.info('Data debit amount %d',100)
            desfire.debit(0,100)
            logger.info('Auth Key %d', 2)
            desfire.authenticate(2, app_key_2) # reading also needs write capability
            logger.info('Get current value of value-file %d', 0)
            value = desfire.getValue(0)
            logger.info('The current value is %d', value) #The value is still 1000, because the transaction is not commited
            logger.info('Commit transaction')
            desfire.commitTransaction()
            desfire.authenticate(2, app_key_2) # reading also needs write capability
            logger.info('Get current value of value-file %d', 0)
            value = desfire.getValue(0)
            logger.info('The current value is %d', value) # Now the value is updated






def main():
    global logger

    logging.basicConfig(level=logging.INFO)
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
