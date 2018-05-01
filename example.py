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
            desfire.authenticate(0,key_setting,'84 9B 36 C5 F8 BF 4A 09')
            desfire.getCardVersion()
            desfire.formatCard()
            desfire.createApplication("00 DE 16",[DESFireKeySettings.KS_ALLOW_CHANGE_MK,DESFireKeySettings.KS_LISTING_WITHOUT_MK,DESFireKeySettings.KS_CREATE_DELETE_WITHOUT_MK,DESFireKeySettings.KS_CONFIGURATION_CHANGEABLE],2,DESFireKeyType.DF_KEY_2K3DES)       
            desfire.createApplication("00 DE 24",[DESFireKeySettings.KS_ALLOW_CHANGE_MK,DESFireKeySettings.KS_LISTING_WITHOUT_MK,DESFireKeySettings.KS_CREATE_DELETE_WITHOUT_MK,DESFireKeySettings.KS_CONFIGURATION_CHANGEABLE],2,DESFireKeyType.DF_KEY_3K3DES)
            desfire.createApplication("00 AE 16",[DESFireKeySettings.KS_ALLOW_CHANGE_MK,DESFireKeySettings.KS_LISTING_WITHOUT_MK,DESFireKeySettings.KS_CREATE_DELETE_WITHOUT_MK,DESFireKeySettings.KS_CONFIGURATION_CHANGEABLE],2,DESFireKeyType.DF_KEY_AES)
            desfire.createApplication("AA BB CC",[DESFireKeySettings.KS_ALLOW_CHANGE_MK,DESFireKeySettings.KS_LISTING_WITHOUT_MK,DESFireKeySettings.KS_CREATE_DELETE_WITHOUT_MK,DESFireKeySettings.KS_CONFIGURATION_CHANGEABLE],1,DESFireKeyType.DF_KEY_2K3DES)
            desfire.getApplicationIDs()
            desfire.deleteApplication("AA BB CC")
            desfire.getApplicationIDs()
            desfire.selectApplication('00 DE 16')
            key_setting.setKey('00 00 00 00 00 00 00 00')
            desfire.authenticate(0,key_setting,'49 EC 63 DE CD E0 07 72')
            desfire.getKeySetting()
            desfire.changeKeySettings([DESFireKeySettings.KS_ALLOW_CHANGE_MK,DESFireKeySettings.KS_CREATE_DELETE_WITHOUT_MK,DESFireKeySettings.KS_CONFIGURATION_CHANGEABLE])
            desfire.getKeySetting()
            print(key_setting)
            key_setting=desfire.getKeySetting()
            desfire.authenticate(0,key_setting,'C9 6C E3 5E 4D 60 87 F2')
            new_key=desfire.createKeySetting('00 10 20 31 40 50 60 70 80 90 A0 B0 B0 A0 90 80',0,DESFireKeyType.DF_KEY_2K3DES,[])
            desfire.changeKey(0,new_key,key_setting)
            desfire.authenticate(0,new_key,'53 0E 3D 90 F7 A2 01 C4')
            new_key2=desfire.createKeySetting('10 18 20 29 30 38 40 48 50 58 60 68 70 78 80 88',0,DESFireKeyType.DF_KEY_2K3DES,[])
            desfire.changeKey(0,new_key2,new_key)
            desfire.authenticate(0,new_key2,'DD B0 97 C2 A1 E4 7B 96')
            desfire.getKeyVersion(0)
            new_key3=desfire.createKeySetting('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',0,DESFireKeyType.DF_KEY_2K3DES,[])
            desfire.changeKey(0,new_key3,new_key2)
            desfire.authenticate(0,key_setting,'CB A6 75 E8 EF BA B9 9C')
            new_key4=desfire.createKeySetting('00 10 20 31 40 50 60 70 80 90 A0 B0 B0 A0 90 80',0,DESFireKeyType.DF_KEY_2K3DES,[])
            desfire.changeKey(1,new_key4,key_setting)
            new_key5=desfire.createKeySetting('10 18 20 29 30 38 40 48 50 58 60 68 70 78 80 88',0,DESFireKeyType.DF_KEY_2K3DES,[])
            desfire.changeKey(1,new_key5,new_key4)

            #applications = desfire.get_applications()
            #for app_id in applications:
            #    logger.info("Found application 0x%06x", app_id)

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
