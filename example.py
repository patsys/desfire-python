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
            desfire.createApplication("00 AE 16",[DESFireKeySettings.KS_ALLOW_CHANGE_MK,DESFireKeySettings.KS_LISTING_WITHOUT_MK,DESFireKeySettings.KS_CONFIGURATION_CHANGEABLE],10,DESFireKeyType.DF_KEY_AES)
            desfire.selectApplication('00 AE 16')
            default_key=desfire.createKeySetting('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',0,DESFireKeyType.DF_KEY_AES,[])            
            app_key=desfire.createKeySetting('00 10 20 31 40 50 60 70 80 90 A0 B0 B0 A0 90 80',0,DESFireKeyType.DF_KEY_AES,[])
            desfire.authenticate(0,default_key)
            desfire.changeKey(0,app_key,default_key)
            desfire.authenticate(0,app_key)
            desfire.changeKeySettings([DESFireKeySettings.KS_ALLOW_CHANGE_MK,DESFireKeySettings.KS_CONFIGURATION_CHANGEABLE,DESFireKeySettings,DESFireKeySettings.KS_CHANGE_KEY_WITH_KEY_1])

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
