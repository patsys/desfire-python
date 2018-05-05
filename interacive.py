from __future__ import print_function



import copy
import functools
import logging
import time
import sys
import os

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

    desfire = None
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
            self.desfire = DESFire(PCSCDevice(connection.component))
            while True:
                num=int(input("""
10. Authenticate
----------------------------
20. Get card information
21. Format card
----------------------------
30. Create application
31. Select applicatino
32. List application
----------------------------
40. Change key
41. Get key settings
42. Change key settings
----------------------------
50. Craete file
51. List files 
52. Write file
53. Read file
90. Exit
"""))
                if num == 90:
                    break;
                elif num == 10:
                    self.auth()
                elif num == 20:
                    self.getCardInfo()
                elif num == 21:
                    self.formatCard()
                elif num == 30:
                    self.createApplication()
                elif num == 31:
                    self.selectApplication()
                elif num == 32:
                    self.listApplication()
                elif num == 40:
                    self.changeKey()
                elif num == 41:
                    self.getKeySettings()
                elif num == 42:
                    self.changeKeySettings()
                elif num == 50:
                    self.createFile()
                elif num == 51:
                    self.listFiles()
                elif num == 52:
                    self.writeFile()
                elif num == 53:
                    self.readFile()

    def auth(self):
        key=self.desfire.getKeySetting()
        key.setKey(input('Key: '))
        self.desfire.authenticate(int(input('Key pos: ')),key)

    def getCardInfo(self):
        print(self.desfire.getCardVersion())

    def formatCard(self):
        self.desfire.formatCard()

    def createApplication(self):
        aid=input('App id: ')
        size=int(input('Number keys: '))
        i=1
        l=list()
        print('Set Settings(y/n):')
        for s in  DESFireKeySettings:
            if input(s.name + ': ') == 'y':
                l+=[s]
            if i == 4:
                break
            i+=1
        k=int(input('Select key for change othor keys: '))
        v=input('Select Enryption(2K3DES,№K3DES,AES): ') 
        l+=[DESFireKeySettings(k<<4)]
        self.desfire.createApplication(aid,l,size,DESFireKeyType['DF_KEY_'+v])

    def changeKey(self):
        i=int(input('Key pos: '))
        old_key=self.desfire.getKeySetting()
        new_key=copy.copy(old_key)
        old_key.setKey(input('Old key: '))
        new_key.setKey(input('New key: '))
        self.desfire.changeKey(i,new_key,old_key)

    def selectApplication(self):
        self.desfire.selectApplication(input('Application id: '))

    def listApplication(self):
        for ids in self.desfire.getApplicationIDs():
            print(byte_array_to_human_readable_hex(ids))

    def changeKeySettings(self):
        i=1
        l=list()
        print('Set Settings(y/n):')
        for s in  DESFireKeySettings:
            if input(s.name + ': ') == 'y':
                l+=[s]
            if i == 4:
                break
            i+=1
        k=int(input('Select key for change othor keys: '))
        l+=[DESFireKeySettings(k<<4)]
        self.desfire.changeKeySettings(l)

    def getKeySettings(self):
        print(self.desfire.getKeySetting())

    def createFile(self):
        filePerm=DESFireFilePermissions()
        filePerm.setPerm(int(input('Read key number: ')),int(intput('Write key number')),int(input('read/write key number: ')),int(input('Change permmision key number: '))) # key 4 read, key3 write, no key read and write, key2 change permissions
        self.desfire.createStdDataFile(int(input('File id: ')),filePerm,int(input('File lenght: '))) # file Id 0, length 32 byte

    def writeFile(self):
        self.desfire.writeFileData(int(input('File id: ')),int(input('Offset')),int(input('Length: ')),input('Data: '))

    def readFile(self):
        print(byte_array_to_human_readable_hex(self.desfire.readFileData(int(input('File id: ')),int(input('Offset')),int(input('Length: ')))))

    def getFileSettings(self):
        self.desfire.getFileSettings(int(input('File id: ')))

    def listFiles(self):
        print(self.desfire.getFileIDs())


def main():
    global logger

    logging.basicConfig(level=logging.ERROR)
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
