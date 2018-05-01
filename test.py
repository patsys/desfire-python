import logging
from Desfire.DESFire import *
from Desfire.pcsc import DummyPCSCDevice




def Test_DES():
        """
        *** GetCardVersion()
        TX CMAC:  50 20 EC 82 60 86 DF 12
        Sending:  00 00 FF 04 FC <D4 40 01 60> 8B 00
        Response: 00 00 FF 0B F5 <D5 41 00 AF 04 01 01 01 00 1A 05> 15 00 AA AA AA AA AA AA AA AA
        Sending:  00 00 FF 04 FC <D4 40 01 AF> 3C 00
        Response: 00 00 FF 0B F5 <D5 41 00 AF 04 01 01 01 04 1A 05> 11 00 AA AA AA AA AA AA AA AA
        Sending:  00 00 FF 04 FC <D4 40 01 AF> 3C 00
        Response: 00 00 FF 1A E6 <D5 41 00 00 04 06 3F 72 63 34 80 BA 45 19 E3 20 49 13 CD C8 10 BA FA 40 17 59> 98 00
        RX CMAC:  CD C8 10 BA FA 40 17 59
        """

        print('Test Des')
        reader=DummyPCSCDevice()
        
        
        reader=DummyPCSCDevice()
        #Auth
        reader.addResponse('45', ['00 0F 01','00 0F 02 25 DD 8D 77 31 B1 CF D5','00 0D 02 61 3F B2 D3 F4 53 D2 E4'])
        reader.addResponse('1A 00',['AF 5D 99 4C E0 85 F2 40 89','AF 84 76 D1 CF 30 24 B7 C7'])
        reader.addResponse('AF 21 D0 AD 5F 2F D9 74 54 A7 46 CC 80 56 7F 1B 1C',['00 91 3C 6D ED 84 22 1C 41'])
        #Get Card information
        reader.addResponse('60',['AF 04 01 01 01 00 1A 05'])
        reader.addResponse('AF',['AF 04 01 01 01 04 1A 05','00 04 06 3F 72 63 34 80 BA 45 19 E3 20 49 13 CD C8 10 BA FA 40 17 59'])
        #Format Card
        reader.addResponse('FC',['00 9C 2C 81 3A 06 5C 45 F7'])
        #Create Application 2 Key 2K3DES
        reader.addResponse('CA 16 DE 00 0F 02',['00 0A 13 79 B0 1D 85 AD 47'])
        #Create Application 1 Key 2K3DES
        reader.addResponse('CA CC BB AA 0F 01',['00 F1 1A C0 73 8E F8 38 78'])
        #Create Application AES
        reader.addResponse('CA 16 AE 00 0F 82',['00 3B 68 D7 2A 3B E0 D2 0C'])
        #Create Application 3K3DES
        reader.addResponse('CA 24 DE 00 0F 42',['00 5D 73 AE 52 87 A1 BB E4'])
        #Get Application IDS
        reader.addResponse('6A',['00 16 DE 00 24 DE 00 16 AE 00 CC BB AA 27 39 15 4E 26 30 D6 50','00 16 DE 00 24 DE 00 16 AE 00 52 0E 51 E0 0A F0 6D 5E'])
        #Delete Application
        reader.addResponse('DA CC BB AA',['00 A9 AF 19 05 22 92 F6 62'])
        #Select Application
        reader.addResponse('5A 16 DE 00',['00'])
        #Authenticate 2
        reader.addResponse('AF DA C6 7A B7 43 76 3D C9 FA F8 A0 AE 50 4E 80 C5',['00 13 E9 E4 FA 43 88 BF 16'])
        #Cange Key Setting
        reader.addResponse('54 27 88 28 05 FC 3F D4 9D',['00 A6 28 37 83 74 27 0A CD'])

        desfire = DESFire(reader)
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
        
        
        print('[+] Test_DES Succsess')


def Test_2k3DES():
        reader=DummyPCSCDevice()
        #Get key Settings
        reader.addResponse('45', ['00 0F 01'])
        #Select Application
        reader.addResponse('5A 16 DE 00',['D5 41 00 00'])
        #Auth DES
        reader.addResponse('1A 00',['AF DE 50 F9 23 10 CA F5 A5','AF B2 95 57 99 26 15 5A E3','AF 94 14 81 9C C8 BB 62 C3','AF 53 A6 70 D7 8C 0D FF D6'])
        reader.addResponse('AF E0 06 16 66 87 04 D5 54 9C 8D 6A 13 A0 F8 FC ED',['00 1D 9D 29 54 69 7D E7 60'])
        #Change Key
        reader.addResponse('C4 00 BE DE 0F C6 ED 34 7D CF 0D 51 C7 17 DF 75 D9 7D 2C 5A 2B A6 CA C7 47 9D',['00'])
        #Auth 2
        reader.addResponse('AF 70 F3 49 74 0C 94 5D AE 15 9B A9 FE DB CC 46 1A',['00 B8 FD 7F E5 6B 24 1F C4'])
        #Change Key 2
        reader.addResponse('C4 00 94 E4 F7 09 DC 2A 2B 07 55 26 10 A1 96 6E 5C 49 EC 90 F6 16 ED EC A5 5B',['00'])
        #Auth 3
        reader.addResponse('AF 93 7E 6B 18 54 A6 D9 2E 0F D9 75 D9 90 90 01 E8',['00 E0 55 D1 1D D9 53 50 60'])
        #Get key version
        reader.addResponse('64 00',['00 10 33 45 AA 95 F2 D9 56 CF'])
        #Change Key 3
        reader.addResponse('C4 00 FC 9E 20 FD 77 19 1E 2A AB 0C FD 53 D9 99 99 84 BC 59 E8 86 BF EB 42 D0',['00'])
        #Auth4
        reader.addResponse('AF B3 08 40 8B 57 5A 20 25 25 3D 49 D6 93 CC C2 9C',['00 52 5B B0 1E 5B 70 B7 94'])
        #change Key other numeber(1)
        reader.addResponse('C4 01 4E B6 69 E4 8D CA 58 47 49 54 2E 1B E8 9C B4 C7 84 5A 38 C5 7D 19 DE 59',['00 2E AD 04 DC F1 21 E0 FE'])
        #change key 1 second
        reader.addResponse('C4 01 FA 7B EF A6 78 2C 93 E8 D6 9C F7 35 2C FD 33 DF 5B C8 AC 4F BA 49 06 FC',['00 CB 0A 50 64 05 51 28 93'])

        desfire = DESFire(reader)
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



def AuthTest_AES():
        print('AuthTest_AES')

        reader=DummyPCSCDevice()
        reader.addResponse('45', ['00 0F 81'])
        reader.addResponse('AA 00',[' AF B9 69 FD FE 56 FD 91 FC 9D E6 F6 F2 13 B8 FD 1E'])
        reader.addResponse('AF 36 AA D7 DF 6E 43 6B A0 8D 18 61 38 30 A7 0D 5A D4 3E 3D 3F 4A 8D 47 54 1E EE 62 3A 93 4E 47 74',['00 80 0D B6 80 BC 14 6B D1 21 D6 57 8F 2D 2E 20 59'])
        desfire = DESFire(reader)
        key_setting=desfire.getKeySetting()
        key_setting.setKey('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')
        desfire.authenticate(0,key_setting,'F4 4B 26 F5 68 6F 3A 39 1C D3 8E BD 10 77 22 81')
        print('[+] Test Des')


def File():
        reader=DummyPCSCDevice()
        reader.addResponse('45', ['00 0F 81'])
        reader.addResponse('AA 00',['AF B3 51 CB 24 65 D4 F3 3A C6 27 FD 6E 87 A1 68 F2'])
        reader.addResponse('AF 04 4B 6C AC 34 3A 08 65 89 51 49 64 9C A8 DD E1 F5 AC 4E C6 7B D2 08 90 0A F0 2F 04 9E 05 F0 B0',['00 A2 EE 14 4B 10 12 FB EB 7B 2F 11 13 2D 95 A4 54'])
        #Create STdDataFile
        reader.addResponse('CD 05 00 11 00 50 00 00',['00 A7 53 16 AD 15 96 B9 53'])
        #Get File Id
        reader.addResponse('6F',['00 05 2D 5F F6 7F FE C9 D2 D3'])
        #Get File Setting
        reader.addResponse('F5 05',['00 00 00 11 00 50 00 00 2A AC 75 17 02 4E 09 DC'])
        #Write File
        reader.addResponse('3D 05 00 00 00 34 00 00 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33',['00 76 5C 9D AA 50 EC B6 2F'])
        reader.addResponse('3D 05 34 00 00 1C 00 00 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F 40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F',['00 3E 0A ED 98 6B 8B 0F 37'])
        #Read File
        reader.addResponse('BD 05 00 00 00 30 00 00',['00 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 4C 65 F1 F8 42 26 2B AC'])
        reader.addResponse('BD 05 30 00 00 20 00 00',['00 30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F 40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F F0 22 05 CF 91 3C 03 C9'])
        reader.addResponse('DF 05',['00 1B EF 0D 32 B6 D1 D7 F9'])

        desfire = DESFire(reader)
        key_setting=desfire.getKeySetting()
        key_setting.setKey('10 18 20 28 30 38 40 48 50 58 60 68 70 78 80 88')
        desfire.authenticate(0,key_setting,'40 E7 D2 71 74 CB A6 75 E8 EF BA B9 9C 53 0E 3D')
        filePerm=DESFireFilePermissions()
        filePerm.unpack('11')
        desfire.createStdDataFile(5,filePerm,80)
        desfire.getFileIDs()
        desfire.getFileSettings(5)
        desfire.writeFileData(5,0,80,'00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F 40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F')
        desfire.readFileData(5,0,80)
        desfire.deleteFile(5)

if __name__ == '__main__':
        logging.basicConfig(level=logging.DEBUG)
        logger = logging.getLogger(__name__)

        testCase = 'offline'

        if testCase == 'offline':
                """
                ChangeKeyTest_2DES()
                """           
                File()
                AuthTest_AES()
                Test_DES()
                Test_2k3DES()
