DESFire
=========

Desfire card library for Python

Project still ongoing, use it with caution!

Features
========

-   Compatible with all readers supported by pySCARD

-   Pure python implementation

-   One of the few DESFire libraries that supports ALL (DES,2DES,3DES,AES)
    authentication types

-   Enumeration of the card gives an overlook on how the card is structured

-   Functions implement:

    -   authenticate
    -   communicate
    -   getApplicationIDs
    -   getKeySetting
    -   getCardVersion
    -   formatCard
    -   selectApplication
    -   createApplication
    -   deleteApplication
    -   getFileIDs
    -   getFileSettings
    -   readFileData
    -   writeFileData
    -   deleteFile
    -   createStdDataFile
    -   getKeyVersion
    -   changeKeySettings
    -   changeKey
    -   createKeySetting

Issues
======

-   Can’t read data from certain file types

-   Some commands are missing (since there is no full documentation available)

Author
======

Patrick Weber

Credits
=======

The codebase of this project was based on two major projects:

Elmue 
------

>   who created a completely working DESFireEV1 library. (this module is based
>   90% of his work!)

>   URL:
>   https://www.codeproject.com/Articles/1096861/DIY-electronic-RFID-Door-Lock-with-Battery-Backup


skelsec
-------

>   who try to implement the code from Elmue written in C to Python. (this module is based 9% of this work)

>   Url:
>   https://github.com/skelsec/pydesfire    

miohtama (https://twitter.com/moo9000)
--------------------------------------

>   who worte the original desfire module for python.

>   URL: <https://github.com/miohtama/desfire/>
