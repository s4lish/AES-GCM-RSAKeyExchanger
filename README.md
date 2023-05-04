# AES-GCM-RSAKeyExchanger
This App write with .Net 7 minimal api to Encrypt and Decrypt End-To-End apps with AES-GCM algorithm.
1-First create RSA Public and private key and send Public key to client and save private key in Database.
2-Client Encrypt Data by AES-GCM algorithm and then Encrypt its Key by Public Key that Server sent to it.
3-Client Send Encrypted AES_GCM data and Encrypted Key to Server
4-Server Recieve 2 Encrpted Data and key and First Decrypt Key By Private Key that before Created
5-Now Decrypt Main Data by key Decypted with private key.
6-Access Plain Text is Ok.

if you want to Encrypt in 2 way that Client need to create RSA public and PRivate Key too and send Public Key to Server And Server Encrypt AES_GCM key by clients public Key.
