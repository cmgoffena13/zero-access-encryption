# Zero Access Encryption

A proof of concept for zero access encryption. Build an app that puts User's privacy first.

## Concepts

### SRP (Secure Remote Passowrd)
Zero-access encryption depends upon a user's password not being stored on the server. This is achieved through a mathematical equation. Essentially the server and the client are given different variables of the same equation and asked to solve for it, coming up with a shared key which confirms authentication. This allows the browser to keep your password locally, without the server knowing about it.

For technical info: https://datatracker.ietf.org/doc/html/rfc5054

### An Encrypted Encryption Key
With your password truly private, it can then be used to generate a private encryption key. This key is used to encrypt an encryption key that is stored on the server. This is VERY important, because if the encryption key was not encrypted itself, anyone with access to the data could use the encryption key to decrypt your data. The only way to encrypt/decrypt the data is by having your password, which decrypts the encryption key itself.