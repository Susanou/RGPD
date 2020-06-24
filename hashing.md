# Security RGPD

## Pratiques de code securisé

## Methodes de cryptage de données

La méthode la plus courante pour crypter les données sensibles est le hashage.
Cependant, le hashage seul est vulnérable face à des attaques utilisant des
`rainbow table` (des tables de hash déjà créer avec les différents algorithmes).
Pour parer à ce genre d'attaques, l'utilisation de hash salés est préférables.

Cet algorithme consiste à hasher les données sensibles avec du "sel" qui correspond à une
ligne aléatoire de caractères. Pour avoir un sel robuste, il faut utiliser un **CSPRNG**
(Cryptographicaly Secure Pseudo Random Number Generator).

| Plateforme       | CSPRNG                                                |
| ---------------- | ----------------------------------------------------- |
| PHP              | mcrypt_create_iv, openssl_random_pseudo_bytes         |
| Java             | java.security.SecureRandom                            |
| Dot NET (C#, VB) | System.Security.Cryptography.RNGCryptoServiceProvider |
| Ruby             | SecureRandom                                          |
| Python           | os.random                                             |
| Linux (GNU/Unix) | lire depuis /dev/random ou /dev/urandom               |
| Javascript       | Crypto.getRandomValues()                              |

Cette liste est sujette à changement. Bien vérifié que ces CSPRNG sont encore utilisables (Liste à dater du 24/06/2020)

### Exemple en Python

```Python
import binascii, os, hashlib

def hash_password(password):
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('utf-8')
    pwdhash = hashlib.scrypt(bytes(password, 'utf-8'), salt=bytes(salt), n=16384, r=8, p=1)

    pwdhash = binascii.hexlify(pwdhash)
    return (salt + pwdhash).decode('ascii')

def verify_password(stored_password, provided_password):
    salt = stored_password[:64]
    stored_password = stored_password[64:]

    pwdhash = hashlib.scrypt(bytes(provided_password, 'utf-8'), salt=bytes(salt, 'utf-8'), n=16384, r=8, p=1)
    pwdhash = binascii.hexlify(pwdhash).decode('ascii')

    return pwdhash == stored_password
```
