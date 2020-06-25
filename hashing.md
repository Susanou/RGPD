# Security RGPD

## Pratiques de code securisé

[OWASP checklist des pratiques de codes](https://owasp.org/www-pdf-archive/OWASP_SCP_Quick_Reference_Guide_v1.pdf)

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

A dater du 24/06/2020 voici les algorithmes de hashage à utiliser de préférence:

- PBKDF2
- bcrypt
- scrypt

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

## Quelles données protéger?

Pour assurer la protection des données personelles, il faut dans un premier temps identifier quelles données sont classées en tant que données personelles.

- nom, prénom, pseudo, date de naissance
- photos, enregistrements vidéos/audio
- numéro de téléphone, adresse postale et e-mail
- adresse IP, identifiants de connection/cookies
- empreinte digitale/veineux/palmaire ou empreinte rétinienne
- numéro de sécurité sociale/identité4
- données d'usage/commentaires etc.

Les données ci-dessous ne peuvent-être récoltées que si l'utilisateur en a donnée son consentement écrit:

- vie ou orientation sexuelle
- origine raciale ou éthnique
- opinions politiques/religieux/philosophiques/syndicales
- santé de l'individu

Quel que soit la méthode employée, les données sont considérées comme protéger lorsqu'elles sont:

- **_Individualisation_**: Qu'il ne soit pas possible d'isoler une partie ou la totalité des enregistrements relatifs à un individu
- **_Corrélation_**: Qu'il ne soit pas possible de relier deux enregistrements relatifs à un individu ou à un groupe de personnes
- **_Inférance_**: Qu'il soit impossible de déduire la valeur d'un attribut depuis des informations intern ou externes au jeu de données

Pour les protéger, il existe 2 méthodes:

### Anonymisation des données

L'anonymisation consiste à rendre impossible toute identification d'un individu au sein d'un jeu de données. Le processus est donc irréversible. Cela permet de ne plus considérer les données comme données personelles et donc les RGPD ne sont plus applicables dessus.

En général ces techniques entrainent une perte de qualité du jeu de données ce qui rend impossible son utilisation en statistique ou autre usage.

Dans l'ensemble des techniques il y a:

- La randomisation
  - Ajout de "bruit"
  - Permuations
- Généralisation

### Pseudonymisation des données





**Il est important de rapeler qu'il n'existe aucune solution parfaite et donc qu'il fait adapter chaque solution à son besoin.**