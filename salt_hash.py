import binascii
import os
import hashlib


def hash_password(password):
    """Function that hashes a password with a random salt

    Args:
        password : String that is the password

    Returns:
        str : returns a hex string of the hash
    """
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('utf-8')
    pwdhash = hashlib.scrypt(
        bytes(password, 'utf-8'), salt=bytes(salt), n=16384, r=8, p=1)

    pwdhash = binascii.hexlify(pwdhash)
    return (salt + pwdhash).decode('ascii')


def verify_password(stored_password, provided_password):
    """Function to check a password against a stored salted hash

    Args:
        stored_password (str): salted hash of the stored passord
        provided_password (str): string that is the password

    Returns:
        bool : Returns Trues if the hashes match, False otherwise
    """
    salt = stored_password[:64]
    stored_password = stored_password[64:]

    pwdhash = hashlib.scrypt(bytes(provided_password, 'utf-8'),
                             salt=bytes(salt, 'utf-8'), n=16384, r=8, p=1)
    pwdhash = binascii.hexlify(pwdhash).decode('ascii')

    return pwdhash == stored_password


password = hash_password('ThisIsAPassWord')
print(password)

print(verify_password(password, 'ThisIsAPassWord'))
print(verify_password(password, 'test'))
