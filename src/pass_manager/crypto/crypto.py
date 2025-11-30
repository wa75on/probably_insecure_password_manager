from argon2 import PasswordHasher, low_level, Type, profiles, extract_parameters
import base64
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA512
from collections import namedtuple
from pass_manager.core.header import KDF
from pass_manager.core.header import ENC

KDF_PARAMS = namedtuple('KDF_PARAMS', ['hash', 'salt'])
EMPTY_KDF_PARAMS = KDF_PARAMS(bytes(), bytes())
SYMM_PARAMS = namedtuple('ENC_PARAMS', ['assoc_data', 'nonce', 'tag'])
EMPTY_SYMM_PARAMS = SYMM_PARAMS(bytes(), bytes(), bytes())

def make_kdf_params(**kwargs) -> KDF_PARAMS:
    return EMPTY_KDF_PARAMS._replace(**kwargs)

def make_symm_params(**kwargs) -> SYMM_PARAMS:
    return EMPTY_SYMM_PARAMS._replace(**kwargs)


class CrytpoError(Exception):
    def __init__(self, message):
        self.message = message

def gen_kdf_key(input: bytes, kdf_id: int, params: KDF_PARAMS) -> tuple[bytes, bytes]:
    if kdf_id not in KDF: raise CrytpoError("Unsupported algorithm!")
    match(KDF[kdf_id]):
        case "Argon2id":
            if not params.hash:
                ph = PasswordHasher()
                key_salt = get_random_bytes(ph.hash_len)
            else:
                ph = PasswordHasher.from_parameters(extract_parameters(params.hash.decode()))
                salt_b64 = params.hash.decode().split("$")[4]
                key_salt = base64.b64decode(salt_b64 + '==')
            
            key = low_level.hash_secret_raw(
                secret=input,
                salt=key_salt,
                time_cost=ph.time_cost, memory_cost=ph.memory_cost, parallelism=ph.parallelism,
                hash_len=ph.hash_len, type=low_level.Type.ID
            )
            pass_hash = ph.hash(input, salt=key_salt)
            return  key, pass_hash.encode()
        case "HKDF":
            if not params.salt:
                key_salt = get_random_bytes(16)
            else:
                key_salt = params.salt
            key = HKDF(input, 32, key_salt, SHA512, num_keys=1)
            return key, key_salt #type: ignore
        case _:
            raise CrytpoError("Unsupported algorithm!")
        
def verify_kek(master_password:str, kek_hash: bytes) -> bool:
    ph = PasswordHasher.from_parameters(extract_parameters(kek_hash.decode()))
    try:
        ph.verify(kek_hash, master_password)
        return True
    except Exception:
        return False


def gen_random_key(enc_id: int) -> bytes:
    if enc_id not in ENC: raise CrytpoError("Unsupported algorithm!")
    match enc_id:
        case 0:
            return get_random_bytes(32)
        case _:
            raise CrytpoError("Unsupported algorithm!")


def encrypt(key: bytes, data: bytes, enc_id: int, symm_params: SYMM_PARAMS) -> tuple[bytes, bytes, bytes]:
    if enc_id not in ENC: raise CrytpoError("Unsupported algorithm!")
    match ENC[enc_id]:
        case "AES-256-GCM":
            aes_256_gcm = AES.new(key, AES.MODE_GCM)
            aes_256_gcm.update(symm_params.assoc_data)
            ciphertext, tag = aes_256_gcm.encrypt_and_digest(data)
            return ciphertext, aes_256_gcm.nonce, tag
        case "AES-256-CTR":
            aes_256_ctr = AES.new(key, AES.MODE_CTR, nonce=symm_params.nonce)
            ciphertext = aes_256_ctr.encrypt(data)
            return ciphertext, bytes(), bytes()
        case _:
            raise CrytpoError("Unsupported algorithm!")

def decrypt(key: bytes, data: bytes, enc_id: int, symm_params: SYMM_PARAMS = EMPTY_SYMM_PARAMS) -> bytes:
    if enc_id not in ENC: raise CrytpoError("Unsupported algorithm!")
    match ENC[enc_id]:
        case "AES-256-GCM":
            aes_256_gcm = AES.new(key, AES.MODE_GCM, nonce=symm_params.nonce)
            aes_256_gcm.update(symm_params.assoc_data)
            plaintext = aes_256_gcm.decrypt_and_verify(data, symm_params.tag)
            return plaintext
        case "AES-256-CTR":
            aes_256_ctr = AES.new(key, AES.MODE_CTR, nonce=symm_params.nonce)
            plaintext = aes_256_ctr.decrypt(data)
            return plaintext
        case _:
            raise CrytpoError("Unsupported algorithm!")
    