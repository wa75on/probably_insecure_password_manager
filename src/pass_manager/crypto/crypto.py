from argon2 import PasswordHasher, low_level, Type, profiles, extract_parameters
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from pass_manager.core.header import KDF
from pass_manager.core.header import ENC

class CrytpoError(Exception):
    def __init__(self, message):
        self.message = message

def gen_kek(master_password: str, kek_id: int, kek_kdf_params=None) -> tuple[bytes, str]:
    if kek_id not in KDF: raise CrytpoError("Unsupported algorithm!")
    kdf = KDF[kek_id] 
    match(kdf):
        case "Argon2id":
            if not kek_kdf_params:
                ph = PasswordHasher()
            else:
                ph = PasswordHasher.from_parameters(extract_parameters(kek_kdf_params))
            mk_salt = get_random_bytes(ph.hash_len)
            mk = low_level.hash_secret_raw(
                secret=master_password.encode(),
                salt=mk_salt,
                time_cost=ph.time_cost, memory_cost=ph.memory_cost, parallelism=ph.parallelism,
                hash_len=ph.hash_len, type=low_level.Type.ID
            )
            kek_params = ph.hash(master_password, salt=mk_salt)
            return  mk, kek_params
        case _:
            raise CrytpoError("Unsupported algorithm!")
        
def verify_kek(master_password:str, kek_hash: str) -> bool:
    ph = PasswordHasher.from_parameters(extract_parameters(kek_hash))
    try:
        ph.verify(kek_hash, master_password)
        return True
    except Exception:
        return False


def gen_mk(enc_id: int) -> bytes:
    if enc_id not in ENC: raise CrytpoError("Unsupported algorithm!")
    match enc_id:
        case 0:
            return get_random_bytes(32)
        case _:
            raise CrytpoError("Unsupported algorithm!")

def encrypt(key: bytes, data: bytes, enc_id: int, assoc_data: bytes, params=None) -> tuple[bytes, bytes, bytes]:
    if enc_id not in ENC: raise CrytpoError("Unsupported algorithm!")
    match enc_id:
        case 0:
            aes_256_gcm = AES.new(key, AES.MODE_GCM)
            aes_256_gcm.update(assoc_data)
            ciphertext, tag = aes_256_gcm.encrypt_and_digest(data)
            return ciphertext, aes_256_gcm.nonce, tag
        case _:
            raise CrytpoError("Unsupported algorithm!")

def decrypt(key: bytes, data: bytes, enc_id: int, assoc_data: bytes, nonce: bytes, tag: bytes) -> bytes:
    if enc_id not in ENC: raise CrytpoError("Unsupported algorithm!")
    match enc_id:
        case 0:
            aes_256_gcm = AES.new(key, AES.MODE_GCM, nonce=nonce)
            aes_256_gcm.update(assoc_data)
            plaintext = aes_256_gcm.decrypt_and_verify(data, tag)
            return plaintext
        case _:
            raise CrytpoError("Unsupported algorithm!")
    