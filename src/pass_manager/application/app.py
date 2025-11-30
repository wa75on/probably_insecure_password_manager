from pass_manager.core.vault import Vault
from pass_manager.core.header import Header
from pass_manager.core.header import ENCODING
from pass_manager.crypto.crypto import *
from pass_manager.storage.storage import *

class ApplicationException(Exception):
    def __init__(self, message):
        self.message = message




def create_vault(username: str, master_pasword: str) -> Vault:
    if vault_exists(username):
        raise ApplicationException("User's vault already exists!")
    kek, params = gen_kdf_key(master_pasword.encode(), 0, make_kdf_params())
    mk = gen_random_key(0)
    header = Header.create_initial(username, params)
    wrapped_mk, nonce, header_tag = encrypt(kek, mk, header.header_fields.mk_wrap_id, make_symm_params(**{'assoc_data':header.get_header_ad()}))
    params = {
        "owner":username,
        "header_tag":header_tag,
        "wmk_nonce":nonce,
        "wrapped_mk":wrapped_mk
    }
    header.update_fields(**params)
    vault = Vault.create_default(header)
    vault_bytes, head_len = vault.to_bytes()
    enc_body, body_nonce, body_tag = encrypt(mk, vault_bytes[head_len:], vault.header.header_fields.body_enc_id, make_symm_params(**{
        'assoc_data':vault.header.header_fields.header_tag
        }))
    updated_fields = {
        "body_tag": body_tag,
        "body_nonce": body_nonce
    }
    vault.header.update_fields(**updated_fields)
    vault_bytes, head_len = vault.to_bytes()
    vault_bytes = vault_bytes[:head_len] + enc_body
    write_vault(username, vault_bytes)
    return vault

def load_vault(username: str, master_password: str) -> Vault:
    locked_vault: bytes = bytes()
    try:
        locked_vault= read_vault(username)
        header, data_pointer = Header.from_bytes(locked_vault)
        if not (header.verify_header_structure(username) and verify_kek(master_password, header.header_fields.kek_kdf_params)):
            raise ApplicationException("Could not decrypt vault!")
        kek, params = gen_kdf_key(master_password.encode(), header.header_fields.kek_kdf_id, make_kdf_params(**{'hash':header.header_fields.kek_kdf_params}))
        mk = decrypt(kek, header.header_fields.wrapped_mk, header.header_fields.mk_wrap_id,
                     make_symm_params(**{
                         'assoc_data':header.get_header_ad(),
                         'nonce':header.header_fields.wmk_nonce,
                         'tag':header.header_fields.header_tag
                     }))
        unlocked_body = decrypt(mk, locked_vault[data_pointer:], header.header_fields.body_enc_id,
                                make_symm_params(**{
            'assoc_data': header.header_fields.header_tag,
            'nonce':header.header_fields.body_nonce,
            'tag':header.header_fields.body_tag
            }))
        return Vault.from_bytes(header, unlocked_body)
    except Exception:
        raise ApplicationException("Could not decrypt vault!")

def ek():
        ek, entry_secret = gen_kdf_key(mk, vault.header.header_fields.ek_kdf_id, make_kdf_params())
        if pepper:
            entry_secret = bytes(entry_secret + pepper.encode(ENCODING))
        enc_pass = encrypt(ek, password.encode(), vault.header.header_fields.ek_enc_id, make_symm_params(**{
            'nonce':entry_secret
        }))
