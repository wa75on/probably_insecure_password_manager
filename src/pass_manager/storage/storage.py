import os

VAULT_PATH = "vaults/"
CURRENT_PATH = os.getcwd()
FILE_EXT = '.vlt'

class StorageException(Exception):
    def __init__(self, message):
        self.message = message

def dir_exists() -> bool:
    if not os.path.exists(f"{CURRENT_PATH}/{VAULT_PATH}"):
        return False
    return True

def vault_exists(username: str) -> bool:
    path = f"{CURRENT_PATH}/{VAULT_PATH}{username}{FILE_EXT}"
    if not os.path.exists(path):
        return False
    return True

def read_vault(username: str) -> bytes:
    if not vault_exists(username): 
        raise StorageException("User vault not found!")
    path = f"{VAULT_PATH}{username}{FILE_EXT}"
    with open(path, "rb") as file:
        data = file.read()
    return data 

def write_vault(username: str, data: bytes):
    path = f"{VAULT_PATH}{username}{FILE_EXT}"
    if not dir_exists():
        os.mkdir(f"{VAULT_PATH}")
    with open(path, "wb") as file:
        file.write(data)
    
