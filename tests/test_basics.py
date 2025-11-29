import unittest
from pass_manager.application.app import *

user = "testuser"
password = "123"

class TestInitialVaultOperatoins(unittest.TestCase):

    def vault_creation(self): 
        vault = create_vault(user, password)
        self.assertTrue(vault_exists(user))

    def vault_loading(self):
        vault = load_vault(user, password)
        self.assertTrue(vault.header.header_fields.owner == user)