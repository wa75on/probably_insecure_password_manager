import unittest
from pass_manager.application.app import *
from pass_manager.core import *
from pass_manager.core.vault import construct_entry
from pass_manager.storage.storage import delete_vault

user = "testuser"
password = "123"

class TestInitialVaultOperatoins(unittest.TestCase):

    def test_vault_creation(self): 
        delete_vault(user)
        vault = create_vault(user, password)
        self.assertTrue(vault_exists(user))

    def test_vault_loading(self):
        delete_vault(user)
        vault = create_vault(user, password)
        vault_load = load_vault(user, password)
        self.assertTrue(vault_load.header.header_fields.owner == user)
    
    def test_entry_creation(self):
        delete_vault(user)
        entry = {
            'title': "google.com",
            'enc_pass': bytes(6),
            'salt': bytes(7),
            'account':user,
            'note':"balls"
        }
        vault = create_vault(user, password)
        added = vault.add_entry(construct_entry(**entry))
        fetched = vault.fetch_entry(added.id)
        self.assertEqual(added, fetched)
        
if __name__ == "__main__":
    unittest.main()