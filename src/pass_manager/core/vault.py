from pass_manager.core.header import Header
from collections import namedtuple
import sqlite3

ENTRY = namedtuple('ENTRY', ['id', 'title', 'account', 'note', 'enc_pass', 'salt'])

def construct_entry(title: str, enc_pass: bytes, salt: bytes,
                    id: int = -1, account: str = "", note: str = "") -> ENTRY:
    return ENTRY(**{
        'id':id,
        'title':title,
        'account':account,
        'note':note,
        'enc_pass':enc_pass,
        'salt':salt
    })

class Vault:
    def __init__(self, header: Header, db: sqlite3.Connection):
        self.header = header
        self.db = db

    @classmethod
    def create_default(cls, header: Header):
        db = sqlite3.connect(":memory:")
        query_script = """
        PRAGMA foreign_key = ON;

        CREATE TABLE titles (
            id INTEGER PRIMARY KEY NOT NULL,
            title TEXT NOT NULL
        );

        CREATE TABLE entries (
            id INTEGER PRIMARY KEY NOT NULL,
            title_id INTEGER NOT NULL,
            account TEXT,
            note TEXT,
            password BLOB NOT NULL,
            salt BLOB NOT NULL,
            FOREIGN KEY (title_id) REFERENCES titles(id)
        );
        """
        db.executescript(query_script)
        db.commit()
        fields = {
            "header": header,
            "db":db
        } 
        return cls(**fields)
    
    def to_bytes(self) -> tuple[bytearray, int]:
        data = bytearray() 
        data.extend(self.header.to_bytes())
        head_len = len(data)
        data.extend(self.db.serialize())
        #self.db.close()
        return data, head_len
    
    @classmethod
    def from_bytes(cls, header: Header, data: bytes):
        db = sqlite3.connect(":memory:")
        db.deserialize(data)
        return cls(header, db)

# Assumed sanitized & validated input
    def add_entry(self, entry: ENTRY) -> ENTRY:
        insert_title_query = """
        INSERT INTO titles (title) VALUES (?);
        """
        insert_entry_query = """
        INSERT INTO entries (title_id, account, note, password, salt)
        VALUES (?, ?, ?, ?, ?);
        """
        self.db.execute(insert_title_query, (entry.title,))
        title_id = self.db.execute("SELECT id FROM titles WHERE title = ?", (entry.title,)).fetchone()[0]
        id = self.db.execute(insert_entry_query, (title_id, entry.account, entry.note, entry.enc_pass, entry.salt)).lastrowid
        
        added_entry = entry._replace(id=id)
        self.db.commit()

        return  added_entry

    def fetch_entry(self, entry_id: str) -> ENTRY:
        db_entry = self.db.execute("SELECT * FROM entries WHERE id = ?", (entry_id,)).fetchone()
        title = self.db.execute("SELECT title FROM titles WHERE id = ?", (db_entry[1],)).fetchone()[0]

        return construct_entry(title, id=db_entry[0], account=db_entry[2], note=db_entry[3],
                               enc_pass=db_entry[4], salt=db_entry[5]) 
        
    def update_entry(self):
        pass
    def delete_entry(self):
        pass