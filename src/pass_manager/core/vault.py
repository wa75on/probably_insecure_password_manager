from pass_manager.core.header import Header
import sqlite3

class Vault:
    def __init__(self, header: Header, db: sqlite3.Connection):
        self.header = header
        self.db = db

    @classmethod
    def create_default(cls, header: Header):
        db = sqlite3.connect(":memory:")
        query_script = """
        PRAGMA foreign_key = ON;
        CREATE TABLE password (
            p_id INTEGER PRIMARY KEY NOT NULL,
            password BLOB NOT NULL,
            salt BLOB NOT NULL,
            pepper BLOB
        );

        CREATE TABLE entry(
            id INTEGER PRIMARY KEY NOT NULL,
            title TEXT NOT NULL,
            account TEXT,
            note TEXT,
            p_id INTEGER NOT NULL,
            FOREIGN KEY (p_id) REFERENCES password(p_id)
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

