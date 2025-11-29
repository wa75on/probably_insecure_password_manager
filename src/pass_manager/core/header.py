from collections import namedtuple

class HeaderError(Exception):
    def __init__(self, message: str):
        self.message = message

HEADER_VERSION = 1
MAGIC_NUMBER = ("SECVLT").encode().hex()
ENCODING = "utf-8"
HEADER = namedtuple('HEADER', 
                    [
                        'magic_number', 'version', 'owner', 'kek_kdf_id', 'kek_kdf_params', 
                        'mk_wrap_id', 'body_enc_id', 'ek_kdf_id', 'ek_enc_id',
                        'header_tag', 'wmk_nonce', 'wrapped_mk', 'body_tag', 'body_nonce'
                 ])
HEADER_SIZE = HEADER(
    magic_number=6,
    version=1,
    owner=1,
    kek_kdf_id=1,
    kek_kdf_params=1,
    mk_wrap_id=1,
    body_enc_id=1,
    ek_kdf_id=1,
    ek_enc_id=1,
    header_tag=1,
    wmk_nonce=1,
    wrapped_mk=1,
    body_tag=1,
    body_nonce=1
)
KDF = {
    0:"Argon2id"
    }
ENC = {
    0:"AES-256-GCM"
}

def parse_fixed(pointer: int, data: bytes, size: int) -> tuple[bytes, int]:
    res = data[pointer: pointer + size]
    pointer += size
    return res, pointer

def parse_var(pointer: int, data: bytes) -> tuple[bytes, int]:
    next_field_size = data[pointer]
    pointer += 1
    res = data[pointer: pointer + next_field_size]
    pointer += next_field_size
    return res, pointer

class Header:
    def __init__(self, magic_number: str, version: int, owner:str, kek_kdf_id: int, kek_kdf_params: str,
                 mk_wrap_id: int, ek_kdf_id: int, ek_enc_id: int, body_enc_id: int, header_tag: bytes,
                 wmk_nonce: bytes, wrapped_mk: bytes, body_tag: bytes, body_nonce: bytes):
        self.header_fields = HEADER(
            magic_number= magic_number,
            version = version,
            owner=owner,
            kek_kdf_id = kek_kdf_id,
            kek_kdf_params = kek_kdf_params,
            mk_wrap_id = mk_wrap_id,
            body_enc_id = body_enc_id,
            ek_kdf_id = ek_kdf_id,
            ek_enc_id=ek_enc_id,
            header_tag = header_tag,
            wmk_nonce=wmk_nonce,
            wrapped_mk = wrapped_mk,
            body_tag = body_tag,
            body_nonce=body_nonce
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> tuple["Header", int]:
        """Create a Header object from bytes."""
        fields = {}
        array_pointer: int = 0
        fields["magic_number"], array_pointer = parse_fixed(array_pointer, data, HEADER_SIZE.magic_number)
        fields["version"], array_pointer = parse_fixed(array_pointer, data, HEADER_SIZE.version)
        fields["owner"], array_pointer = parse_var(array_pointer, data)
        fields["kek_kdf_id"], array_pointer = parse_fixed(array_pointer, data, HEADER_SIZE.kek_kdf_id)
        fields["kek_kdf_params"], array_pointer = parse_var(array_pointer, data)
        fields["mk_wrap_id"], array_pointer = parse_fixed(array_pointer, data, HEADER_SIZE.mk_wrap_id)
        fields["body_enc_id"], array_pointer = parse_fixed(array_pointer, data, HEADER_SIZE.body_enc_id)
        fields["ek_kdf_id"], array_pointer = parse_fixed(array_pointer, data, HEADER_SIZE.ek_kdf_id)
        fields["ek_end_id"], array_pointer = parse_fixed(array_pointer, data, HEADER_SIZE.ek_enc_id)
        fields["header_tag"], array_pointer = parse_var(array_pointer, data)
        fields["wmk_nonce"], array_pointer = parse_var(array_pointer, data)
        fields["body_tag"], array_pointer = parse_var(array_pointer, data)
        fields["body_nonce"], array_pointer = parse_var(array_pointer, data)
        return cls(**fields), array_pointer
    
    @classmethod
    def create_initial(cls, username:str, kek_kdf_params: str,
                       header_tag: bytes = bytes(), wmk_nonce: bytes = bytes(),
                       wrapped_mk: bytes = bytes(), body_tag: bytes = bytes(),
                       body_nonce: bytes = bytes()) -> "Header":
        fields = {
            "magic_number":MAGIC_NUMBER,
            "version":HEADER_VERSION,
            "owner":username,
            "kek_kdf_id":0,
            "kek_kdf_params":kek_kdf_params,
            "mk_wrap_id":0,
            "body_enc_id":0,
            "ek_kdf_id":0,
            "ek_enc_id":0,
            "header_tag":header_tag,
            "wmk_nonce": wmk_nonce,
            "wrapped_mk":wrapped_mk,
            "body_tag":body_tag,
            "body_nonce":body_nonce
        }
        return cls(**fields)
    
    def to_bytes(self) -> bytes:
        data = bytearray()
        data.extend(self.header_fields.magic_number.encode(ENCODING))
        data.extend(self.header_fields.version.to_bytes(length=HEADER_SIZE.version))
        data.extend(len(self.header_fields.owner).to_bytes(length=HEADER_SIZE.owner))
        data.extend(self.header_fields.owner.encode(ENCODING))
        data.extend(self.header_fields.kek_kdf_id.to_bytes(length=HEADER_SIZE.kek_kdf_id))
        data.extend(len(self.header_fields.kek_kdf_params.encode(ENCODING)).to_bytes(length=HEADER_SIZE.kek_kdf_params))
        data.extend(self.header_fields.kek_kdf_params.encode(ENCODING))
        data.extend(self.header_fields.mk_wrap_id.to_bytes(length=HEADER_SIZE.mk_wrap_id))
        data.extend(self.header_fields.body_enc_id.to_bytes(length=HEADER_SIZE.body_enc_id))
        data.extend(self.header_fields.ek_kdf_id.to_bytes(length=HEADER_SIZE.ek_kdf_id))
        data.extend(self.header_fields.ek_enc_id.to_bytes(length=HEADER_SIZE.ek_enc_id))
        data.extend(len(self.header_fields.header_tag).to_bytes(length=HEADER_SIZE.header_tag))
        data.extend(self.header_fields.header_tag)
        data.extend(len(self.header_fields.wmk_nonce).to_bytes(length=HEADER_SIZE.wmk_nonce))
        data.extend(self.header_fields.wmk_nonce)
        data.extend(len(self.header_fields.wrapped_mk).to_bytes(length=HEADER_SIZE.wrapped_mk))
        data.extend(self.header_fields.wrapped_mk)
        data.extend(len(self.header_fields.body_tag).to_bytes(length=HEADER_SIZE.body_tag))
        data.extend(self.header_fields.body_tag)
        data.extend(len(self.header_fields.body_nonce).to_bytes(length=HEADER_SIZE.body_nonce))
        data.extend(self.header_fields.body_nonce)
        return bytes(data)
    
    def get_header_ad(self) -> bytes:
        data = bytearray()
        data.extend(self.header_fields.magic_number.encode(ENCODING))
        data.extend(self.header_fields.version.to_bytes(length=HEADER_SIZE.version))
        data.extend(len(self.header_fields.owner).to_bytes(length=HEADER_SIZE.owner))
        data.extend(self.header_fields.owner.encode(ENCODING))
        data.extend(self.header_fields.kek_kdf_id.to_bytes(length=HEADER_SIZE.kek_kdf_id))
        data.extend(len(self.header_fields.kek_kdf_params.encode(ENCODING)).to_bytes(length=HEADER_SIZE.kek_kdf_params))
        data.extend(self.header_fields.kek_kdf_params.encode(ENCODING))
        data.extend(self.header_fields.mk_wrap_id.to_bytes(length=HEADER_SIZE.mk_wrap_id))
        data.extend(self.header_fields.body_enc_id.to_bytes(length=HEADER_SIZE.body_enc_id))
        data.extend(self.header_fields.ek_kdf_id.to_bytes(length=HEADER_SIZE.ek_kdf_id))
        data.extend(self.header_fields.ek_enc_id.to_bytes(length=HEADER_SIZE.ek_enc_id))
        return bytes(data) 
    
    def update_fields(self, **kwargs):
        self.header_fields._replace(**kwargs)
    
    def verify_header_structure(self, username: str) -> bool:
        if self.header_fields.magic_number != MAGIC_NUMBER: return False
        if self.header_fields.version != HEADER_VERSION: return False
        if self.header_fields.owner != username: return False
        return True
        


