import tempfile
from pathlib import Path


PROTOCOL_VERSION = "ashtp/1.3"
SUPPORTED_SERVER_VERSIONS = [PROTOCOL_VERSION] # btw ts will never support more than one

TMP = Path(tempfile.gettempdir()) / "ashtp" / "S"
TMP.mkdir(parents=True, exist_ok=True)
EXTRACT_RESULTS = Path(tempfile.gettempdir()) / "ashtp" / "S" / "extracted"
EXTRACT_RESULTS.mkdir(parents=True, exist_ok=True)

CHUNK_SIZE_LIMIT = 258 * 1024 # 258 KiB
FILE_PACKAGE_SIZE_LIMIT = 16 * 1024 * 1024 # 16 MiB
JSON_PACKAGE_SIZE_LIMIT = 1024 * 1024 # 1 MiB
FILE_SIZE_LIMIT = 5 * 1024 * 1024 * 1024 # 5 GiB
HANDSHAKE_PASS_PHRASE = b"lets go"


idr = "yes" #the fuck is this... btw dont touch it

from .ASHTPClient import ASHTPClient
from .ASHTPServer import ASHTPServer
from .IKeyAuthority import IKeyAuthority
