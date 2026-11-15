import tempfile
from pathlib import Path
from enum import StrEnum

from .ASHTPClient import ASHTPClient
from .ASHTPServer import ASHTPServer
from .IKeyAuthority import IKeyAuthority

PROTOCOL_VERSION = "ashtp/1.3"
SUPPORTED_SERVER_VERSIONS = [PROTOCOL_VERSION]

TMP = Path(tempfile.gettempdir()) / "ashtp" / "S"
TMP.mkdir(parents=True, exist_ok=True)

class ContentType(StrEnum):
    SMALL_FILE = "small_file"
    FILE_STREAM = "file_stream"
    BYTE_STREAM = "byte_stream"
    JSON = "json"

idr = "no" #the fuck is this