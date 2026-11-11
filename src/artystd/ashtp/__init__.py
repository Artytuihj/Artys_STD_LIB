import tempfile
from pathlib import Path

from .ASHTPClient import ASHTPClient
from .ASHTPServer import ASHTPServer
from .IKeyAuthority import IKeyAuthority
PROTOCOL_VERSION = "ashtp/1.3"
SUPPORTED_SERVER_VERSIONS = [PROTOCOL_VERSION]

TMP = Path(tempfile.gettempdir()) / "ashtp" / "S"
TMP.mkdir(parents=True, exist_ok=True)

idr = "no" #tf