import tempfile
from pathlib import Path

from .ASHTPClient import ASHTPClient
from .ASHTPServer import ASHTPServer
from .IKeyAuthority import IKeyAuthority

PROTOCOL_VERSION = "ashtp/1.3"
SUPPORTED_SERVER_VERSIONS = [PROTOCOL_VERSION]

TMP = Path(tempfile.gettempdir()) / "ashtp" / "S"
TMP.mkdir(parents=True, exist_ok=True)
#TODO put most of theese values into a generated config on import,
# make it so the values are accsesible to the module and make them be loaded into memory on import
chunkSizeLimit = 258 * 1024 # 258 KiB
filePackageSizeLimit = 16 * 1024 * 1024 # 16 MiB
jsonPackageSizeLimit = 1024 * 1024 # 1 MiB
fileSizeLimit = 5 * 1024 * 1024 * 1024 # 5 GiB


idr = "yes" #the fuck is this... btw dont touch it