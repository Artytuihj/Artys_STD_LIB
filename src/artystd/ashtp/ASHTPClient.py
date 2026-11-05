#std
import json
import secrets
import tempfile
import time
import zipfile
from email import generator
from pathlib import Path
import asyncio
import logging
import base64
import hashlib
from typing import Iterable, Iterator

#pypi
import requests
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidTag
from requests import Response

#in module
from src.artystd.ashtp import PROTOCOL_VERSION
from src.artystd.utilities.ArtysEventManager import ArtysEventManager

class HandshakeError(Exception):
    pass

class ParsingError(Exception):
    pass

class ReplayError(Exception):
    pass

class ASHTPGeneralException(Exception):
    pass


def _DeriveKeys(secret:bytes, transcrypt:bytes, length:int=64)-> tuple[bytes,bytes]:
    symKey = HKDF(algorithm=hashes.SHA256(), length=length, salt=None,
                  info=b"ashtp sym sesscion key" + transcrypt).derive(secret)
    return symKey[32:], symKey[:32]

def _aad(sid: bytes, method: str, endpoint: str, ref: int | None = None) -> bytes:
    if not endpoint.startswith("/"):
        endpoint = "/" + endpoint
    a = sid + method.upper().encode() + b" " + endpoint.encode()
    if ref is not None:
        a += b" " + ref.to_bytes(8, "little")   # fixed width at the end, so unambiguous
    return a

class Session():
    def __init__(self, send_key:bytes, recv_key:bytes):
        self.send = ChaCha20Poly1305(send_key)
        self.recv = ChaCha20Poly1305(recv_key)
        self.sendN = 0
        self.recvN = -1

    @staticmethod
    def _nonce(n: int) -> bytes:
        return b"\0" * 4 + n.to_bytes(8, "little") # generates a 12 byte number ( 0 0 0 0 )just filed with zeros (0 0 0 0 0 0 0 0) a simple counter little means less significant comes first

    def Encrypt(self, data:bytes, tag:bytes = b""):
        n = self.sendN # save the number used to build the nonce
        self.sendN += 1 # increment
        return n, self.send.encrypt(self._nonce(n), data, tag) # here we encrypt data with the send key and tag (ct stands for "cyphertext")

    def Decrypt(self, data:bytes,n ,tag:bytes = b""):
        if not ( self.recvN < n < 2**64): # make sure we are not being replayed and below the limit
            raise ReplayError("The message is being replayed or key is stale. rekey! ")
        dr = self.recv.decrypt(self._nonce(n), data, tag) # do the same as encrypt but backwards ("dr" stands for decryption result)
        self.recvN = n
        return dr

class ASHTPClient:
    def __init__(self,
                 server_public_encryption_const: bytes,
                 server_ip: str,
                 server_port: int | None = None,
                 url_prefix: str = "http://",
                 url_health: str = "/health",
                 url_handshake: str = "/privet",
                 url_auth: str = "/auth",
                 timeout_time: int = 5,
                 max_reties: int = 5,
                 health_poll_rate: int = 5):

        # ----------------------------------------------
        # |||  Arty's Secure HTTP Transport Protocol |||
        # ----------------------------------------------

        # ---------- protocol ----------
        self._version: str = PROTOCOL_VERSION

        # ---------- server address ----------
        self.serverIp: str = server_ip
        self.serverPort: int | None = server_port
        self.serverPrefix: str = url_prefix
        self.serverHealthEndpoint: str = url_health
        self.serverHandshakeEndpoint: str = url_handshake
        self.serverAuthEndpoint: str = url_auth
        self.serverUrl: str = f"{self.serverPrefix}{self.serverIp}{f":{self.serverPort}" if self.serverPort else ""}"

        # ---------- request behaviour ----------
        self.timeoutTime: int = timeout_time
        self.maxRequestRetries: int = max_reties

        # ---------- health polling settings ----------
        self.healthCheckRate: int = health_poll_rate

        # ---------- file transfer ----------
        self._tmp = Path(tempfile.gettempdir()) / "ashtp" / "C"
        self._tmp.mkdir(parents=True, exist_ok=True)

        # ---------- integrations (optional) ----------
        self.logger = logging.getLogger(__name__)

        # ---------- crypto / handshake ----------
        self.Sb: bytes = server_public_encryption_const  # server's constant public key
        self.HELLO_REPLY_FORMAT = {
            "F":          {"type": bytes, "len": 32, "required": True}, # servers temp public key to make the symertric one
            "session_id": {"type": bytes, "len": 16, "required": True}, # just a random id
            "ok":         {"type": bytes, "len": 23, "required": True}, # ts sends "ok" and a 16 bit tag to detect tampering or corruption
        }
        self.AUTH_REPLY_FORMAT = {
            "ok": {"type": str, "required": True}
        }
        self.secureTunnelActive = False
        self.session:Session = None
        self.sessionId:bytes = b""
        self.apiKey: str = ""
        self._connecting: bool = False
        self._lastConnect: float = 0.0

        # ---------- runtime state ----------
        self.isOnline: bool = False
        self.failedRequests: int = 0

        # ---------- background tasks (keep last, they use everything above) ----------
        self._healthTask = None

    def Log(self, message:str):
        self.logger.info(message)

    def Error(self, message:str):
        self.logger.error(message)

    def emit(self, event:str ,*args, **kwargs):
        ArtysEventManager.EmitEvent(event, *args, **kwargs)


    def Parse(self, msg: dict, fmt: dict)-> dict:
        """
        takes one dict and compares it to a template
        :param msg:
        :param fmt:
        :return:
        """
        if not isinstance(msg, dict) or set(msg) - set(fmt):
            raise ParsingError("msg inst a dict or has forbidden fields")
        output = {}

        for name , spec in fmt.items():
            if name not in msg:
                if spec["required"]:
                    raise ParsingError("msg is missing keys defined in template")
                continue
            value = msg[name]
            if spec["type"] is bytes:
                try:
                    value = base64.b64decode(value, validate=True)
                except Exception as e:
                    raise ParsingError(f"{name} isn't bytes or the field is corrupted")

                if len(value) != spec["len"]:
                    raise ParsingError(f"{name} dosen't match length target")
            elif not isinstance(value, spec["type"]):
                raise ParsingError(f"{name} dosen't match type")
            output[name] = value
        return output

    def Seal(self, msg:bytes, method:str, path:str,session:Session|None = None, sessionId:bytes|None = None, ref:int|None = None) -> tuple[bytes, int]:
        """ Turns unencrypted JSON into request ready data

        :param ref:
        :param sessionId:
        :param session:
        :param msg:
        :param method:
        :param path:
        :return:
        """

        sec = session if session is not None else self.session
        secId = sessionId if sessionId is not None else self.sessionId

        plain = json.dumps(msg).encode()
        tag = _aad(secId, method, path, ref=ref)
        n, data = sec.Encrypt(plain, tag)

        return data, n

    def SealFileStream(self, meta:dict, filePath:Path, method:str, path:str, chunkSize:int=64*1024,
                       session:Session|None = None, sessionId:bytes|None = None, ref:int|None = None) -> Iterator[tuple[bytes, int]]:
        """ Turns an unencrypted File into request ready byte stream

        :param chunkSize:
        :param filePath:
        :param meta:
        :param method:
        :param path:
        :param sessionId:
        :param session:
        :param ref:
        :return:
        """

        sec = session if session is not None else self.session
        secId = sessionId if sessionId is not None else self.sessionId
        initialRequest = json.dumps( meta | {"chunk_size": chunkSize} ).encode()
        with tempfile.TemporaryDirectory(dir=self._tmp) as td: # niche thing i like

            zipPath = Path(td) / f"{filePath.name}.zip"
            with zipfile.ZipFile(zipPath, "w", zipfile.ZIP_DEFLATED) as zf:
                for file in filePath.rglob("*"):
                    if file.is_dir():
                        zf.write(file, arcname=str(file.relative_to(filePath)) + "/")
                    else:
                        zf.write(file, arcname=file.relative_to(filePath))

            data, n = self.Seal(initialRequest, method, path, sec, secId, ref)
            yield data, n

            with zipPath.open("rb") as f:
                while chunk := f.read(chunkSize):
                    data, n = self.Seal(chunk, method, path, sec, secId, ref)
                    yield data, n

    def TearOpen(self, msg:bytes, method:str, path:str, serverCount:int, session:Session|None = None, sessionId:bytes|None = None, ref:int|None = None) -> dict:
        """
        Turns encrypt byte data into (hopefuly) a readable JSON

        :param ref:
        :param serverCount:
        :param msg:
        :param method:
        :param path:
        :param session:
        :param sessionId:
        :return:
        """
        sec = session if session is not None else self.session
        secId = sessionId if sessionId is not None else self.sessionId

        if sec is None or secId is None:
            raise HandshakeError("no active session")

        path = path if path.startswith("/") else "/" + path
        n = serverCount
        tag = _aad(secId, method, path, ref=ref)
        plain  = sec.Decrypt(msg, n, tag)

        return json.loads(plain.decode())

    async def Init(self,api_key:str) -> bool:
        """
        Initializes the connection with the server and creates the encrypted authenticated channel.
        This function HAS to be used at the start of comunication with any server running the "ashtp" protocol.
        :param api_key:
        :return:
        """
        self.apiKey = api_key
        key_id = hashlib.blake2b(self.Sb, digest_size=8).digest()
        proto = self._version.encode("utf-8")

        for i in range(3):

            e = X25519PrivateKey.generate() # clients private key
            E = e.public_key() # clients public key
            Eb = E.public_bytes( # clients public key but converted to bytes
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )

            eS = e.exchange(X25519PublicKey.from_public_bytes(self.Sb)) # mix our private with servers const public

            #handshake package
            hello = {
                "protocol": self._version,
                "spk_hash": base64.b64encode( key_id ).decode(),
                "E":        base64.b64encode( Eb ).decode(),
            }

            #send of the handshake
            try:
                resp = await asyncio.to_thread(requests.post, f"{self.serverUrl}{self.serverHandshakeEndpoint}",
                                               json = hello, timeout = self.timeoutTime)
                resp.raise_for_status() # neat thing it raises when bad status arrives like 500 or 404
            except Exception as err:
                self.failedRequests += 1
                self.Error(str(err))
                continue

            try:
                reply = self.Parse(resp.json(), self.HELLO_REPLY_FORMAT)# check that the handshake package is actualy valid
                F = reply["F"]
                eF = e.exchange(X25519PublicKey.from_public_bytes(F)) # exchange keys to get the secret number (mix our private with servers public)

                c2s, s2c = _DeriveKeys(eS + eF, proto + key_id + Eb + F + self.Sb + reply["session_id"])
                session = Session(c2s, s2c)

                if session.Decrypt(reply["ok"],0, b"") != b"lets go":
                    raise HandshakeError("<ok> didnt match the expected! keys/ package are either malformed or where tampered with")

            except (HandshakeError, ParsingError, InvalidTag, ValueError) as err:
                self.Error(f"Handshake Failed: {err}")
                return False
            try:
                authPackage = json.dumps({ "api_key":api_key }).encode()

                authBytes, n = self.Seal(authPackage, "POST", self.serverAuthEndpoint, session, reply["session_id"])
                headers = {
                    "ashtp-Session": base64.b64encode(reply["session_id"]).decode(),    # take session id make it into base64 and turn it into words
                    "ashtp-Counter": str(n),                                            # the counter needed for encryption/decryption
                    "ashtp-Content": "json",                                            # content type
                }
                resp = await asyncio.to_thread(requests.post, f"{self.serverUrl}{self.serverAuthEndpoint}",
                                               data=authBytes, headers=headers, timeout=self.timeoutTime)
                resp.raise_for_status()
                serverCounter= int(resp.headers["ashtp-Counter"])
                resp = self.TearOpen(resp.content, "POST", self.serverAuthEndpoint, serverCounter ,session, reply["session_id"], ref=n)

                resp = self.Parse(resp, self.AUTH_REPLY_FORMAT)
                if not resp.get("ok") == "ok": raise HandshakeError("couldnt log in")

            except Exception as err:
                self.Error(f"Handshake Failed: {err}")
                return False


            #lets go we connected

            self.session = session
            self.sessionId = reply["session_id"]
            self.secureTunnelActive = True
            self.isOnline = True
            self.failedRequests = 0
            self.emit("ashtp_server_status_changed", True)
            return True
        return False

    async def CheckHealth(self):
        combinedUrl = f"{self.serverUrl}{self.serverHealthEndpoint}"

        while True:
            try:
                resp = await asyncio.to_thread(requests.get, combinedUrl,timeout=self.timeoutTime)
                resp.raise_for_status()
                if resp.json():
                    self.failedRequests = 0
                else:
                    self.failedRequests += 1

            except Exception as e:
                print(e)
                self.failedRequests += 1

            prev = self.isOnline
            if self.failedRequests > self.maxRequestRetries:
                self.isOnline = False
                self.secureTunnelActive = False
            elif self.failedRequests == 0:
                self.isOnline = True
            if self.isOnline != prev:
                self.Log(f"status -> {self.isOnline}")
            self.emit("ashtp_server_status_changed", self.isOnline)

            # rebuild the tunnel whenever the server is up but we have no working session
            if (self.isOnline and not self.secureTunnelActive and self.apiKey
                    and not self._connecting and time.monotonic() - self._lastConnect > 15):
                self._connecting = True
                self._lastConnect = time.monotonic()
                try:
                    await self.Init(self.apiKey)
                except Exception as err:
                    self.Error(f"reconnect failed: {err}")
                finally:
                    self._connecting = False

            await asyncio.sleep(self.healthCheckRate)

    async def _request(self, method: str, path: str, contentType:str, request: Iterable[bytes], timeout, usrHeaders:dict|None = None, sendBody: bool = True) -> dict:
        if not self.isOnline:
            raise ASHTPGeneralException("Server is offline")
        if not self.secureTunnelActive:
            raise ASHTPGeneralException("No active tunnel")

        timeout = self.timeoutTime if timeout is None else timeout
        path = path if path.startswith("/") else "/" + path
        url = f"{self.serverUrl}{path}"

        response:Response = Response()

        if contentType == "json":
            payload = next(iter(request)) if request is not None else json.dumps({"placeholder": secrets.randbits(64)}).encode()
            last_error = ""
            for attempt in range(self.maxRequestRetries):
                data, n = self.Seal(payload, method, path)

                headers = {
                    "ashtp-Session": base64.b64encode(self.sessionId).decode(), # take session id make it into base64 and turn it into words
                    "ashtp-Counter": str(n),                                    # the counter needed for encryption/decryption
                    "ashtp-Content": "json",                                    # content type
                }

                kwargs = {"headers": (usrHeaders or {}) | headers, "timeout": timeout}
                if sendBody:
                    kwargs["data"] = data
                if usrHeaders is not None:
                    body = kwargs.setdefault("data", {})
                    if not isinstance(body, dict):
                        raise TypeError("user headers can only be attached to dict bodies")
                    uh = body.setdefault("user_headers", {})
                    for key, header in usrHeaders.items():
                        if isinstance(header, str):
                            header = header.encode()
                        uh[key] = base64.b64encode(header).decode()
                try:
                    resp = await asyncio.to_thread(requests.request, method, url, **kwargs)
                    resp.raise_for_status()
                except requests.exceptions.HTTPError as e:
                    self.failedRequests += 1
                    last_error = str(e)
                    if e.response is not None and e.response.status_code == 401:
                        self.secureTunnelActive = False
                    if e.response is not None and e.response.status_code < 500:
                        raise ASHTPGeneralException(last_error) from e
                except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                    self.failedRequests += 1
                    last_error = str(e)
                else:
                    response = resp

                await asyncio.sleep(
                    min(0.25 * 2 ** attempt, 5))  # wait longer each time we fail to not hammer the server
            raise ASHTPGeneralException(last_error)
        elif contentType == "file":
            payload = request

        if (contentType := response.headers.get("ashtp-Content")) is not None:
            if type == "json":
                ...
            elif type == "file":
                ...
        raise ASHTPGeneralException("welp...")


    async def GetData(self, path:str, request:dict=None, timeout:float=None, usrHeaders:dict=None) -> dict:
        return await self._request("GET", path, request, timeout, usrHeaders, sendBody=True)

    async def PostData(self, path:str, request:dict, timeout:float=None, usrHeaders:dict=None) -> dict:
        return await self._request("POST", path, request, timeout, usrHeaders)


    async def GetFile(self, path:str, request:dict=None, timeout:float=None, usrHeaders:dict = None) -> Path:
        """
                Streams a file from the server.
                Can only be used to request files!
                If the file are larger than 1GB they will be put in tmp.

                :param path:
                :param usrHeaders:
                :param timeout:
                :param request:
                :return: path to downlaoded file
        """

        if not self.isOnline:
            raise ASHTPGeneralException("Server is offline")
        if not self.secureTunnelActive:
            raise ASHTPGeneralException("No active tunnel")

        timeout = self.timeoutTime if timeout is None else timeout
        path = path if path.startswith("/") else "/" + path
        url = f"{self.serverUrl}{path}"
        payload = request if request is not None else {"placeholder": secrets.randbits(64)}

        data, headers, n = self.Seal(payload, "GET", url)
        kwargs = {"headers": (usrHeaders or {}) | headers, "timeout": timeout}





async def PostFile(self, endPoint: str, file:Path,headers:dict = {}) -> dict:
    """
    Posts file to the server.
    Can only be used to upload files

    :param endPoint:
    :param file:
    :return: response
    """

    if not self.isOnline:
        return {"status": "failed", "code": "400", "message": "server is offline"}

    if not self.isOnline:
        return {"status": "failed", "code": "400", "message": "a secure connection to the server was not established"}

    combinedUrl = f"{self.serverUrl}{endPoint if endPoint.startswith("/") else "/" + endPoint}"
    kwargs = {"headers": self.persistentHeaders | headers}
    last_error = ""

    with open(file, "rb") as f:
        kwargs["headers"]["Content-Name"] = f.name
        kwargs["files"] = {"file": f}

        for i in range(0, self.maxRequestRetries):
            f.seek(0)
            try:
                resp = await asyncio.to_thread(requests.post, combinedUrl, **kwargs)
                resp.raise_for_status()
                response = resp.json()
                self.failedRequests = 0
                return response
            except Exception as e:
                last_error = e

    return {"status": "failed", "code": "000", "message": str(last_error)}
