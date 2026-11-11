#std
import json
import secrets
import time
import zipfile
from pathlib import Path
import asyncio
import logging
import base64
import hashlib

#pypi
import requests
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidTag
from requests import Response

#in module
from src.artystd.ashtp import PROTOCOL_VERSION
from src.artystd.utilities.ArtysEventManager import ArtysEventManager
from .Session import Session
from .ASHTPExceptions import HandshakeError, ParsingError, ASHTPGeneralException
from .ASHTPBase import ASHTPBase

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

        # ---------- background tasks ----------
        self._healthTask = None

    def Log(self, message:str):
        self.logger.info(message)

    def Error(self, message:str):
        self.logger.error(message)

    def emit(self, event:str ,*args, **kwargs):
        ArtysEventManager.EmitEvent(event, *args, **kwargs)


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
                reply = ASHTPBase.Parse(resp.json(), self.HELLO_REPLY_FORMAT)# check that the handshake package is actualy valid
                F = reply["F"]
                eF = e.exchange(X25519PublicKey.from_public_bytes(F)) # exchange keys to get the secret number (mix our private with servers public)

                c2s, s2c = ASHTPBase.DeriveKeys(eS + eF, proto + key_id + Eb + F + self.Sb + reply["session_id"])
                session = Session(c2s, s2c)

                if session.Decrypt(reply["ok"],0, b"") != b"lets go":
                    raise HandshakeError("<ok> didnt match the expected! keys/ package are either malformed or where tampered with")

            except (HandshakeError, ParsingError, InvalidTag, ValueError) as err:
                self.Error(f"Handshake Failed: {err}")
                return False
            try:
                authPackage = json.dumps({ "api_key":api_key }).encode()

                authBytes, n = ASHTPBase.Seal(authPackage, "POST", self.serverAuthEndpoint, session, reply["session_id"])
                headers = {
                    "ashtp-Session": base64.b64encode(reply["session_id"]).decode(),    # take session id make it into base64 and turn it into words
                    "ashtp-Counter": str(n),                                            # the counter needed for encryption/decryption
                    "ashtp-Content": "json",                                            # content type
                }
                resp = await asyncio.to_thread(requests.post, f"{self.serverUrl}{self.serverAuthEndpoint}",
                                               data=authBytes, headers=headers, timeout=self.timeoutTime)
                resp.raise_for_status()
                serverCounter= int(resp.headers["ashtp-Counter"])
                resp = ASHTPBase.TearOpen(resp.content, "POST", self.serverAuthEndpoint, serverCounter ,session, reply["session_id"], ref=n)

                resp = ASHTPBase.Parse(resp, self.AUTH_REPLY_FORMAT)
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
                resp:Response = await asyncio.to_thread(requests.get, combinedUrl,timeout=self.timeoutTime)
                resp.raise_for_status()
                if resp.ok:
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

    async def _request(self, method: str, path: str, contentType:str, request: bytes, timeout, usrHeaders:dict|None = None, sendBody: bool = True) -> tuple[dict,dict]:
        if not self.isOnline:
            raise ASHTPGeneralException("Server is offline")
        if not self.secureTunnelActive:
            raise ASHTPGeneralException("No active tunnel")

        timeout = self.timeoutTime if timeout is None else timeout
        path = path if path.startswith("/") else "/" + path
        url = f"{self.serverUrl}{path}"

        response:Response = Response()

        if contentType == "json":
            payload = request if request is not None else json.dumps({"placeholder": secrets.randbits(64)}).encode()
            last_error = ""
            for attempt in range(self.maxRequestRetries):
                data, n = ASHTPBase.Seal(payload, method, path, self.session, self.sessionId)

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
                        raise TypeError("user headers can only be attached to dict bodies or files")
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

            headers = {
                "ashtp-Session": base64.b64encode(self.sessionId).decode(), # take session id make it into base64 and turn it into words
                "ashtp-Counter": str(self.session.sendN + 1),  # the counter needed for encryption/decryption
                "ashtp-Content": "file",  # content type
            }

            if not request["file"]: raise FileNotFoundError("File path expected by got NONE")
            kwargs = {"headers": (usrHeaders or {}) | headers, "timeout": timeout,
                      "data": ASHTPBase.Frame(ASHTPBase.SealFileStream(usrHeaders, Path(request.decode()), method, path, self.session, self.sessionId))}#TODO headers are mad fix them
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

        if (respContentType := response.headers.get("ashtp-Content")) is not None:
            if respContentType == "json":
                unwrapped = ASHTPBase.TearOpen(response.content, method, path, int(response.headers["ashtp-Counter"]), self.session, self.sessionId)
                unwrapped["status-code"] = response.status_code
                return unwrapped, dict(response.headers) | unwrapped.get("headers", {})
            elif respContentType == "file":
                ...#TODO implement what happens in case we recive a file back ok :)
                   # procrastinating for like 5 days now...
                   # ts is still not done wtf
        raise ASHTPGeneralException("welp...")

    async def GetData(self, path:str, request:dict=None, timeout:float=None, usrHeaders:dict=None) -> dict:
        return await self._request("GET", path, request, timeout, usrHeaders, sendBody=True)

    async def PostData(self, path:str, request:dict, timeout:float=None, usrHeaders:dict=None) -> dict:
        return await self._request("POST", path, request, timeout, usrHeaders)





async def PostFile(self, endPoint: str, file:Path,headers:dict = {}) -> dict:
    raise Exception("why tf u shouldnt be here")
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
