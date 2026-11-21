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
import tempfile

#pypi
import requests
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidTag
from requests import Response

#in module
from artystd.ashtp import PROTOCOL_VERSION, idr, HANDSHAKE_PASS_PHRASE, TMP
from artystd.utilities.ArtysEventManager import ArtysEventManager
from .ASHTPEnums import ContentType, BaseHeaders
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
        if idr != "yes":
            raise Exception("no")
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
                sessionId = reply["session_id"]#TODO check how ts is sent

                if session.Decrypt(reply["ok"],0, b"") != HANDSHAKE_PASS_PHRASE:
                    raise HandshakeError("<ok> didnt match the expected! keys/package are either malformed or where tampered with")

            except (HandshakeError, ParsingError, InvalidTag, ValueError) as err:
                self.Error(f"Handshake Failed: {err}")
                return False
            try:
                authUrl = f"{self.serverUrl}{self.serverAuthEndpoint}"
                authBytes, n = ASHTPBase.Seal({ "api_key":api_key }, "POST", authUrl, session, sessionId)

                headers = ASHTPBase.StandardHeaders(ContentType.JSON, sessionId, n, False, len(authBytes))

                resp = await asyncio.to_thread(requests.post, authUrl,
                                               data=authBytes, headers=headers, timeout=self.timeoutTime)
                resp.raise_for_status()
                resp = await ASHTPBase.ReadBody(resp, session, sessionId, ref=n)
                resp = ASHTPBase.Parse(resp, self.AUTH_REPLY_FORMAT)
                if not resp.get("ok") == "ok": raise HandshakeError("couldnt log in")


            except Exception as err:
                self.Error(f"Handshake Failed: {err}")
                return False


            #lets go we connected

            self.session = session
            self.sessionId = sessionId
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

    # >>> EDIT [C4] one place for "send + count failures", used by both json and file mode
    async def _Send(self, method: str, url: str, **kwargs) -> tuple[Response | None, str]:
        """
        Sends one http request. Returns (response, "") on success, (None, error) when the caller may retry
        (5xx / timeout / connection error) and raises ASHTPGeneralException on 4xx.
        stream=True so ReadBody can iterate file replies instead of loading them whole.
        """
        try:
            resp = await asyncio.to_thread(requests.request, method, url, stream=True, **kwargs)
            resp.raise_for_status()
            return resp, ""
        except requests.exceptions.HTTPError as e:
            self.failedRequests += 1
            if e.response is not None and e.response.status_code == 401:
                self.secureTunnelActive = False
            if e.response is not None and e.response.status_code < 500:
                raise ASHTPGeneralException(str(e)) from e
            return None, str(e)
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            self.failedRequests += 1
            return None, str(e)



    async def _request(self, method: str, path: str, contentType: ContentType, request: dict | Path | str | None,
                       timeout: float | None = None, usrHeaders: dict | None = None, chunkSize: int = 64*1024) -> dict:
        if not self.isOnline:
            raise ASHTPGeneralException("Server is offline")
        if not self.secureTunnelActive:
            raise ASHTPGeneralException("No active tunnel")

        timeout = self.timeoutTime if timeout is None else timeout
        method = method.upper()
        path = path if path.startswith("/") else "/" + path
        url = f"{self.serverUrl}{path}"
        encodedUsrHeaders = None
        if usrHeaders:
            encodedUsrHeaders = {k: base64.b64encode(h.encode() if isinstance(h, str) else h).decode()
                                 for k, h in usrHeaders.items()}
        sendUHeaders = encodedUsrHeaders is not None

        if contentType == ContentType.JSON:
            payload = dict(request) if request else {}
            if sendUHeaders:
                payload["user_headers"] = encodedUsrHeaders
            last_error = ""
            for attempt in range(self.maxRequestRetries):
                data, n = ASHTPBase.Seal(payload, method, url, self.session, self.sessionId)  # fresh nonce per attempt

                headers = ASHTPBase.StandardHeaders(ContentType.JSON, self.sessionId, n, sendUHeaders, len(data))

                response, last_error = await self._Send(method, url, data=data, headers=headers, timeout=timeout)
                if response is not None:
                    return await ASHTPBase.ReadBody(response, self.session, self.sessionId, ref=n)
                await asyncio.sleep(
                    min(0.25 * 2 ** attempt, 5))  # wait longer each time we fail to not hammer the server
            raise ASHTPGeneralException(last_error)

        elif contentType == ContentType.FILE_STREAM:
            src = Path(request)
            if not src.exists():
                raise FileNotFoundError(f"File path expected but got nothing at: {src}")
            meta = {"user_headers": encodedUsrHeaders} if sendUHeaders else {}

            with tempfile.TemporaryDirectory(dir=TMP) as td:
                zipPath = ASHTPBase.PackZip(src, Path(td))
                size = zipPath.stat().st_size
                ref = self.session.sendN
                headers = ASHTPBase.StandardHeaders(ContentType.FILE_STREAM, self.sessionId, ref, sendUHeaders, size, chunkSize)
                frames = ASHTPBase.Frame(
                    ASHTPBase.SealFileStream(meta, zipPath, method, url, self.session, self.sessionId, chunkSize))
                response, last_error = await self._Send(method, url, data=frames, headers=headers, timeout=timeout)
                if response is None:  # a half consumed generator can't be replayed, so no retry loop in file mode
                    raise ASHTPGeneralException(last_error)
            return await ASHTPBase.ReadBody(response, self.session, self.sessionId, ref=ref)

        raise ASHTPGeneralException(f"Unsupported content type: {contentType}")

    async def GetData(self, path:str, request:dict=None, timeout:float=None, usrHeaders:dict=None) -> dict:
        return await self._request("GET", path, ContentType.JSON, request, timeout, usrHeaders)

    async def PostData(self, path:str, request:dict, timeout:float=None, usrHeaders:dict=None) -> dict:
        return await self._request("POST", path, ContentType.JSON, request, timeout, usrHeaders)

    async def PostFile(self, path:str, filePath: Path | str, timeout:float=None, usrHeaders:dict=None, chunkSize:int=64*1024) -> dict:
        return await self._request("POST", path, ContentType.FILE_STREAM, filePath, timeout, usrHeaders, chunkSize)
