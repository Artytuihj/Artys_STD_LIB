from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path

import fastapi
import requests
import asyncio
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, serialization
import base64
import hashlib
from fastapi import FastAPI, Request, Response
import logging
import IKeyAuthority
from dataclasses import dataclass, field
from cryptography.exceptions import InvalidTag
import secrets

class HandshakeError(Exception):
    pass

class ParsingError(Exception):
    pass


def _DeriveKeys(secret:bytes, transcrypt:bytes, length:int=64)-> tuple[bytes,bytes]:
    symKey = HKDF(algorithm=hashes.SHA256(), length=length, salt=None,
                  info=b"ashtp sym sesscion key" + transcrypt).derive(secret)
    return symKey[32:], symKey[:32]

def _Expire(self, max_age: float = 10.0):
    now = time.monotonic()
    for sid, s in list(self.activeSessions.items()):
        if not s.authenticated and now - s.created > max_age:
            del self.activeSessions[sid]

@dataclass
class ActiveSession:
    session: Session
    created: float = field(default_factory=time.monotonic)
    permsLevel: int = 0

class Session():
    def __init__(self, send_key:bytes, recv_key:bytes):
        self.send = ChaCha20Poly1305(send_key)
        self.recv = ChaCha20Poly1305(recv_key)
        self.sendN = 0
        self.recvN = 0

    @staticmethod
    def _nonce(n: int) -> bytes:
        return b"\0" * 4 + n.to_bytes(8, "little") # generates a 12 byte number ( 0 0 0 0 )just filed with zeros (0 0 0 0 0 0 0 0) a simple counter little means less significant comes first

    def Encrypt(self, data:bytes, tag:bytes = b""):
        ct = self.send.encrypt(self._nonce(self.sendN), data, tag) # here we encrypt data with the send key and tag (ct stands for "cyphertext")
        self.sendN += 1
        return ct

    def Decrypt(self, data:bytes,n ,tag:bytes = b""):
        dr = self.recv.decrypt(self._nonce(n), data, tag) # do the same as encrypt but backwards ("dr" stands for decryption result)
        self.recvN = 1
        return  dr

class ASHTPServer:
    def __init__(self,
                 server_private_encryption_const: bytes,
                 key_authority: type[IKeyAuthority],
                 application_name: str = "ASHTP-Service",
                 port: int = 80,
                 host:str = "127.0.0.1",
                 url_prefix: str = "http://",
                 url_health: str = "/health",
                 url_handshake: str = "/privet",
                 url_auth: str = "/auth",):

        # ----------------------------------------------
        # |||  Arty's Secure HTTP Transport Protocol |||
        # ----------------------------------------------

        # ---------- protocol ----------
        self._version: str = "ashtp 1"

        # ---------- server address ----------
        self.appName = application_name
        self.serverPort: int = port
        self.ServerIp:str = host
        self.serverPrefix: str = url_prefix
        self.serverHealthEndpoint: str = url_health
        self.serverHandshakeEndpoint: str = url_handshake
        self.serverAuthEndpoint: str = url_auth

        # ---------- file transfer ----------
        self._tmp = Path(tempfile.gettempdir()) / "ashtp" / "S"
        self._tmp.mkdir(exist_ok=True)

        # ---------- crypto / handshake ----------
        self.sb: bytes = server_private_encryption_const  # server's constant private key
        self.s = X25519PrivateKey.from_private_bytes(self.sb)  # servers const private
        self.S = self.s.public_key()  # servers const public
        self.Sb = self.S.public_bytes(  # const public in bytes
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        self.HELLO_FORMAT = {
            "protocol": {"type": str, "required": True},
            "spk_hash": {"type": bytes, "len": 8, "required": True},
            "E":        {"type": bytes, "len": 32, "required": True},
        }
        self.AUTH_FORMAT = {
            "api_key": {"type": str, "required": True}
        }
        # ---------- session management ----------
        self.activeSessions: dict[bytes,ActiveSession] = {}
        self.keyAuthority = key_authority

        # --------- other ------------
        self.logger = logging.getLogger(__name__)

        # --------- app ---------
        self.app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
        self.app.add_api_route("/health", self.Health, methods=["GET"])
        self.app.add_api_route("/privet", self.Handshake, methods=["POST"])
        self.app.add_api_route("/auth", self.Authenticate, methods=["POST"])

    # ---------- tool chain ----------
    def Log(self, message:str):
        self.logger.info(message)

    def Error(self, message:str):
        self.logger.error(message)

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

    # ------------ endpoints --------------

    async def Health(self):
        return {"status": "success", "code": 200, "message": "ok"}

    async def Handshake(self, request: Request):
        _Expire(self) # remove old sessions to prevent overflow
        try:
            req = await request.json()
            req = self.Parse(req, self.HELLO_FORMAT)

            proto = req["protocol"]
            key_id = req["spk_hash"]

            if proto != self._version: # check that the version matches
                raise HandshakeError("Wrong handshake version")
            if key_id != hashlib.blake2b(self.Sb, digest_size=8).digest(): # check the key matches
                raise HandshakeError("Wrong/old public key")

            Eb = req["E"] # clients public bytes

            sE = self.s.exchange(X25519PublicKey.from_public_bytes(Eb))  # mix our const private with Clients public

            f = X25519PrivateKey.generate()
            F = f.public_key()
            Fb = F.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )

            sessionId = secrets.token_bytes(16) # make a session id

            fE = f.exchange(X25519PublicKey.from_public_bytes(Eb))

            c2s, s2c = _DeriveKeys(sE + fE, proto.encode("utf-8") + key_id + Eb + Fb + self.Sb)
            session = Session(s2c, c2s)
            self.activeSessions[sessionId] = ActiveSession(session)

            reply = {
                "F":          base64.b64encode( Fb ).decode(),
                "session_id": base64.b64encode( sessionId ).decode(),
                "ok":         base64.b64encode( session.Encrypt(b"lets go", b"") ).decode()
            }
            return reply
        except (ValueError, ParsingError, HandshakeError) as e:
            self.Error(str(e))
            return Response(status_code=400)

    async def Authenticate(self, request: Request):
        try:
            req = await request.json()
            req = self.Parse(req, self.AUTH_FORMAT)
            #TODO add authentication with the key authority

        except (ValueError, ParsingError, HandshakeError) as e:
            self.Error(str(e))
            return Response(status_code=400)


    def Seal(self, msg:dict, method:str, path:str, session:Session|None = None, sessionId:bytes|None = None ):
        """ Turns unencrypted JSON into request ready data

        :param sessionId:
        :param session:
        :param msg:
        :param method:
        :param path:
        :return:
        """

        sec = session if session is not None else self.session
        secId = sessionId if sessionId is not None else self.sessionId

        n = sec.sendN
        plain = json.dumps(msg).encode()
        tag = secId + method.encode() + b" " + path.encode()
        data = sec.Encrypt(plain,tag)

        headers = {
            "X-Session": base64.b64encode(secId).decode(), # take session id make it into base64 and turn it into words
            "X-Counter": str(n),# the counter needed for encryption/decryption
            "Content-Type": "application/octet-stream",#the thing saying basicly we have random binary bs onboard (octet = byte)
        }

        return data, headers

    def TearOpen(self, msg:bytes, method:str, path:str, serverCount:int, session:Session|None = None, sessionId:bytes|None = None ) -> dict:
        """
        Turns encrypt byte data into (hopefuly) a readable JSON

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
        tag = secId + method.encode() + b" " + path.encode()
        plain  = sec.Decrypt(msg, n, tag)

        return json.loads(plain.decode())