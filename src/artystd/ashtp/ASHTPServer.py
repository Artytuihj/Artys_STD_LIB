from __future__ import annotations

import asyncio
import json
import tempfile
import time
from collections import deque
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, serialization
import base64
import hashlib
from fastapi import FastAPI, Request, Response
import logging
import inspect

from dataclasses import dataclass, field
import secrets

from src.artystd.ashtp import PROTOCOL_VERSION, SUPPORTED_SERVER_VERSIONS
from src.artystd.ashtp.IKeyAuthority import IKeyAuthority as ika


class HandshakeError(Exception):
    pass
class ParsingError(Exception):
    pass
class ReplayError(Exception):
    pass
class BodyTooLarge(Exception):
    pass
class ErrorHandlingError(Exception):
    pass
class ClientTooOldError(Exception):
    ...
class KeyLacksPermissionError(Exception):
    ...

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

async def _ReadBody(req: Request, limit: int) -> tuple[bytes, dict]:
    cl = req.headers.get("content-length")
    if cl is not None and int(cl) > limit:
        raise BodyTooLarge
    buf = bytearray()
    async for chunk in req.stream():
        buf += chunk
        if len(buf) > limit:
            raise BodyTooLarge
    return bytes(buf), dict(req.headers)

@dataclass
class ActiveSession:
    session: Session
    created: float = field(default_factory=time.monotonic)
    permsLevel: int = -1
    name: str = "None"
class Session:
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
class RateLimiter:#neat  thingy
    def __init__(self, limit: int, window: float):
        self.limit = limit
        self.window = window
        self.hits: dict[str, deque[float]] = {} # store key and a queue of req attempts

    def _Trim(self, key: str) -> deque:
        q = self.hits.setdefault(key, deque()) # get the queue from the dict and if dosent exist yet make it
        now = time.monotonic()
        while q and now - q[0] > self.window: # repeat while q is a thing and q[0] fits within the window
            q.popleft()
        return q

    def Count(self, key: str) -> int:#remove stale requests
        return len(self._Trim(key))

    def Blocked(self, key: str) -> bool:
        return self.Count(key) >= self.limit# call count and check if we are over the limit

    def Hit(self, key: str):
        self._Trim(key).append(time.monotonic())# add to the counter

class ASHTPServer:
    def __init__(self,
                 application:type[FastAPI],
                 server_private_encryption_const: bytes,
                 key_authority: ika,
                 url_prefix: str = "http://",
                 url_health: str = "/health",
                 url_handshake: str = "/privet",
                 url_auth: str = "/auth",):

        # ----------------------------------------------
        # |||  Arty's Secure HTTP Transport Protocol |||
        # ----------------------------------------------

        # --------- protocol ----------
        self._version: str = PROTOCOL_VERSION

        # ------- server address --------
        self.serverPrefix: str = url_prefix
        self.serverHealthEndpoint: str = url_health
        self.serverHandshakeEndpoint: str = url_handshake
        self.serverAuthEndpoint: str = url_auth

        # -------- file transfer ---------
        self._tmp = Path(tempfile.gettempdir()) / "ashtp" / "S"
        self._tmp.mkdir(parents=True, exist_ok=True)

        # ---------- crypto / handshake -------
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
        # ------- session management ---------
        self.activeSessions: dict[bytes,ActiveSession] = {}
        self.keyAuthority = key_authority

        # --------- rate limits --------
        self.hsLimit = RateLimiter(limit=300, window=60)
        self.authFails = RateLimiter(limit=50, window=300)
        self.maxSessions = 200

        # -------- other ---------
        self.logger = logging.getLogger(__name__)

        # ------- app --------
        self.app = application
        self.app.add_api_route("/health", self.Health, methods=["GET"])
        self.app.add_api_route("/privet", self.Handshake, methods=["POST"])
        self.app.add_api_route("/auth", self.Authenticate, methods=["POST"])

    # --------- tool chain --------
    def Log(self, message:str):
        self.logger.info(message)

    def Error(self, message:str):
        self.logger.error(message)

    def Parse(self, msg: dict, baseModel: dict)-> dict:
        """
        takes one dict and compares it to a template
        :param msg:
        :param baseModel:
        :return:
        """
        if not isinstance(msg, dict) or set(msg) - set(baseModel): # turn the dict into a set(storing the keys) and compare with base model
            raise ParsingError("msg inst a dict or has forbidden fields")
        output = {}

        for name , spec in baseModel.items():
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

    def Expire(self, max_age: float = 10.0):
        now = time.monotonic()
        for sid, s in list(self.activeSessions.items()):
            if s.permsLevel == -1 and now - s.created > max_age:
                del self.activeSessions[sid]


    def Seal(self, msg:dict, method:str, path:str, sessionId:bytes, ref:int|None = None ):
        """ Turns unencrypted JSON into request ready data

        :param ref:
        :param sessionId:
        :param session:
        :param msg:
        :param method:
        :param path:
        :return:
        """

        try:
            sec = self.activeSessions[sessionId].session
        except KeyError:
            raise KeyError("[ashtp] Tried using expired session")


        plain = json.dumps(msg).encode()
        tag = _aad(sessionId, method, path, ref=ref)
        n, data = sec.Encrypt(plain,tag)

        headers = {
            "ashtp-Session": base64.b64encode(sessionId).decode(), # take session id make it into base64 and turn it into words
            "ashtp-Counter": str(n),# the counter needed for encryption/decryption
            "ashtp-Content": "json",# content type
        }

        return data, headers, n

    def TearOpen(self, msg:tuple[bytes,dict[str,str]], method:str, path:str, clientCount:int, sessionId:bytes, ref:int|None = None) -> tuple[dict,dict]:
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
        sec = self.activeSessions[sessionId].session

        path = path if path.startswith("/") else "/" + path
        n = clientCount
        tag = _aad(sessionId, method, path, ref=ref)
        plain  = sec.Decrypt(msg[0], n, tag)
        plainJson = json.loads(plain.decode())
        headers = plainJson["user_headers"] | msg[1]
        body = plainJson.pop("user_headers", None)

        return body , headers

    def Endpoint(self, path:str, method:str, minPerms:int|None = None, baseModel:dict|None = None, maxBody:int = 16 * 1024):
        method = method.upper()

        def decorator(fn):
            async def endpoint(req:Request):
                # unpack the request
                try:
                    sid = base64.b64decode(req.headers["ashtp-Session"])
                    active = self.activeSessions.get(sid)
                    requiredPermissionLevel = self.keyAuthority.minPermissionLevel if minPerms is None else minPerms


                    if active is None or not self.keyAuthority.ComparePermissions(active.permsLevel, requiredPermissionLevel):
                        return Response(status_code=403)# forbidden request

                    counter = int(req.headers["ashtp-Counter"])

                    contents, headers = self.TearOpen(await _ReadBody(req, maxBody), method, path, counter, sid)
                    if baseModel: contents = self.Parse(contents, baseModel)

                except (KeyError, ValueError, ReplayError, InvalidTag) as e:
                    self.Error(f"{path}: {e}")
                    return Response(status_code=400) # broken request
                except BodyTooLarge:
                    return Response(status_code=413) # body too large

                # handle request
                try:
                    if inspect.iscoroutinefunction(fn):
                        result = await fn(active, contents, headers)
                    else:
                        result = await asyncio.to_thread(fn, active, contents, headers)
                except Exception as e:
                    self.Error(f"{path} handler failed: {e}")
                    return Response(status_code=500) # random error
                try:
                    data, headers, _ = self.Seal(result, method, path, sid, ref=counter)
                    return Response(content=data, headers=headers, media_type="application/octet-stream")
                except KeyError as e:
                    self.Log(str(e))
                    return Response(status_code=401) # Unotorised

            self.app.add_api_route(path, endpoint, methods=[method])
            return fn
        return decorator


    # ------------ endpoints ---------------

    async def Health(self):
        return {"code": 200, "message": "ok"}

    async def Handshake(self, request: Request):

        if self.hsLimit.Blocked("*"):
            return Response(status_code=429)# rate limit exceeded
        self.hsLimit.Hit("*")
        self.Expire() # remove old sessions to prevent overflow

        try:
            body = await _ReadBody(request, 1024)
            raw = self.Parse(json.loads(body), self.HELLO_FORMAT)


            proto = raw["protocol"]
            key_id = raw["spk_hash"]

            if proto not in SUPPORTED_SERVER_VERSIONS: # check that the version matches
                raise ClientTooOldError("Client is not supported")
            if key_id != hashlib.blake2b(self.Sb, digest_size=8).digest(): # check the key matches
                raise HandshakeError("Wrong/old public key")

            Eb = raw["E"] # clients public bytes

            sE = self.s.exchange(X25519PublicKey.from_public_bytes(Eb))  # mix our const private with Clients public

            f = X25519PrivateKey.generate()
            F = f.public_key()
            Fb = F.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )

            sessionId = secrets.token_bytes(16) # make a session id

            fE = f.exchange(X25519PublicKey.from_public_bytes(Eb))

            c2s, s2c = _DeriveKeys(sE + fE, proto.encode() + key_id + Eb + Fb + self.Sb + sessionId)
            session = Session(s2c, c2s)

            if len(self.activeSessions) >= self.maxSessions:
                unauth = [(s.created, k) for k, s in self.activeSessions.items() if s.permsLevel < 0]
                if not unauth:
                    return Response(status_code=503) # if we have all aslots taken refuse service
                del self.activeSessions[min(unauth)[1]]

            self.activeSessions[sessionId] = ActiveSession(session=session)
            n, ct = session.Encrypt(b"lets go", b"")
            reply = {
                "F":          base64.b64encode( Fb ).decode(),
                "session_id": base64.b64encode( sessionId ).decode(),
                "ok":         base64.b64encode( ct ).decode()
            }
            return reply
        except BodyTooLarge as e:
            return Response(status_code=413) #body to large
        except (ValueError, ParsingError, HandshakeError) as e:
            self.Error(str(e))
            return Response(status_code=400) # bad request
        except ClientTooOldError:
            return Response(status_code=426, headers={"ashtp-Upgrade": PROTOCOL_VERSION})

    async def Authenticate(self, request: Request):
        try:
            raw = await _ReadBody(request, 2 * 1024)

            sid = base64.b64decode(request.headers["ashtp-Session"])
            active = self.activeSessions.get(sid)
            if active is None:
                raise HandshakeError("unknown session")

            count = int(request.headers["ashtp-Counter"])

            req = self.TearOpen(raw, "POST", self.serverAuthEndpoint, count, sid)
            req = self.Parse(req, self.AUTH_FORMAT)

            apiKey = req["api_key"]
            allowed, permissionLevel, name = await self.keyAuthority.CheckPerms(apiKey)
            if allowed:
                active.permsLevel = permissionLevel
                active.name = name

                data, headers, n = self.Seal({"ok": "ok"}, "POST", self.serverAuthEndpoint, sid, count)
                return Response(content=data, headers=headers)
            else:
                self.activeSessions.pop(sid)
                self.authFails.Hit("*")
                await asyncio.sleep(min(1 + 0.2 * self.authFails.Count("*"), 10))
                raise KeyLacksPermissionError("Key dosen't have enough permissions or dosen't match")


        except BodyTooLarge:
            return Response(status_code=413) # too large bish
        except (KeyError, ValueError, ParsingError, HandshakeError, ReplayError, InvalidTag) as e:
            self.Error(str(e))
            return Response(status_code=400)# bad req
        except KeyLacksPermissionError:
            return Response(status_code=403)# no no perms
