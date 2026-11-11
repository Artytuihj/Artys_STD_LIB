import asyncio
import json
import time
from collections import deque
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
import base64
import hashlib
from fastapi import FastAPI, Request, Response
import logging
import inspect

from dataclasses import dataclass, field
import secrets

from src.artystd.ashtp import PROTOCOL_VERSION, SUPPORTED_SERVER_VERSIONS
from .IKeyAuthority import IKeyAuthority as ika
from .Session import Session
from .ASHTPExceptions import ParsingError, HandshakeError, ReplayError, BodyTooLarge, ClientTooOldError, KeyLacksPermissionError
from .ASHTPBase import ASHTPBase

@dataclass
class ActiveSession:
    session: Session
    created: float = field(default_factory=time.monotonic)
    permsLevel: int = -1
    name: str = "None"

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

    def Expire(self, max_age: float = 10.0):
        now = time.monotonic()
        for sid, s in list(self.activeSessions.items()):
            if s.permsLevel == -1 and now - s.created > max_age:
                del self.activeSessions[sid]

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

                    contents, headers = ASHTPBase.TearOpen(await ASHTPBase.ReadBody(req, maxBody), method, path, counter, active.session, sid)
                    if baseModel: contents = ASHTPBase.Parse(contents, baseModel)

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
                    data, headers, _ = ASHTPBase.Seal(result, method, path,active.session, sid, ref=counter)#TODO update seals and tears to a new standard
                    return Response(content=data, headers=headers, media_type="application/octet-stream")
                except KeyError as e:
                    self.Log(str(e))
                    return Response(status_code=401) # Unotorised

            self.app.add_api_route(path, endpoint, methods=[method])
            return fn
        return decorator


    # ------------ endpoints ---------------

    async def Health(self):
        return Response(status_code=200)

    async def Handshake(self, request: Request):

        if self.hsLimit.Blocked("*"):
            return Response(status_code=429)# rate limit exceeded
        self.hsLimit.Hit("*")
        self.Expire() # remove old sessions to prevent overflow

        try:
            body = await ASHTPBase.ReadBody(request, 1024)
            raw = ASHTPBase.Parse(json.loads(body), self.HELLO_FORMAT)#TODO body is angry ova here check it out later


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

            c2s, s2c = ASHTPBase.DeriveKeys(sE + fE, proto.encode() + key_id + Eb + Fb + self.Sb + sessionId)
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
            raw = await ASHTPBase.ReadBody(request, 2 * 1024)

            sid = base64.b64decode(request.headers["ashtp-Session"])
            active = self.activeSessions.get(sid)
            if active is None:
                raise HandshakeError("unknown session")

            count = int(request.headers["ashtp-Counter"])

            req = ASHTPBase.TearOpen(raw, "POST", self.serverAuthEndpoint, count, active.session, sid)# TODO same problem fix the Read Body function its fucky
            req = ASHTPBase.Parse(req, self.AUTH_FORMAT)

            apiKey = req["api_key"]
            allowed, permissionLevel, name = await self.keyAuthority.CheckPerms(apiKey)
            if allowed:
                active.permsLevel = permissionLevel
                active.name = name

                data, n = ASHTPBase.Seal({"ok": "ok"}, "POST", self.serverAuthEndpoint, active.session, sid, count)
                return Response(content=data)#, headers=headers) TODO wants basic headers make a function for it in base
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
