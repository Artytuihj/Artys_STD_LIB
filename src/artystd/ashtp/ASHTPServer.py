import asyncio
import json
import shutil  # EDIT [S1]: needed by _FileReply cleanup
import tempfile  # EDIT [S1]: needed by _FileReply
import time
from collections import deque
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
import base64
import hashlib
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse  # EDIT [S1]: file replies
import logging
import inspect

from dataclasses import dataclass, field
import secrets

from artystd.ashtp import PROTOCOL_VERSION, SUPPORTED_SERVER_VERSIONS, TMP, HANDSHAKE_PASS_PHRASE  # EDIT [S1]: was `src.artystd...` (Base uses `artystd...`, two names = two module copies); + TMP / HANDSHAKE_PASS_PHRASE
from . import idr
from .ASHTPEnums import BaseHeaders, ContentType  # EDIT [S1]: ContentType
from .IKeyAuthority import IKeyAuthority as ika
from .Session import Session
from .ASHTPExceptions import ParsingError, HandshakeError, ReplayError, ContentTooLarge, ClientTooOldError, KeyLacksPermissionError, MalformedHeader, TamperedPackage  # EDIT [S1]: + MalformedHeader, TamperedPackage (ReadBody raises them)
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
                 url_body: str,
                 url_prefix: str = "http://",
                 url_health: str = "/health",
                 url_handshake: str = "/privet",
                 url_auth: str = "/auth",):

        # ----------------------------------------------
        # |||  Arty's Secure HTTP Transport Protocol |||
        # ----------------------------------------------
        if idr != "yes":
            raise Exception("no")
        # --------- protocol ----------
        self._version: str = PROTOCOL_VERSION

        # ------- server address --------
        self.serverPrefix: str = url_prefix
        self.serverBody: str = url_body
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

        self.app.add_api_route(self.serverHealthEndpoint, self.Health, methods=["GET"])
        self.app.add_api_route(self.serverHandshakeEndpoint, self.Handshake, methods=["POST"])
        self.app.add_api_route(self.serverAuthEndpoint, self.Authenticate, methods=["POST"])


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

    # >>> EDIT [S4] two helpers used by the handlers below
    async def _ReadPlain(self, req: Request, limit: int) -> bytes:
        """
        Reads an UNENCRYPTED body (only the handshake hello is) with a size cap.
        Needed because ReadBody always decrypts, so it can't be used before a session exists.
        """
        declared = req.headers.get("content-length")
        if declared is not None and int(declared) > limit:
            raise ContentTooLarge("Body larger than allowed")
        body = await req.body()
        if len(body) > limit:
            raise ContentTooLarge("Body larger than allowed")
        return body

    def _FileReply(self, src: Path, method: str, url: str, active: ActiveSession, sid: bytes, counter: int,
                   chunkSize: int = 64 * 1024) -> StreamingResponse:
        """
        Builds the reply for a handler that returned a Path: zip -> seal chunk by chunk -> frame, streamed.
        The zip is built up front because the size header has to be known before the first byte is sent.
        """
        td = tempfile.mkdtemp(dir=TMP)
        try:
            zipPath = ASHTPBase.PackZip(src, Path(td))
            size = zipPath.stat().st_size
        except Exception:
            shutil.rmtree(td, ignore_errors=True)
            raise

        def body():
            try:
                yield from ASHTPBase.Frame(
                    ASHTPBase.SealFileStream({}, zipPath, method, url, active.session, sid, chunkSize, ref=counter))
            finally:
                shutil.rmtree(td, ignore_errors=True)  # delete the zip once streamed (or the client dropped)

        # counter header is informational for streams (every frame carries its own n), the request counter keeps it simple
        headers = ASHTPBase.StandardHeaders(ContentType.FILE_STREAM, sid, counter, False, size, chunkSize)
        return StreamingResponse(body(), headers=headers, media_type="application/octet-stream")


    def Endpoint(self, path:str, method:str, minPerms:int|None = None, baseModel:dict|None = None, maxBody:int = 16 * 1024):#todo adjust the size limits
        method = method.upper()

        def decorator(fn):

            async def endpoint(req:Request):
                url = str(req.url)
                try:
                    sid = base64.b64decode(req.headers[BaseHeaders.SESSION])
                    active = self.activeSessions.get(sid)
                    requiredPermissionLevel = self.keyAuthority.minPermissionLevel if minPerms is None else minPerms

                    if active is None or active.permsLevel < 0:
                        return Response(status_code=401)# no/unauthenticated session -> client must re-handshake
                    if not self.keyAuthority.ComparePermissions(active.permsLevel, requiredPermissionLevel):
                        return Response(status_code=403)# forbidden request

                    counter = int(req.headers[BaseHeaders.COUNTER])
                    contentType = ContentType(req.headers[BaseHeaders.CONTENT_TYPE])
                    sendsUHeaders = req.headers.get(BaseHeaders.INCL_HEADERS) == "1"

                    if contentType == ContentType.JSON and int(req.headers.get("content-length", 0)) > maxBody:
                        raise ContentTooLarge("Body larger than this endpoint allows")  # maxBody was an unused param

                    contents = await ASHTPBase.ReadBody(req, active.session, sid)

                    # json -> the dict is the payload, stream -> the payload is the metadata frame
                    holder = contents["meta"] if contentType.isStream else contents
                    if not isinstance(holder, dict):
                        raise ParsingError("payload isn't a dict")
                    holder.pop("chunk_size", None)  # added by SealFileStream, not part of the user's fields

                    userHeaders = {}
                    if sendsUHeaders:
                        raw = holder.pop("user_headers", {})
                        if not isinstance(raw, dict):
                            raise ParsingError("user_headers isn't a dict")
                        userHeaders = {k: base64.b64decode(v, validate=True) for k, v in raw.items()}

                    if baseModel:
                        holder = ASHTPBase.Parse(holder, baseModel)
                        if contentType.isStream:
                            contents["meta"] = holder
                        else:
                            contents = holder

                except ContentTooLarge:
                    return Response(status_code=413) # body too large
                except HandshakeError as e:
                    self.Error(f"{path}: {e}")
                    return Response(status_code=401)
                except (KeyError, ValueError, TypeError, ReplayError, InvalidTag, ParsingError, MalformedHeader, TamperedPackage) as e:
                    self.Error(f"{path}: {e}")
                    return Response(status_code=400) # broken request

                # handle request
                try:
                    if inspect.iscoroutinefunction(fn):
                        result = await fn(active, contents, userHeaders)
                    else:
                        result = await asyncio.to_thread(fn, active, contents, userHeaders)
                except Exception as e:
                    self.Error(f"{path} handler failed: {e}")
                    return Response(status_code=500) # random error

                # a handler returns a dict (-> json reply) or a Path to a file/folder (-> file stream reply)
                try:
                    if isinstance(result, Path):
                        return self._FileReply(result, method, url, active, sid, counter)
                    data, n = ASHTPBase.Seal(result, method, url, active.session, sid, ref=counter)
                    replyHeaders = ASHTPBase.StandardHeaders(ContentType.JSON, sid, n, False, len(data))
                    return Response(content=data, headers=replyHeaders, media_type="application/octet-stream")
                except Exception as e:
                    self.Error(f"{path} couldn't seal the reply: {e}")
                    return Response(status_code=500)


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
            body = await self._ReadPlain(request, 1024)
            raw = ASHTPBase.Parse(json.loads(body), self.HELLO_FORMAT)


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
            n, ct = session.Encrypt(HANDSHAKE_PASS_PHRASE, b"")
            reply = {
                "F":          base64.b64encode( Fb ).decode(),
                "session_id": base64.b64encode( sessionId ).decode(),
                "ok":         base64.b64encode( ct ).decode()
            }
            return reply
        except ContentTooLarge as e: # tell him to fuck off ye!
            return Response(status_code=413) #body to large
        except (ValueError, ParsingError, HandshakeError) as e:
            self.Error(str(e))
            return Response(status_code=400) # bad request
        except ClientTooOldError:
            return Response(status_code=426, headers={"ashtp-Upgrade": PROTOCOL_VERSION})

    async def Authenticate(self, request: Request):
        try:

            sid = base64.b64decode(request.headers[BaseHeaders.SESSION])
            active = self.activeSessions.get(sid)
            if active is None:
                raise HandshakeError("unknown session")

            count = int(request.headers[BaseHeaders.COUNTER])
            url = str(request.url)

            if request.headers.get(BaseHeaders.CONTENT_TYPE) != ContentType.JSON:
                raise ParsingError("auth has to be json")  # ReadBody would otherwise happily accept a file stream here
            if int(request.headers.get("content-length", 0)) > 2 * 1024:
                raise ContentTooLarge("auth body too large")

            req = await ASHTPBase.ReadBody(request, active.session, sid)
            req = ASHTPBase.Parse(req, self.AUTH_FORMAT)


            apiKey = req["api_key"]
            allowed, permissionLevel, name = await self.keyAuthority.CheckPerms(apiKey)
            if allowed:
                active.permsLevel = permissionLevel
                active.name = name

                data, n = ASHTPBase.Seal({"ok": "ok"}, "POST", url, active.session, sid, count)
                headers = ASHTPBase.StandardHeaders(ContentType.JSON, sid, n, False, len(data))
                return Response(content=data, headers=headers, media_type="application/octet-stream")
            else:
                self.activeSessions.pop(sid)
                self.authFails.Hit("*")
                await asyncio.sleep(min(1 + 0.2 * self.authFails.Count("*"), 10))
                raise KeyLacksPermissionError("Key dosen't have enough permissions or dosen't match")


        except ContentTooLarge:
            return Response(status_code=413)
        except (KeyError, ValueError, ParsingError, HandshakeError, ReplayError, InvalidTag, MalformedHeader, TamperedPackage) as e:
            self.Error(str(e))
            return Response(status_code=400)
        except KeyLacksPermissionError:
            return Response(status_code=403)
