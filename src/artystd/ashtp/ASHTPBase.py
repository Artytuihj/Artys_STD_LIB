import base64
import json
import struct
import tempfile
import zipfile
from pathlib import Path
from typing import Iterator

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from requests import Request

from artystd.ashtp import TMP
from artystd.ashtp.ASHTPExceptions import BodyTooLarge, HandshakeError, ParsingError
from artystd.ashtp.Session import Session


class ASHTPBase:
    @classmethod
    async def ReadBody(cls, req: Request, limit: int) -> tuple[bytes, dict]:
        cl = req.headers.get("content-length")
        if cl is not None and int(cl) > limit:
            raise BodyTooLarge
        buf = bytearray()
        async for chunk in req.stream():
            buf += chunk
            if len(buf) > limit:
                raise BodyTooLarge
        return bytes(buf), dict(req.headers)

    @classmethod
    def DeriveKeys(cls,secret: bytes, transcrypt: bytes, length: int = 64) -> tuple[bytes, bytes]:
        symKey = HKDF(algorithm=hashes.SHA256(), length=length, salt=None,
                      info=b"ashtp sym sesscion key" + transcrypt).derive(secret)
        return symKey[32:], symKey[:32]

    @classmethod
    def Aad(cls, sid:bytes, method:str, endpoint:str, ref:int|None = None) -> bytes:
        if not endpoint.startswith("/"):
            endpoint = "/" + endpoint
        a = sid + method.upper().encode() + b" " + endpoint.encode()
        if ref is not None:
            a += b" " + ref.to_bytes(8, "little")  # fixed width at the end, so unambiguous
        return a

    @classmethod
    def TearOpen(cls, msg:bytes, method:str, path:str, serverCount:int, session:Session, sessionId:bytes, ref:int|None = None) -> dict:
        """
        Turns encrypted byte data into (hopefuly) a readable piece of JSON

        :param ref:
        :param serverCount:
        :param msg:
        :param method:
        :param path:
        :param session:
        :param sessionId:
        :return:
        """

        if session is None or sessionId is None:
            raise HandshakeError("no active session")

        path = path if path.startswith("/") else "/" + path
        n = serverCount
        tag = ASHTPBase.Aad(sessionId, method, path, ref=ref)
        plain  = session.Decrypt(msg, n, tag)

        return json.loads(plain.decode())

    @classmethod
    def Seal(cls, msg:bytes, method:str, path:str,session:Session, sessionId:bytes, ref:int|None = None) -> tuple[bytes, int]:
        """ Turns unencrypted JSON into request ready data

        :param ref:
        :param sessionId:
        :param session:
        :param msg:
        :param method:
        :param path:
        :return:
        """


        plain = json.dumps(msg).encode()
        tag = ASHTPBase.Aad(sessionId, method, path, ref=ref)
        n, data = session.Encrypt(plain, tag)

        return data, n

    @classmethod
    def Parse(cls, msg: dict, fmt: dict)-> dict:
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

    @classmethod
    def Frame(cls, gen, counter):
        for chunk in gen:
            yield struct.pack(">QI", counter, len(chunk)) + chunk

    @classmethod
    def SealFileStream(cls, meta:dict, filePath:Path, method:str, path:str, session:Session, sessionId:bytes, chunkSize:int=65*1024
                       , ref:int|None = None) -> Iterator[tuple[bytes, int]]:
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

        initialRequest = json.dumps( meta | {"chunk_size": chunkSize} ).encode()
        with tempfile.TemporaryDirectory(dir=TMP) as td: # niche thing i like

            zipPath = Path(td) / f"{filePath.name}.zip"
            with zipfile.ZipFile(zipPath, "w", zipfile.ZIP_DEFLATED) as zf:
                for file in filePath.rglob("*"):
                    if file.is_dir():
                        zf.write(file, arcname=str(file.relative_to(filePath)) + "/")
                    else:
                        zf.write(file, arcname=file.relative_to(filePath))

            data, n = cls.Seal(initialRequest, method, path, session, sessionId, ref)
            yield data, n

            with zipPath.open("rb") as f:
                while chunk := f.read(chunkSize):
                    data, n = cls.Seal(chunk, method, path, session, sessionId, ref)
                    yield data, n