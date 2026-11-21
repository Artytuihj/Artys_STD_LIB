import asyncio
import base64
import json
import random
import struct
import tempfile
import zipfile
from pathlib import Path
from typing import Iterator
import shutil

from charset_normalizer import from_path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from requests import Response
from fastapi import Request

from artystd.ashtp import TMP, CHUNK_SIZE_LIMIT, FILE_SIZE_LIMIT, JSON_PACKAGE_SIZE_LIMIT, FILE_PACKAGE_SIZE_LIMIT, \
    EXTRACT_RESULTS
from artystd.ashtp.ASHTPEnums import ContentType, BaseHeaders
from artystd.ashtp.ASHTPExceptions import ContentTooLarge, HandshakeError, ParsingError, MalformedHeader, \
    TamperedPackage
from artystd.ashtp.Session import Session

_HDR = struct.Struct(">QI") # the header template


def _SafeUnzip(path: Path, dest: Path):
    dest = dest.resolve()
    try:
        with zipfile.ZipFile(path) as zf:
            if (bad := zf.testzip()) is not None:
                raise TamperedPackage(f"Package was tampered with or is corrupted: {bad}")

            for file in zf.infolist():
                target = (dest / file.filename).resolve()
                if not target.is_relative_to(dest):
                    raise TamperedPackage(f"Zip-Slip detected at file: {file.filename} to {target}")

            zf.extractall(dest)

    except Exception as e:
        shutil.rmtree(dest, ignore_errors=True)  # delete the leftovers
        if isinstance(e, zipfile.BadZipFile):
            raise TamperedPackage("Package is not a valid zip file") from e
        raise

def _CheckSize(chk: bytes, ttl) -> int:
    if len(chk) > CHUNK_SIZE_LIMIT:
        raise ContentTooLarge("Received chunk size exceeded the limit")
    ttl += len(chk)
    if ttl > FILE_SIZE_LIMIT:
        raise ContentTooLarge("File size exceeded the limit")
    return ttl

class ASHTPBase:

    @classmethod
    async def ReadBody(cls, req: Request | Response, session: Session, sessionId: bytes, ref: int | None = None) -> dict:
        """
        Takes a Request item and unpacks + decrypts it into usable data

        :param req:
        :param session:
        :param sessionId:
        :param ref: counter of the request this body is an answer to (replies only, None when reading a request)
        :return: json -> the dict itself, streams -> {"file": <extracted dir>, "meta": <first frame>}
        """

        contentSize = req.headers.get(BaseHeaders.SIZE)
        contentType = req.headers.get(BaseHeaders.CONTENT_TYPE)
        chunkSize = req.headers.get(BaseHeaders.CHUNK_SIZE)
        counter = req.headers.get(BaseHeaders.COUNTER)

        tmpFileName = random.randbytes(20).hex()

        reqType = "req" if isinstance(req, Request) else "resp"

        method = req.method if reqType == "req" else req.request.method
        url = str(req.url)

        try:
            contentSize = int(contentSize)
            contentType = ContentType(str(contentType))
            chunkSize = int(chunkSize)
            counter = int(counter)
        except (ValueError, TypeError):
            raise ParsingError("Received an unexpected header value")

        if contentType.isStream:
            # ============STREAM=============
            total = 0
            written = 0
            meta = None

            if chunkSize > CHUNK_SIZE_LIMIT or contentSize > FILE_SIZE_LIMIT:
                raise ContentTooLarge("File or Chunk size exceeded the limit")

            def _Handle(f, n: int, chunk: bytes):
                nonlocal total, written, meta
                total = _CheckSize(chunk, total)
                plain = cls.TearOpen(chunk, method, url, n, session, sessionId, ref)
                if meta is None:
                    try:
                        meta = json.loads(plain)
                    except ValueError:
                        raise ParsingError("Stream metadata frame is not valid json")
                    if not isinstance(meta, dict):
                        raise ParsingError("Stream metadata frame is not a dict")
                    return
                f.write(plain)
                written += len(plain)

            def _WriteRespStream(f):
                for n, chunk in cls.DeFrame(req.iter_content(chunk_size=chunkSize)):
                    _Handle(f, n, chunk)

            with tempfile.TemporaryDirectory(dir=TMP) as td:
                pathToTmpFile = Path(td) / tmpFileName
                with open(pathToTmpFile, "wb") as f:
                    if reqType == "req":
                        async for n, chunk in cls.AsyncDeFrame(req.stream()):
                            _Handle(f, n, chunk)

                    elif reqType == "resp":
                        await asyncio.to_thread(_WriteRespStream, f)
                    else:
                        raise ParsingError("Fym u ran out of options... HOW!?")

                if meta is None:
                    raise MalformedHeader("Stream carried no frames")

                if written != contentSize:
                    raise TamperedPackage(f"Stream size mismatch: header said {contentSize}, received {written}")

                outputPath = EXTRACT_RESULTS / tmpFileName
                await asyncio.to_thread(_SafeUnzip, pathToTmpFile, outputPath)
                return {"file": str(outputPath), "meta": meta}  # EDIT [B3]: meta is needed for user headers / chunk_size
        else:
            data: bytes
            if reqType == "req":
                data = await req.body()
            elif reqType == "resp":
                data = req.content
            if contentType == ContentType.JSON:
                if len(data) > JSON_PACKAGE_SIZE_LIMIT:
                    raise ContentTooLarge("Json size exceeded the limit")

                plain = cls.TearOpen(data, method, url, counter, session, sessionId, ref)
                try:
                    notSoPlain = json.loads(plain)
                except ValueError:
                    raise ParsingError("Couldnt parse bytes into json ")

                return notSoPlain
            elif contentType == ContentType.SMALL_FILE:
                if len(data) > FILE_PACKAGE_SIZE_LIMIT:
                    raise ContentTooLarge("Small File size exceeded the limit")

                plain = cls.TearOpen(data, method, url, counter, session, sessionId, ref)

                with tempfile.TemporaryDirectory(dir=TMP) as td:
                    pathToTmpFile = Path(td) / tmpFileName
                    with open(pathToTmpFile, "wb") as f:
                        f.write(plain)

                    outputPath = EXTRACT_RESULTS / tmpFileName

                    await asyncio.to_thread(_SafeUnzip, pathToTmpFile, outputPath)
                    return {"file": str(outputPath)}
            else:
                raise ParsingError("Tried Using non existant content type lmao")

    @classmethod
    def DeriveKeys(cls, secret: bytes, transcrypt: bytes, length: int = 64) -> tuple[bytes, bytes]:
        """
        Derives keys... there isnt much else to say :|

        :param secret:
        :param transcrypt:
        :param length:
        :return:
        """
        symKey = HKDF(algorithm=hashes.SHA256(), length=length, salt=None,
                      info=b"ashtp sym sesscion key" + transcrypt).derive(secret)
        return symKey[32:], symKey[:32]

    @classmethod
    def Aad(cls, sid:bytes, method:str, endpoint:str, ref:int|None = None) -> bytes:
        """
        Generates the encryption tag/aad

        :param sid:
        :param method:
        :param endpoint:
        :param ref:
        :return:
        """
        if not endpoint.startswith("/"):
            endpoint = "/" + endpoint
        a = sid + method.upper().encode() + b" " + endpoint.encode()
        if ref is not None:
            a += b" " + ref.to_bytes(8, "little")  # fixed width at the end, so unambiguous
        return a

    @classmethod
    def TearOpen(cls, msg:bytes, method:str, path:str, serverCount:int, session:Session, sessionId:bytes, ref:int|None = None) -> bytes:
        """
        Turns encrypted byte data into just byte data

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

        return plain

    @classmethod
    def Seal(cls, msg:dict|bytes, method:str, path:str,session:Session, sessionId:bytes, ref:int|None = None) -> tuple[bytes, int]:
        """ Turns unencrypted JSON into request ready data

        :param ref:
        :param sessionId:
        :param session:
        :param msg:
        :param method:
        :param path:
        :return:
        """


        if isinstance(msg, (bytes, bytearray)):
            plain = bytes(msg)
        else:
            plain = json.dumps(msg).encode()

        tag = ASHTPBase.Aad(sessionId, method, path, ref=ref)
        n, data = session.Encrypt(plain, tag)

        return data, n

    @classmethod
    def Parse(cls, msg: dict, template: dict)-> dict:
        """
        takes a dict and compares it to a template

        :param msg:
        :param template:
        :return:
        """
        if not isinstance(msg, dict) or set(msg) - set(template):
            raise ParsingError("msg inst a dict or has forbidden fields")
        output = {}

        for name , spec in template.items():
            if name not in msg:
                if spec["required"]:
                    raise ParsingError("msg is missing keys defined in template")
                continue
            value = msg[name]
            if spec["type"] is bytes:
                try:
                    value = base64.b64decode(value, validate=True)
                except Exception:
                    raise ParsingError(f"{name} isn't bytes or the field is corrupted")

                if len(value) != spec["len"]:
                    raise ParsingError(f"{name} dosen't match length target")
            elif not isinstance(value, spec["type"]):
                raise ParsingError(f"{name} dosen't match type")
            output[name] = value
        return output

    @classmethod
    def Frame(cls, gen):
        """
        adds a frame around every chunk with its metadata

        :param gen: iterator of (sealed chunk, counter used to seal it) -> what SealFileStream yields
        :return:
        """
        total = 0
        for chunk, n in gen:
            if len(chunk) > CHUNK_SIZE_LIMIT:
                raise ContentTooLarge("Trying to frame a chunk that is bigger than the limit")

            total += len(chunk)
            if total > FILE_SIZE_LIMIT:
                raise ContentTooLarge("Can not frame past file size limit")

            yield _HDR.pack(n, len(chunk)) + chunk

    @classmethod
    def _PopFrames(cls, buf: bytearray, total: int) -> tuple[list[tuple[int, bytes]], int]:
        """
        Cuts every complete frame out of buf (in place) and leaves a partial one for the next call

        :param buf: bytes received so far and not consumed
        :param total: payload bytes already de-framed in this stream
        :return: the frames + the new running total
        """
        frames = []
        while len(buf) >= _HDR.size:
            n, lng = _HDR.unpack_from(buf)

            if lng > CHUNK_SIZE_LIMIT:
                raise ContentTooLarge("Trying to de-frame a chunk which header states to be too big")

            if len(buf) < _HDR.size + lng:
                break  # rest of the frame hasn't arrived yet

            total += lng
            if total > FILE_SIZE_LIMIT:
                raise ContentTooLarge("Can not de-frame past file size limit")

            frames.append((n, bytes(buf[_HDR.size:_HDR.size + lng])))
            del buf[:_HDR.size + lng]
        return frames, total

    @classmethod
    def DeFrame(cls, gen):
        """
        Destructure a frame around every chunk

        :param gen: iterator of raw byte pieces as they came off the wire
        :return:
        """
        total = 0
        buf = bytearray()
        for piece in gen:
            buf += piece
            frames, total = cls._PopFrames(buf, total)
            yield from frames
        if buf:
            raise MalformedHeader("Stream ended in the middle of a frame")

    @classmethod
    async def AsyncDeFrame(cls, gen):
        """
        Destructure a frame around every chunk

        :param gen: async iterator of raw byte pieces as they came off the wire
        :return:
        """
        total = 0
        buf = bytearray()
        async for piece in gen:
            buf += piece
            frames, total = cls._PopFrames(buf, total)
            for frame in frames:
                yield frame
        if buf:
            raise MalformedHeader("Stream ended in the middle of a frame")

    @classmethod
    def PackZip(cls, src: Path, destDir: Path) -> Path:
        """
        Zips a file or a folder into destDir

        :param src: file or folder to pack
        :param destDir: where the zip is written, caller owns the cleanup
        :return: path of the zip
        """
        zipPath = destDir / f"{src.name}.zip"
        with zipfile.ZipFile(zipPath, "w", zipfile.ZIP_DEFLATED) as zf:
            if src.is_file():
                zf.write(src, arcname=src.name)
            else:
                for file in src.rglob("*"):
                    if file.is_dir():
                        zf.write(file, arcname=str(file.relative_to(src)) + "/")
                    else:
                        zf.write(file, arcname=file.relative_to(src))
        return zipPath

    @classmethod
    def SealFileStream(cls, meta:dict, zipPath:Path, method:str, path:str, session:Session, sessionId:bytes, chunkSize:int=65*1024, ref:int|None = None) -> Iterator[tuple[bytes, int]]:  # EDIT [B8]: takes the finished zip (see PackZip) instead of a folder
        """ Turns an unencrypted File into request ready byte stream

        :param chunkSize:
        :param zipPath: zip made with PackZip
        :param meta:
        :param method:
        :param path:
        :param sessionId:
        :param session:
        :param ref:
        :return:
        """

        initialRequest = json.dumps( meta ).encode()

        data, n = cls.Seal(initialRequest, method, path, session, sessionId, ref)
        yield data, n

        with zipPath.open("rb") as f:
            while chunk := f.read(chunkSize):
                data, n = cls.Seal(chunk, method, path, session, sessionId, ref)
                yield data, n

    @classmethod
    def StandardHeaders(cls,contentType:ContentType, sessionId:bytes, counter:int, sendUHeaders:bool, size:int, chunkSize:None|int = None):
        """
        Returns the default Header table that should be attached to every ashtp request

        :param contentType:
        :param sessionId:
        :param counter:
        :param sendUHeaders:
        :param size:
        :param chunkSize:
        :return:
        """

        return{
            f"{BaseHeaders.SESSION}": base64.b64encode(sessionId).decode(),
            f"{BaseHeaders.COUNTER}": str(counter),
            f"{BaseHeaders.CONTENT_TYPE}": str(contentType),
            f"{BaseHeaders.INCL_HEADERS}": "1" if sendUHeaders else "0",
            f"{BaseHeaders.SIZE}":str(size),
            f"{BaseHeaders.CHUNK_SIZE}": str(chunkSize) if chunkSize else "-1"
        }
