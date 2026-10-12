import hashlib
from cryptography.exceptions import InvalidTag

HELLO_REPLY_FORMAT = {
    "F":          {"type": bytes, "len": 32, "required": True},
    "session_id": {"type": bytes, "len": 16, "required": True},
    "ok":         {"type": bytes, "len": 18, "required": True},   # b"ok" + 16-byte tag
}

async def Init(self) -> bool:
    S_bytes = self.serverConstPubKey
    S_pub = X25519PublicKey.from_public_bytes(S_bytes)
    key_id = hashlib.blake2b(S_bytes, digest_size=8).digest()
    proto = self._version.encode("utf-8")

    for attempt in range(3):
        e = X25519PrivateKey.generate()
        E = e.public_key().public_bytes(serialization.Encoding.Raw,
                                        serialization.PublicFormat.Raw)
        es = e.exchange(S_pub)

        hello = {                                    # fresh dict per attempt
            "protocol": self._version,
            "server_key_id": base64.b64encode(key_id).decode(),
            "E": base64.b64encode(E).decode(),
        }

        # 1) network part: retry on failure
        try:
            resp = await asyncio.to_thread(requests.post, f"{self.serverUrl}/handshake",
                                           json=hello, timeout=self.timeoutTime)
            resp.raise_for_status()
        except requests.RequestException as ex:
            self.failedRequests += 1
            self.Error(str(ex))
            continue

        # 2) crypto part: no retry, a failure here means wrong key or tampering
        try:
            reply = parse(resp.json(), HELLO_REPLY_FORMAT)
            F = reply["F"]
            ee = e.exchange(X25519PublicKey.from_public_bytes(F))
            c2s, s2c = derive_keys(es + ee, proto + key_id + E + F + S_bytes)
            session = Session(send_key=c2s, recv_key=s2c)
            if session.decrypt(reply["ok"]) != b"ok":
                raise HandshakeError
        except (HandshakeError, InvalidTag, ValueError):
            self.Error("handshake failed")
            return False

        self.session = session
        self.sessionId = reply["session_id"]
        self.isOnline = True
        self.failedRequests = 0
        self.emit("ashtp_server_status_changed", True)
        return True                                  # e and es die with this function

    return False