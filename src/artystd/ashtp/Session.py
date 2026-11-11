from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from artystd.ashtp.ASHTPExceptions import ReplayError


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