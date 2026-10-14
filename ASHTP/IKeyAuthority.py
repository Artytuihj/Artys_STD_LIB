from abc import ABC, abstractmethod

class IKeyAuthority(ABC):
    @property
    @abstractmethod
    def minPermissionLevel(self) -> int: ...

    @abstractmethod
    async def CheckPerms(self, apiKey: str) -> int:
        """
        Look up an API key.

        Returns:
            -1   the key was revoked
             0   the key is not registered
            >0   the key is valid (the number is the permission level of the key (if implemented) )
        """


