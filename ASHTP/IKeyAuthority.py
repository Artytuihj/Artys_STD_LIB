from abc import ABC, abstractmethod

class IKeyAuthority(ABC):
    @property
    @abstractmethod
    def minPermissionLevel(self) -> int: ...

    @abstractmethod
    def CheckPerms(self, apiKey: str) -> tuple[int, str]:
        """
        Look up an API key.

        Returns:
            -1   the key is invalid
             0   the key is system/admin
            >0   any other permission
        and the name of the key
        """


