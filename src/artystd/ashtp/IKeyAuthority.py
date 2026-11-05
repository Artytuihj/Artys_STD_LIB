from abc import ABC, abstractmethod

class IKeyAuthority(ABC):
    @property
    @abstractmethod
    def minPermissionLevel(self) -> int: ...

    @abstractmethod
    async def CheckPerms(self, apiKey: str) -> tuple[bool, int, str]:
        """
        Look up an API key.
        Defined as async because DB lookup is expected.

        Returns:
            bool : whether the key meets minimum permission limit,
            int : permission level of the key,
            name : the username under which the key is registered

        :param apiKey: The key of the client used to identify it
        :returns:
        """

    @abstractmethod
    def ComparePermissions(self, clientPerm: int, requiredPerm: int) -> bool:
        """
        Decide whether a client's permission level satisfies a required level.

        What "satisfies" means depends on the application, so subclasses define it.

        :param clientPerm: The permission level of the client making the request.
        :param requiredPerm: The permission level the action requires.
        :return: True if the client is allowed, False if not.
        """

