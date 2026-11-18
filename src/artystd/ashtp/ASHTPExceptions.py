#lwkey kinda sad i need this many errors wtf
class HandshakeError(Exception):
    pass
class ParsingError(Exception):
    pass
class ReplayError(Exception):
    pass
class ContentTooLarge(Exception):
    pass
class ErrorHandlingError(Exception): #tf
    pass
class ClientTooOldError(Exception):
    pass
class KeyLacksPermissionError(Exception):
    pass
class ASHTPGeneralException(Exception):
    pass
class MalformedHeader(Exception):
    pass
class TamperedPackage(Exception):
    pass