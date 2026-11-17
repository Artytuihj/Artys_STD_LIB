from enum import StrEnum

class ContentType(StrEnum):
    SMALL_FILE = "small_file"
    FILE_STREAM = "file_stream"
    JSON = "json"

    @property
    def isStream(self) -> bool:
        return self in (ContentType.FILE_STREAM)


class BaseHeaders(StrEnum):
    SESSION = "ashtp-session"
    COUNTER = "ashtp-counter"
    CONTENT_TYPE = "ashtp-content_type"
    INCL_HEADERS = "ashtp-inc_uheaders"
    SIZE = "ashtp-size"
    CHUNK_SIZE = "ashtp-chunk_size"
