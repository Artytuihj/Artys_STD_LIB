import logging

class ArtysLogger:

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        filename="app.log"
    )

    @classmethod
    def getLog(cls,name):
        return logging.getLogger(name)

