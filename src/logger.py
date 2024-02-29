import logging

class Logger:


    def __init__(self, verbosity: bool, name: str):
        self._verbosity = verbosity
        logging.basicConfig(level=logging.DEBUG,
        format="%(asctime)s : [%(levelname)s] : %(message)s",
        filename=name+".log",
        filemode="w",
    )

    def info(self,addr,msg):
        if self._verbosity:
            logging.info("["+addr+"] "+msg)

    def debug(self,addr,msg):
        if self._verbosity:
            logging.debug("["+addr+"] "+msg)
    
    def warning(self,addr,msg):
        if self._verbosity:
            logging.warning("["+addr+"] "+msg)
    def error(self,addr,msg):
        if self._verbosity:
            logging.error("["+addr+"] "+msg)
        