# octacrypt/utils/logger.py

import logging


def get_logger(name: str) -> logging.Logger:
    """
    Retorna un logger configurado para OctaCrypt.

    Uso:
        from octacrypt.utils.logger import get_logger
        logger = get_logger(__name__)
        logger.info("Mensaje")
    """
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            "[%(levelname)s] %(name)s: %(message)s"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

    return logger