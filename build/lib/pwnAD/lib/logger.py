import logging
import sys

RESET = '\033[0m'
RED = '\033[31m'
GREEN = '\033[32m'
ORANGE = '\033[33m'
BLUE = '\033[34m'
PURPLE = '\033[35m'
LIGHT_RED = '\033[91m'


class ADSFormatter(logging.Formatter):
  '''
  Prefixing logged messages through the custom attribute 'bullet'.
  '''
  def __init__(self):
      logging.Formatter.__init__(self,'%(bullet)s %(message)s', None)

  def format(self, record):
    if record.levelno == logging.INFO:
      record.bullet = f'[*]'
    elif record.levelno == logging.DEBUG:
      record.bullet = f'[*]'
    elif record.levelno == logging.WARNING:
      record.bullet = f'{ORANGE}[!]{RESET}'
    elif record.levelno == logging.ERROR:
      record.bullet = f'{RED}[-]{RESET}'
    elif record.levelno == logging.CRITICAL:
      record.bullet = f'{LIGHT_RED}[-]{RESET}'
    else:
      record.bullet = f'{PURPLE}[?]{RESET}'  

    return logging.Formatter.format(self, record)


def init():
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(ADSFormatter())

    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.INFO)