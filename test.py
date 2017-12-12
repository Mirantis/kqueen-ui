import logging

logger = logging.getLogger(__name__)


def a():
    test = 'kokot'
    return b()

def b():
    test = 'hovno'
    print('B')
    logger.error(str(locals()), stack_info=True)

a()
