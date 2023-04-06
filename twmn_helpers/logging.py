#!/usr/bin/env python

"""Contains custom logging classes that add color and more log levels.
This module comes from Nikolaos Kakouros' cheat detection system :
https://kth.diva-portal.org/smash/record.jsf?aq2=%5B%5B%5D%5D&c=29&af=%5B%5D&searchType=LIST_LATEST&sortOrder2=title_sort_asc&query=&language=no&pid=diva2%3A1477521&aq=%5B%5B%5D%5D&sf=all&aqe=%5B%5D&sortOrder=author_sort_asc&onlyFullText=false&noOfRows=50&dswid=-116
"""
#initial

import copy
import logging
import os
from pprint import pformat
from typing import Any

# The background is set with 40 plus the number of the color, and the foreground with 30
# These are the sequences need to get colored ouput.
RESET_SEQ = "\033[0m"
COLOR_SEQ = "\033[0;%dm"
BOLD_SEQ = "\033[1m"

BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)

COLORS = {
    "WARNING": MAGENTA,
    "INFO": YELLOW,
    "DEBUG": BLUE,
    "DEBUGV": CYAN,
    "CRITICAL": GREEN,
    "ERROR": RED,
}


class ColoredFormatter(logging.Formatter):
    """Custom logging formatter that wraps msgs in color depending on level."""

    def __init__(self, use_color: bool = True) -> None:
        """Create a colored formatter.
        :param use_color: whether to use colorize output
        """
        msg_format = "%(message)s$RESET"
        msg_format = self._ansi_encode(msg_format, use_color)

        super().__init__(msg_format)

        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        """Prepend log message with a color according to the loglevel."""
        record = copy.copy(record)
        if self.use_color and record.levelname in COLORS:
            color = COLOR_SEQ % (30 + COLORS[record.levelname])
            record.msg = f"{color}({record.name}) {record.msg}"

        msg = logging.Formatter.format(self, record)
        return msg

    def _ansi_encode(self, string: str, use_color: bool = True) -> str:
        if use_color:
            string = string.replace("$RESET", RESET_SEQ).replace("$BOLD", BOLD_SEQ)
        else:
            string = string.replace("$RESET", "").replace("$BOLD", "")
        return string


DEBUGV = 9
logging.DEBUGV = DEBUGV  # type: ignore
logging.addLevelName(logging.DEBUGV, "DEBUGV")  # type: ignore


class TwmnLogger(logging.Logger):
    """Custom logging class that uses an extra logging level."""

    def __init__(self, name: str) -> None:
        """Create a custom logger.
        :name: The name of the logger to create
        """
        super().__init__(name)

        # Set default logging level to what the user has requested via
        # PYTHON_DEBUG. Doing it here, in the logger itself, instead of creating
        # the logger first, then using its `setLevel` method.
        self.loglevel = os.getenv("PYTHON_DEBUG", "INFO")
        self.loglevel = getattr(logging, self.loglevel.upper(), None)

        if not isinstance(self.loglevel, int):
            raise ValueError("Invalid log level: %s" % self.loglevel)

        # This logger is used by twmn modules. To avoid having output from the
        # modules by default, the logging output is silenced by using
        # a NullHandler. In a `__main__` module, if logging is needed, the
        # `enable_output` method below will add a StreamHandler to output to the
        # terminal. Doing it here, instead of first creating the logger and then
        # using its `addHandler` method.
        self.addHandler(logging.NullHandler())

        if name == "__main__":
            self.enable_output()

    # custom log level
    def debugv(self, message: Any, *args: Any, **kwargs: Any) -> None:
        """Print a DEBUGV level message."""
        if self.isEnabledFor(logging.DEBUGV):  # type: ignore
            self._log(logging.DEBUGV, pformat(message), args, **kwargs)  # type: ignore

    def enable_output(self) -> None:
        """Enable output using a color-enabled console handler.
        The output is disabled by default (the logger uses a `NullHandler`
        handler on creation). The reason is that this Logging class is used in
        twmn modules. Enabling debug output should be a decision for the user of
        the modules and not of the modules themselves. Logging still happens in
        the modules and the user of the modules can decide if they want to see
        the output or not.
        To enable output for a module named `twmn.instance`, the user can do
        `l.getLogger('twmn.instance').enable_output()` where `l` is an instance
        of the Logging class below. Or, they can do
        `l.getLogger('twmn').enable_output()` to enable output for all
        submodules under `twmn`.
        """
        color_formatter = ColoredFormatter()

        console = logging.StreamHandler()
        console.setFormatter(color_formatter)

        self.addHandler(console)
        self.setLevel(self.loglevel)


class Logging:
    """Dummy class to return a ready to use Logger."""

    def __init__(self, name: str) -> None:
        """Create a Logging object that gives indirect access to the Logger."""
        logging.setLoggerClass(TwmnLogger)

        self._logger = logging.getLogger(name)

    def getLogger(  # noqa N802 getLogger is how core `logging` has it
        self, name: str
    ) -> logging.Logger:
        """Proxy the logging.getLogger method that returns a logger object.
        :param name: the name of the logger to return
        """
        return logging.getLogger(name)

    def __getattr__(self, name: str) -> Any:
        """Return the attribute of the logger object as if this were the
        logger."""
        return getattr(self._logger, name)