# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import sys

def color(text, color_code, readline=False):
    """Colorize text.
    @param text: text.
    @param color_code: color.
    @return: colorized text.
    """
    # $TERM under Windows:
    # cmd.exe -> "" (what would you expect..?)
    # cygwin -> "cygwin" (should support colors, but doesn't work somehow)
    # mintty -> "xterm" (supports colors)
    if sys.platform == "win32" and os.getenv("TERM") != "xterm":
        return text
    if readline:
        # special readline escapes to fix colored input promps
        # http://bugs.python.org/issue17337
        return "\x01\x1b[%dm\x02%s\x01\x1b[0m\x02" % (color_code, text)
    return "\x1b[%dm%s\x1b[0m" % (color_code, text)

def black(text, readline=False):
    return color(text, 30, readline)

def red(text, readline=False):
    return color(text, 31, readline)

def green(text, readline=False):
    return color(text, 32, readline)

def yellow(text, readline=False):
    return color(text, 33, readline)

def blue(text, readline=False):
    return color(text, 34, readline)

def magenta(text, readline=False):
    return color(text, 35, readline)

def cyan(text, readline=False):
    return color(text, 36, readline)

def white(text, readline=False):
    return color(text, 37, readline)

def bold(text, readline=False):
    return color(text, 1, readline)
