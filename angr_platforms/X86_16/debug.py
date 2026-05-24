import sys
import traceback

# Constants for debug message types
F_ASSERT = 0
F_ERROR = 1
F_WARN = 2
F_INFO = 3
F_MSG = 4

# Global debug level
debug_level = 0

def debug_print(type, file, function, line, level, fmt, *args):
    """Prints debug messages based on the message type and debug level."""
    typeset = {
        F_ASSERT: ("ASSERT", sys.stderr, True),
        F_ERROR: ("ERROR", sys.stderr, True),
        F_WARN: ("WARN", sys.stderr, False),
        F_INFO: ("INFO", sys.stdout, False),
        F_MSG: (None, sys.stdout, False),
    }

    name, fp, fatal = typeset[type]

    if fatal or (level > 0 and (1 << (level - 1)) & debug_level):
        if name:
            print(f"[{name}{f'_{level}' if level else ''}] ", end="", file=fp)
            print(f"{function} ({file}:{line}) ", end="", file=fp)
        print(fmt % args, file=fp)
        if fatal:
            traceback.print_stack()
            sys.exit(-1)

def ASSERT(cond):
    """Asserts a condition and prints an error message if it fails."""
    if not cond:
        debug_print(F_ASSERT, *traceback.extract_stack()[-2], cond)

def ERROR(fmt, *args):
    """Prints an error message and terminates the program."""
    debug_print(F_ERROR, *traceback.extract_stack()[-2], fmt, *args)

def WARN(fmt, *args):
    """Prints a warning message."""
    debug_print(F_WARN, *traceback.extract_stack()[-2], 0, fmt, *args)

def INFO(level, fmt, *args):
    """Prints an informational message based on the debug level."""
    debug_print(F_INFO, *traceback.extract_stack()[-2], level, fmt, *args)

def DEBUG_MSG(level, fmt, *args):
    """Prints a debug message based on the debug level."""
    debug_print(F_MSG, *traceback.extract_stack()[-2], level, fmt, *args)

def MSG(fmt, *args):
    """Prints a regular message to stdout."""
    print(fmt % args, file=sys.stdout)

def set_debuglv(verbose):
    """Sets the global debug level."""
    global debug_level
    debug_level = int(verbose)
