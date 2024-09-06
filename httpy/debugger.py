import inspect
import builtins
import sys
import os
from .utils import force_string


def get_path():
    return os.path.dirname(os.path.abspath(__file__))


def _debugprint(debug, what, *args, **kwargs):
    if debug:
        print(force_string(what), *args, **kwargs)


class _Debugger:
    """
    A debugger
    """

    def __init__(self, do_debug=None):
        self._debug = do_debug

    def debugprint(self, *args, **kwargs):
        if self.debug:
            print(*args, **kwargs)

    def frame_class_name(self, fr):
        args, _, _, value_dict = inspect.getargvalues(fr)
        if len(args) and args[0] == "self":
            instance = value_dict.get("self", None)
            if instance:
                return getattr(getattr(instance, "__class__", None), "__name__", None)
        return None

    @property
    def debug(self):
        if self._debug is not None:
            return self._debug
        return getattr(builtins, "debug", False)

    def debugging_method(prefix, suffix):
        def decorated(a, data):
            if a.debug:
                fr = inspect.currentframe().f_back
                class_name = a.frame_class_name(fr)

                sys.stdout.write(prefix)
                if class_name:
                    sys.stdout.write(class_name)
                    sys.stdout.write(".")
                sys.stdout.write(fr.f_code.co_name)
                sys.stdout.write("(")
                sys.stdout.write(os.path.relpath(fr.f_code.co_filename, get_path()))
                sys.stdout.write(":")
                sys.stdout.write(str(inspect.getframeinfo(fr).lineno))
                sys.stdout.write(")")
                sys.stdout.write(": ")
                sys.stdout.write(data)
                sys.stdout.write(suffix)
                sys.stdout.write("\r\n")

        return decorated

    info = debugging_method("[INFO]", "")
    ok = debugging_method("[OK]", "")
    warn = debugging_method("[WARN]", "")
    error = debugging_method("[ERROR]", "")
