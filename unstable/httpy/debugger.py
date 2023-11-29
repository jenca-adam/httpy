import inspect
import builtins
import sys

class _Debugger:
    """
    Debugger
    """

    def __init__(self, do_debug=None):
        self._debug = do_debug

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

    def debugging_method(self, suffix):
        def decorated(a, data):
            if a.debug:
                fr = inspect.currentframe().f_back
                class_name = a.frame_class_name(fr)

                sys.stdout.write(self)
                if class_name:
                    sys.stdout.write(class_name)
                sys.stdout.write("[")
                sys.stdout.write(fr.f_code.co_name)
                sys.stdout.write("]")
                sys.stdout.write("(")
                sys.stdout.write(str(inspect.getframeinfo(fr).lineno))
                sys.stdout.write(")")
                sys.stdout.write(": ")
                sys.stdout.write(data)
                sys.stdout.write(suffix)
                sys.stdout.write("\r\n")

        return decorated

    info = debugging_method("\033[94;1m[INFO]", "\033[0m")
    ok = debugging_method("\033[92;1m[OK]", "\033[0m")
    warn = debugging_method("\033[93;1m[WARN]", "\033[0m")
    error = debugging_method("\033[31;1m[ERROR]", "\033[0m")

