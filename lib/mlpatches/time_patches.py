import time

from mlpatches import base


class ClockPatch(base.FunctionPatch):
    """patch for os.listdir()"""

    PY3 = True
    module = "time"
    function = "clock"
    replacement = time.perf_counter


CLOCK_PATCH = ClockPatch()
