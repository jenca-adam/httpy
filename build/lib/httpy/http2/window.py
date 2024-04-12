from .error import FLOW_CONTROL_ERROR

# i totally didn't steal this from h2


class Window:
    def __init__(self, max_window_size):
        self.size = max_window_size
        self.max_window_size = max_window_size
        self._processed_since_update = 0

    def increase_size(self, si):
        self.size += si
        self.max_window_size = max(self.max_window_size, self.size)
        if self.size > 2**31 - 1:
            raise FLOW_CONTROL_ERROR("Flow control window too large")

    def update_max_window_size(self, new_size):
        if self.new_size == self.max_window_size:
            return
        self.max_window_size = new_size
        self.size = min(self.size, self.max_window_size)

    def received_frame(self, f):
        self.size -= f
        if self.size < 0:
            raise FLOW_CONTROL_ERROR("No space left in the window.")
        # return self.window_update()

    def process(self, nbytes):
        self._processed_since_update += nbytes
        if nbytes == 0:
            return 0
        max_increment = self.max_window_size - self.size

        increment = 0

        if self._processed_since_update > min(self.max_window_size // 2, 8192):
            increment = max_increment
            self._processed_since_update = 0
        self.increase_size(increment)
        return increment
