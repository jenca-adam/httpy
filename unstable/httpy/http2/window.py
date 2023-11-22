from .error import FLOW_CONTROL_ERROR

# i totally didn't steal this from h2


class Window:
    def __init__(self, max_window_size):
        self.size = max_window_size
        self.max_window_size = max_window_size

    def increase_size(self, si):
        self.size += si
        self.max_window_size = max(self.max_window_size, self.size)
        if self.size > 2**31 - 1:
            raise FLOW_CONTROL_ERROR("Flow control window too large")

    def received_frame(self, f):
        print(self.size)
        self.size -= f
        print(self.size)
        if self.size < 0:
            raise FLOW_CONTROL_ERROR("No space left in the window.")
        # return self.window_update()

    def process(self, nbytes):
        if nbytes == 0:
            return 0
        max_increment = self.max_window_size - self.size

        increment = 0

        if ((self.size == 0) and (nbytes > self.max_window_size // 4)) or (
            nbytes >= self.max_window_size // 2
        ):
            increment = min(nbytes, max_increment)

        return increment
