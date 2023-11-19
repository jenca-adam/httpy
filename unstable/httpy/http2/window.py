from .error import FLOW_CONTROL_ERROR
class Window:
    def __init__(self):
        self.size=0
        self._processed=0
    def increase_size(self,si):
        self.size+=si
        if self.size>2**31-1:
            raise FLOW_CONTROL_ERROR("Flow control window too large")
    def received_frame(self,f):
        self.size-=f.payload_length
        if self.size<0:
            raise FLOW_CONTROL_ERROR("No space left in the window.")
        #return self.window_update()
    """def window_update(self):
        if self.size<=self.max_window_size:
            return (self.max_window_size-size)"""

        
