from static import STATIC_TABLE
class Entry:
    def __init__(self,name,value=None):
        self.name=name
        if isinstance(value,list):
            value=value[0]
        self.value=value
    @property
    def size(self):
        return len(self.name)+len(self.value or "")+32
    def __repr__(self):
        return f"{self.name}{': ' if self.value else ''}{self.value or ''}"
class Table:
    def __init__(self,max_size=4096):
        self.static_table=[]
        self.dynamic_table=[]
        self.size=0
        self.max_size=max_size
        self._loadstatic(STATIC_TABLE)
    def _loadstatic(self,tab):
        if self.static_table or self.dynamic_table or self.size:
            raise RuntimeError("_loadstatic can't be called after the table has been changed")
        self.static_table=[None for _ in range(max(i[0] for i in tab)+1)] # "allocate" static_table with Nones
        for ix,k,*v in tab:
            self.static_table[ix] = Entry(k, v or None)

    def append(self,entry):
        if entry.size>self.max_size: 
            self.dynamic_table=[]
            self.size=0
        self.size+=entry.size
        while self.size>self.max_size:
            self.size-=self.dynamic_table[0].size
            del self.dynamic_table[0]
        self.dynamic_table.append(entry)
    def change_size(self,new_size):
        while new_size<self.size:
            self.size-=self.dynamic_table[-1].size
            del self.dynamic_table[-1]
        self.max_size=new_size
    def __getitem__(self,index):
        if index<len(self.static_table):
            table=self.static_table
            qtab="static"
        else:
            qtab="dynamic"
            table=self.dynamic_table
            index-=len(self.static_table)
        if index>len(table)-1:
            raise IndexError(
                    f"Index {index}({hex(index)}) of the {qtab} table out of range. {qtab} table size: {len(table)}"
                    )
        elif table[index] is None:
            raise IndexError(
                    f"Index {index}({hex(index)}) of the {qtab} table was not set."
                    )
        return table[index]
