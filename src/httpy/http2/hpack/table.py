from .static import STATIC_TABLE
from httpy.utils import force_string


class Entry:
    """
    A HPACK table entry.
    """

    def __init__(self, name, value=None):
        self.name = force_string(name)
        if isinstance(value, list):
            value = value[0]
        if value is not None:
            value = force_string(value)
        self.value = value

    def __eq__(self, i):
        if isinstance(i, str):
            return i.lower() == self.name.lower()
        elif isinstance(i, self.__class__):
            return i.name.lower() == self.name.lower() and i.value == self.value
        return False

    @property
    def size(self):
        return len(self.name) + len(self.value or "") + 32

    def __repr__(self):
        return f"{self.name}{': ' if self.value else ''}{self.value or ''}"


class Table:
    """
    A HPACK table implementation
    """

    def __init__(self, max_size=4096):
        self.static_table = []
        self.dynamic_table = []
        self.size = 0
        self.max_size = max_size
        self._loadstatic(STATIC_TABLE)

    def _loadstatic(self, tab):
        if self.static_table or self.dynamic_table or self.size:
            raise RuntimeError(
                "_loadstatic can't be called after the table has been changed"
            )
        self.static_table = [
            None for _ in range(max(i[0] for i in tab) + 1)
        ]  # "allocate" static_table with Nones
        for ix, k, *v in tab:
            self.static_table[ix] = Entry(k, v or None)

    def add(self, entry):
        """
        Adds an entry to the dynamic table
        """
        if entry.size > self.max_size:
            self.dynamic_table = []
            self.size = 0
        self.size += entry.size
        while self.size > self.max_size:
            self.size -= self.dynamic_table[-1].size
            del self.dynamic_table[-1]
        self.dynamic_table.insert(0, entry)

    def change_size(self, new_size):
        """
        Changes the dynamic table size by removing items
        """
        while new_size < self.size:
            self.size -= self.dynamic_table[-1].size
            del self.dynamic_table[-1]
        self.max_size = new_size

    def find_item(self, item):
        """
        Returns the index of an item in the table
        """
        if not isinstance(item, Entry):
            item = force_string(item)
        if item in self.static_table:
            return self.static_table.index(item)
        elif item in self.dynamic_table:
            return self.dynamic_table.index(item) + len(self.static_table)
        # else none

    def __contains__(self, item):
        item = force_string(item)
        return item in self.static_table or item in self.dynamic_table

    def __getitem__(self, index):
        if index < len(self.static_table):
            table = self.static_table
            qtab = "static"
        else:
            qtab = "dynamic"
            table = self.dynamic_table
            index -= len(self.static_table)
        if index > len(table) - 1:
            raise IndexError(
                f"Index {index}({hex(index)}) of the {qtab} table out of range. {qtab} table size: {len(table)}"
            )
        elif table[index] is None:
            raise IndexError(
                f"Index {index}({hex(index)}) of the {qtab} table was not set."
            )
        return table[index]
