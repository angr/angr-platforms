class CR:
    def __init__(self):
        self.cr0 = 0
        self.cr1 = 0
        self.cr2 = 0
        self.cr3 = 0
        self.cr4 = 0

    def get_crn(self, n: int) -> int:
        if n == 0:
            return self.cr0
        elif n == 1:
            return self.cr1
        elif n == 2:
            return self.cr2
        elif n == 3:
            return self.cr3
        elif n == 4:
            return self.cr4
        else:
            raise ValueError(f"Invalid CR index: {n}")

    def set_crn(self, n: int, value: int):
        pass

    def is_protected(self) -> bool:
        return False

    def is_ena_paging(self) -> bool:
        return bool(self.cr0 & (1 << 31))  # PG bit

    def get_pdir_base(self) -> int:
        return (self.cr3 >> 12) & 0xFFFFF000  # Page Directory Base
