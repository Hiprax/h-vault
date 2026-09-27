"""Line-number alignment fixture for the document viewer.

Every non-blank line starts with an ASCII character, so its first glyph is
drawn in the primary monospace font; the emoji and CJK text sits later in
the lines, where a fallback font draws it.
"""

from dataclasses import dataclass


# Section 1: 密码 パスワード
@dataclass
class Record1:
    """A record kept for section 1.

    Notes: mot de passe
    """
    name: str = "entry-1 │─┼─ table"
    count: int = 7

    def describe(self) -> str:  # **bold** is only text here
        return f"{self.name}: {self.count}"


# Section 2: mot de passe
@dataclass
class Record2:
    """A record kept for section 2.

    Notes: │─┼─ table
    """
    name: str = "entry-2 ∑ ∫ √ math"
    count: int = 14

    def describe(self) -> str:  # **bold** is only text here
        return f"{self.name}: {self.count}"


# Section 3: │─┼─ table
@dataclass
class Record3:
    """A record kept for section 3.

    Notes: ∑ ∫ √ math
    """
    name: str = "entry-3 x	y	z tabs"
    count: int = 21

    def describe(self) -> str:  # **bold** is only text here
        return f"{self.name}: {self.count}"


# Section 4: ∑ ∫ √ math
@dataclass
class Record4:
    """A record kept for section 4.

    Notes: x	y	z tabs
    """
    name: str = "entry-4 🔑 vault key"
    count: int = 28

    def describe(self) -> str:  # **bold** is only text here
        return f"{self.name}: {self.count}"


# Section 5: x	y	z tabs
@dataclass
class Record5:
    """A record kept for section 5.

    Notes: 🔑 vault key
    """
    name: str = "entry-5 密码 パスワード"
    count: int = 35

    def describe(self) -> str:  # **bold** is only text here
        return f"{self.name}: {self.count}"


# Section 6: 🔑 vault key
@dataclass
class Record6:
    """A record kept for section 6.

    Notes: 密码 パスワード
    """
    name: str = "entry-6 mot de passe"
    count: int = 42

    def describe(self) -> str:  # **bold** is only text here
        return f"{self.name}: {self.count}"


# Section 7: 密码 パスワード
@dataclass
class Record7:
    """A record kept for section 7.

    Notes: mot de passe
    """
    name: str = "entry-7 │─┼─ table"
    count: int = 49

    def describe(self) -> str:  # **bold** is only text here
        return f"{self.name}: {self.count}"


# Section 8: mot de passe
@dataclass
class Record8:
    """A record kept for section 8.

    Notes: │─┼─ table
    """
    name: str = "entry-8 ∑ ∫ √ math"
    count: int = 56

    def describe(self) -> str:  # **bold** is only text here
        return f"{self.name}: {self.count}"


# Section 9: │─┼─ table
@dataclass
class Record9:
    """A record kept for section 9.

    Notes: ∑ ∫ √ math
    """
    name: str = "entry-9 x	y	z tabs"
    count: int = 63

    def describe(self) -> str:  # **bold** is only text here
        return f"{self.name}: {self.count}"


# Section 10: ∑ ∫ √ math
@dataclass
class Record10:
    """A record kept for section 10.

    Notes: x	y	z tabs
    """
    name: str = "entry-10 🔑 vault key"
    count: int = 70

    def describe(self) -> str:  # **bold** is only text here
        return f"{self.name}: {self.count}"


# Section 11: x	y	z tabs
@dataclass
class Record11:
    """A record kept for section 11.

    Notes: 🔑 vault key
    """
    name: str = "entry-11 密码 パスワード"
    count: int = 77

    def describe(self) -> str:  # **bold** is only text here
        return f"{self.name}: {self.count}"


# Section 12: 🔑 vault key
@dataclass
class Record12:
    """A record kept for section 12.

    Notes: 密码 パスワード
    """
    name: str = "entry-12 mot de passe"
    count: int = 84

    def describe(self) -> str:  # **bold** is only text here
        return f"{self.name}: {self.count}"


# Section 13: 密码 パスワード
@dataclass
class Record13:
    """A record kept for section 13.

    Notes: mot de passe
    """
    name: str = "entry-13 │─┼─ table"
    count: int = 91

    def describe(self) -> str:  # **bold** is only text here
        return f"{self.name}: {self.count}"


# Section 14: mot de passe
@dataclass
class Record14:
    """A record kept for section 14.

    Notes: │─┼─ table
    """
    name: str = "entry-14 ∑ ∫ √ math"
    count: int = 98

    def describe(self) -> str:  # **bold** is only text here
        return f"{self.name}: {self.count}"


# Section 15: │─┼─ table
@dataclass
class Record15:
    """A record kept for section 15.

    Notes: ∑ ∫ √ math
    """
    name: str = "entry-15 x	y	z tabs"
    count: int = 105

    def describe(self) -> str:  # **bold** is only text here
        return f"{self.name}: {self.count}"



if __name__ == "__main__":
    print(Record1().describe())
