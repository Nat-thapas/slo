"""
Compatibility layer for Python 3.8
(The application was originally developed for Python 3.13 because I thought 3.13 is considered 3.8+ but apparently not)
"""

import bisect as bisect_module
import random
from typing import Any, Callable, Generic, List, Protocol, Sequence, TypeVar


class SupportsRichComparison(Protocol):
    def __lt__(self, __other: Any) -> bool: ...
    def __gt__(self, __other: Any) -> bool: ...


ItemType = TypeVar("ItemType")
ReturnType = TypeVar("ReturnType")
ValueType = TypeVar("ValueType", bound=SupportsRichComparison)


class KeyWrapper(Generic[ItemType, ReturnType]):
    def __init__(self, iterable: Sequence[ItemType], key: Callable[[ItemType], ReturnType]) -> None:
        self.it = iterable
        self.key = key

    def __getitem__(self, i: int) -> ReturnType:
        return self.key(self.it[i])

    def __len__(self) -> int:
        return len(self.it)


def bisect_left(list: List[ItemType], val: ValueType, key: Callable[[ItemType], ValueType]) -> int:
    return bisect_module.bisect_left(KeyWrapper(list, key), val)


def bisect_right(list: List[ItemType], val: ValueType, key: Callable[[ItemType], ValueType]) -> int:
    return bisect_module.bisect_right(KeyWrapper(list, key), val)


def bisect(list: List[ItemType], val: ValueType, key: Callable[[ItemType], ValueType]) -> int:
    return bisect_module.bisect(KeyWrapper(list, key), val)


def randbytes(n: int) -> bytes:
    return random.getrandbits(n * 8).to_bytes(n, "little")
