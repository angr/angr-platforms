from angr_platforms.X86_16.analysis.alias import MemRange, Storage, may_alias, overlap, storage_of
from angr_platforms.X86_16.ir.core import AddressStatus, IRAddress, IRValue, MemSpace


def test_storage_of_ignores_const_and_tmp_values():
    assert storage_of(IRValue(MemSpace.CONST, const=1)) is None
    assert storage_of(IRValue(MemSpace.TMP, name="t1")) is None


def test_storage_of_address_preserves_base_tuple_and_size():
    storage = storage_of(IRAddress(MemSpace.DS, base=("bx", "si"), offset=2, size=4, status=AddressStatus.PROVISIONAL))

    assert storage == Storage(MemSpace.DS, ("bx", "si"), 2, 4)


def test_storage_alias_requires_same_space_base_and_overlapping_ranges():
    left = Storage(MemSpace.DS, ("si",), 2, 2)
    right = Storage(MemSpace.DS, ("si",), 3, 2)
    wrong_space = Storage(MemSpace.SS, ("si",), 2, 2)
    wrong_base = Storage(MemSpace.DS, ("di",), 2, 2)

    assert may_alias(left, right) is True
    assert may_alias(left, wrong_space) is False
    assert may_alias(left, wrong_base) is False


def test_overlap_requires_same_segment_and_base_tuple():
    left = MemRange(MemSpace.SS, ("bp",), -6, 4)
    overlap_right = MemRange(MemSpace.SS, ("bp",), -4, 2)
    separate_right = MemRange(MemSpace.SS, ("bp",), 4, 2)
    other_space = MemRange(MemSpace.DS, ("bp",), -4, 2)

    assert overlap(left, overlap_right) is True
    assert overlap(left, separate_right) is False
    assert overlap(left, other_space) is False
