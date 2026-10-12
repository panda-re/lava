from typing import Iterable, Sequence, TypeVar
from ..utils.database_types import Dua, Range, LabelSet

T = TypeVar("T")


def disjoint(list1: Sequence[int], list2: Sequence[int]) -> bool:
    """
    Return True if the two sorted sequences have no element in common.
    Both sequences must be sorted in ascending order; sort sets before calling.
    """
    i, j = 0, 0
    len1, len2 = len(list1), len(list2)

    while i < len1 and j < len2:
        if list1[i] < list2[j]:
            i += 1
        elif list2[j] < list1[i]:
            j += 1
        else:
            # list1[i] == list2[j] -> not disjoint
            return False

    return True


def count_nonzero(viable_bytes: list[LabelSet]) -> int:
    """Safely counts non-null / non-zero elements, acting like C++ pointer/int checks."""
    return sum(1 for x in viable_bytes if x is not None)


def merge_into(target_set: set[T], new_labels: Iterable[T]) -> set[T]:
    target_set.update(new_labels)
    return target_set


def get_dua_dead_range(dua: Dua, to_avoid: list[int], liveness: dict[int, int], project_data: dict) -> Range:
    viable_bytes = dua.viable_bytes
    if "nodua" in dua.lval_relationship.ast_name:
        empty = Range(0, 0)
        return empty
    result = get_dead_range(viable_bytes, to_avoid, liveness, project_data)
    return result


def get_dead_range(viable_bytes: list[LabelSet | None], to_avoid: list[int],
                   liveness: dict[int, int], project_data: dict, lava_magic_value_size: int = 4) -> Range:
    # Track the current run using primitive integers instead of a Range object
    current_low = 0
    current_high = 0

    for i in range(len(viable_bytes)):
        byte_viable = True
        label_set = viable_bytes[i]

        if label_set is not None:
            if not disjoint(label_set.labels, to_avoid):
                byte_viable = False
            else:
                for label in label_set.labels:
                    if liveness.get(label, 0) > project_data["max_liveness"]:
                        byte_viable = False
                        break

            if byte_viable:
                # If current run is empty (high <= low), start a new one
                if current_high <= current_low:
                    current_low = i
                    current_high = i + 1
                else:
                    # Extend the current run
                    current_high += 1

                    if (current_high - current_low) >= lava_magic_value_size:
                        break
                continue

        # Reset the run if we hit a non-viable byte or a None label_set
        current_low = 0
        current_high = 0

    # Only instantiate the Frozen Range at the very end
    if (current_high - current_low) < lava_magic_value_size:
        return Range(0, 0)

    return Range(current_low, current_high)
