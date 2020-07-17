def partition(l, size):
    """
    Partition the provided list into a list of sub-lists of the provided size. The last sub-list may be smaller if the
    length of the originally provided list is not evenly divisible by `size`.

    :param l: the list to partition
    :param size: the size of each sub-list

    :return: a list of sub-lists
    """
    return [l[i:i + size] for i in range(0, len(l), size)]
