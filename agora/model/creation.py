from agora.keys import PublicKey


class Creation:
    """ The :class:`Creation <Creation>` object, which represents a token account creation.

    :param owner: The :class:`PublicKey <agora.keys.PublicKey>` of the account that owns this token account.
    :param address: The :class:`PublicKey <agora.keys.PublicKey>` representing the address of the token account.
    """

    def __init__(self, owner: PublicKey, address: PublicKey):
        self.owner = owner
        self.address = address

    def __eq__(self, other):
        if not isinstance(other, Creation):
            return False

        return (self.owner == other.owner and
                self.address == other.address)

    def __repr__(self):
        return f'{self.__class__.__name__}(' \
               f'owner={self.owner!r}, address={self.address!r})'
