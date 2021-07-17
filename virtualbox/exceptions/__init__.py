from typing import Any


class NoSuchFileOrDirectory(Exception):
    """Im only puting it here to make pep8 happy. it is obvious what it does. __init__(self)"""

    def __init__(self):
        super().__init__("no such file or directory")


class FileOrDirectoryAlreadyExist(Exception):
    """Im only puting it here to make pep8 happy. it is obvious what it does. __init__(self)"""

    def __init__(self):
        super().__init__("file or directory already exist")


class NotAnDirectory(Exception):
    """Im only puting it here to make pep8 happy. it is obvious what it does. __init__(self)"""

    def __init__(self):
        super().__init__("not an directory")


class NotAnFile(Exception):
    """Im only puting it here to make pep8 happy. it is obvious what it does. __init__(self)"""

    def __init__(self):
        super().__init__("not an file")


class NotAnIntiger(Exception):
    """Im only puting it here to make pep8 happy. it is obvious what it does. __init__(self)"""

    def __init__(self):
        super().__init__("not an intiger")


class PermisionDenied(Exception):
    """Im only puting it here to make pep8 happy. it is obvious what it does. __init__(self)"""

    def __init__(self):
        super().__init__("permision denied")


class NoSuchIndex(Exception):
    """Im only puting it here to make pep8 happy. it is obvious what it does. __init__(self)"""

    def __init__(self):
        super().__init__("no such index")


class UIDAlreadyExist(Exception):
    """Im only puting it here to make pep8 happy. it is obvious what it does. __init__(self)"""

    def __init__(self):
        super().__init__("uid already exist")


class CannotFullFillFunction(Exception):
    """Im only puting it here to make pep8 happy. it is obvious what it does. __init__(self)"""

    def __init__(self):
        super().__init__("function argument request cannot be fullfiled!")


class CannotReadFileInTextMode(Exception):
    """Im only puting it here to make pep8 happy. it is obvious what it does. __init__(self)"""

    def __init__(self):
        super().__init__("file content cannot be red in text mode. try binary mode insted")


class CommandNotFound(Exception):
    """Im only puting it here to make pep8 happy. it is obvious what it does. __init__(self)"""

    def __init__(self):
        super().__init__("command not found!")


class WrongAmmountOfArguments(Exception):
    """Hymmmm, __init__(self, requiredLen, acctual lengjt)"""

    def __init__(self, reqLen: int, Len: int):
        super().__init__("minimum required argument count is {} supplied count is {}".format(reqLen, Len))


class NoSuchFlagOrOption(Exception):
    """HYMMMM, __init__(self, name)"""

    def __init__(self, flag: str):
        super().__init__("no such flag or option {}".format(flag))


class ConversionError(Exception):
    """hymmm, __init__(type, varable)"""

    def __init__(self, type: type, what: Any):
        super().__init__("{} cannot be converted to {} type".format(what, type))


class ConversionErrorMulti(Exception):
    """hymmm, __init__(types, varable)"""

    def __init__(self, types: list, what: Any):
        super().__init__("{} cannot be converted to any of those {} types".format(what, types))


class WrongKeywordUsage(Exception):
    """Hymmmm, __init__(self, name)"""

    def __init__(self, name: str):
        super().__init__("bad keyword syntax! peroper keyword syntax is {}:value".format(name))


class InvalidLoginOrPassword(Exception):
    """Hymmmm, __init__(self)"""

    def __init__(self):
        super().__init__("invalid login or password! try again")


class NoSuchUser(Exception):
    """Hymmmm, __init__(self, name)"""

    def __init__(self, name: str):
        super().__init__(f"user {name} does not exist")


class CannotChangePermisionsForFather(Exception):
    """Hymmmm, __init__(self)"""

    def __init__(self):
        super().__init__("cannot change permisions for father aka ..!")
