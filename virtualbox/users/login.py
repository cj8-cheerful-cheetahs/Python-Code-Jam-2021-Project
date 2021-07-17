from copy import copy

from blessed import Terminal
from .user import User

from virtualbox.exceptions import InvalidLoginOrPassword
from virtualbox.functions.blessed_functions import echo, request


def login(Users: User, term: Terminal) -> None:
    """Logs user"""
    while True:
        login = request("login: ", term)
        password = request("password: ", term)

        if login in Users and Users[login].checkPassword(password):
            return copy(Users[login])
        echo(InvalidLoginOrPassword().args[0], term)
