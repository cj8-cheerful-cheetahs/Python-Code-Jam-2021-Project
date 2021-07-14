from functions.command_functions import get_entry
from functions.blessed_functions import print_tree, print_box
from users.user import User, ROOT
from users.uid import Uidspace
from exceptions import CannotFullFillFunction
from config import START_PATH, MAIN_PATH
from blessed import Terminal
from copy import copy
from fs.fs_dir import Dir


# file system imports
fs = Dir.FromPath(START_PATH, None, 7, 0, 0)

# Users uid space
users_uid_space = Uidspace(1)

# User
Users = User.loadUsers(ROOT, fs, users_uid_space)

# init terminal
term = Terminal()
print(term.home + term.clear + term.move_y(term.height // 2))

failed_tasks = 0



# is't it declared somewhere already?
def add_failure():
    global failed_tasks
    failed_tasks += 1
    print(f"DEBUG: failues: {failed_tasks}")


# it should be moved into blessing
def clear_term():
    print(term.clear)


def ProcessArgs(args, argsDicit):
    try:
        return [argsDicit[i] for i in args]
    except KeyError:
        raise CannotFullFillFunction()


# COMMAND MANAGER
def user_input_cmd(fs, user):
    global term
    # clear_term()
    while True:
        # try:
        user_input = input(">>>  ").split()
        entry = get_entry(user_input[0])
        entry[0](*ProcessArgs(entry[1], locals()))
        # except Exception as e:
        #   print(e)


# should be moved into it's own file
def start(fs, user):
    content = ""
    with open(MAIN_PATH + 'first_game.txt', 'r') as f:
        content = f.readline()
    clear_term()
    if content[0] == '0':
        print_box('Intro',
           [' Hey There! You are an Artificial Intelligant,',' built by the USA, developed to get into PCs and analyze them.',' You was hacked into a System by the Atomic Program of the Iran.',' Here, your job was to analyze the Data and to see,',' if there are any files which could gives hints to the Atomatic Missiles of the Iran.'])
        input()
        clear_term()
        print_box('Intro',
           [' You found out that there will be a nuclear',' launch today, it should hit the US. But unfortunally, the system',' is offline, you cant contact the USA to warn them.'])
        input()
        clear_term()
        print_box('Intro',
           [' Because of that, you have decided that youll try to',' turn of the System, because you found indicates that that will stop',' the attack. But unfortunally, you need Root Privilages to',' shutdown the Operating System '])
        input()
        clear_term()
        print_box('Intro',
           ['You can gain access to these by (*insert challange here,',' example: get the password of the main file*). ','You will have to overcome multiple challenges'])
        input()
        clear_term()
        print_box('Intro',
            ['So, dont waste your time, think smarter not harder, and good luck!',
                   '*Title* starting',
                   'gaining system access',
                   'Access gained.',
                   'AI will launch...)'])
        clear_term()
        print_box('helper', 'This is the file tree, here, you can see every file in the operating system!')
        print_tree("System", fs, user)
        print_box('helper', 'First, type "help" in the console to see all of the commands you can use!')
        with open('first_game.txt', 'w') as firstgamefile:
            firstgamefile.truncate()
            firstgamefile.write('1')
    else:
        print_box('Welcome Back', ['', 'Your Game-State was loaded again! ', ''])


def main():
    global fs
    start(fs, ROOT)
    user_input_cmd(copy(fs), ROOT)


if __name__ == "__main__":
    main()
