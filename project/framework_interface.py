from os import walk, path, sep
import blessed
term = blessed.Terminal

import binaryfilelibrary

cl = ["│", "─", "┌", "┬", "┐", "├", "┼", "┤", "└", "┴", "┘"]

def list_files(startpath):
    print('── /System/ ──')
    for root, dirs, files in walk(startpath):
        level = root.replace(startpath, '').count(sep)
        indent = ' ' * 4 * (level)
        print('┌'+'{}{}/'.format(indent, path.basename(root)))
        subindent ='├' +'─' * 4 * (level + 1)
        for f in files:
            print('{}{}'.format(subindent, f))

#Just like in the binaryfilelibrary, encrypt and decrypt does the same thing.
def encrypt_file(path, password):
    binaryfilelibrary.modifyFile(path, password)

def decrypt_file(path, password):
    binaryfilelibrary.modifyFile(path, password)

list_files("Project")
