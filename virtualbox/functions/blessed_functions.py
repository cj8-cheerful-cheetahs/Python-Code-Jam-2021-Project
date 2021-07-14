from config import template


def treat_subdir(rest, add):
    result = []
    for j, i in enumerate(rest):
        s = '└' if len(rest) - 1 == j else '├'
        if isinstance(i, tuple):
            if len(i[1]) == 0:
                result.append(add + s + '─' + i[0])
            else:
                result.append(add + s + '┬' + i[0])
                result += treat_subdir(i[1], add + (" " if s == '└' else '│'))
        else:
            result.append(add + s + i)
    return result


def print_tree(header, directory, user):
    print_box(header, treat_subdir(directory.walk(user), ''))
    # "│", "─", " ┌", "┬", "┐", "├", "┼", "┤", "└", "┴", "┘"]


def lc(char, index):
    if len(char) <= index or len(char) == 0:
        return "│"
    if char[index] in ("─", "┬", "┐", "┼", "┤"  "┴", "┘"):
        return "├"
    return "│"


def rc(char, index):
    if len(char) <= index or len(char) == 0:
        return "│"
    if char[index] in ("─", "┌", "┬", "├", "┼", "└", "┴"):
        return "├"
    return "│"


def uc(char, index):
    if len(char) <= index or len(char) == 0:
        return "─"
    if char[index] in ("│", "├", "┼", "┤", "└", "┴", "┘"):
        return "┬"
    return "─"


def dc(char, index):
    if len(char) <= index or len(char) == 0:
        return "─"
    if char[index] in ("│", "┌", "┬", "┐", "├", "┼", "┤"):
        return "┴"
    return "─"


def print_box(header, text):
    if len(text) == 0:
        print(template.format('┌', header, "", '┐'))
        print(template.format('└', header, "", '┘'))
        return

    max_len = max(map(len, text))
    if max_len < len(header) + 4:
        max_len = len(header) + 4

    shift = len(header) + 3

    ushift = ""
    dshift = ""
    for i in range(max_len - shift):
        ushift += uc(text, shift + i)
        dshift += dc(text, shift + i)

    ftemplate = '{:<' + str(max_len) + '}'

    print(template.format('┌', uc(text[0], 0), header, ushift, '┐'))
    print("\n".join(lc(i, 0) + ftemplate.format(i) + rc(i, -1) for i in text))
    print(template.format('└', dc(text[-1], 0), header, dshift, '┘'))
