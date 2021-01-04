"""
This software helps automate a more secure password given a set of criteria,
    e.g. include lower vs upper-case letters, digits, symbols, etc. with given length
"""


import argparse
import sys
import string
import random

symbols = list('`~!@#$%^&*()-=_+[]{}|\\;\',./<>?')
lower_cases = list(string.ascii_lowercase)
upper_cases = list(string.ascii_uppercase)
digits = list(string.digits)


def validate_password_requirements(length, include_lowercase, include_uppercase, include_number, include_symbols):
    minimum_length = 0

    if include_lowercase:
        minimum_length += 1

    if include_uppercase:
        minimum_length += 1

    if include_number:
        minimum_length += 1

    if include_symbols:
        minimum_length += 1

    return length >= minimum_length


def get_character_space(include_lowercase, include_uppercase, include_number, include_symbols):
    all_chars = []

    if include_lowercase:
        all_chars += lower_cases

    if include_uppercase:
        all_chars += upper_cases

    if include_number:
        all_chars += digits

    if include_symbols:
        all_chars += symbols

    return all_chars


def get_password(length, include_lowercase, include_uppercase, include_number, include_symbols):
    pw = []
    add_lowercase = add_uppercase = add_number = add_symbols = False
    all_chars = get_character_space(include_lowercase, include_uppercase, include_number, include_symbols)

    random.shuffle(all_chars)

    for i in range(length):

        if include_lowercase and not add_lowercase:
            random_index = random.randint(0, len(lower_cases))
            pw += lower_cases[random_index]
            add_lowercase = True

        elif include_uppercase and not add_uppercase:
            random_index = random.randint(0, len(upper_cases))
            pw += upper_cases[random_index]
            add_uppercase = True

        elif include_number and not add_number:
            random_index = random.randint(0, len(digits))
            pw += digits[random_index]
            add_number = True

        elif include_symbols and not add_symbols:
            random_index = random.randint(0, len(symbols))
            pw += symbols[random_index]
            add_symbols = True

        else:
            random_index = random.randint(0, len(all_chars))
            pw += all_chars[random_index]

    random.shuffle(pw)

    return ''.join(pw)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Generate random password")
    parser.add_argument("--length", "-l", required=True, type=int, help="Length of password")
    parser.add_argument("--include_lowercase", "-lc", required=False, type=bool, default=True,
                        help="Include lowercase character in the password")
    parser.add_argument("--include_uppercase", "-uc", required=False, type=bool, default=True,
                        help="Include uppercase character in the password")
    parser.add_argument("--include_digit", "-d", required=False, type=bool, default=True,
                        help="Include numeric character in the password")
    parser.add_argument("--include_symbol", "-s", required=False, type=bool, default=True,
                        help="Include special character in the password")
    args = parser.parse_args()

    try:
        pw_length = args.length
        pw_lower = args.include_lowercase
        pw_upper = args.include_uppercase
        pw_digit = args.include_digit
        pw_symbol = args.include_symbol

        is_valid_pw = validate_password_requirements(pw_length, pw_lower, pw_upper, pw_digit, pw_symbol)

        if is_valid_pw:
            password = get_password(pw_length, pw_lower, pw_upper, pw_digit, pw_symbol)
            print(password)
        else:
            print('Password length is not valid per requirements')
    except:
        print("Unexpected error:", sys.exc_info()[0])
        raise
