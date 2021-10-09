#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
This software helps creating a secure (hopefully unpredictable and not findable in dictionaries) password
given a set of characters to compose the password and a desired password length

e.g. include lowercase, uppercase, digits, punctuation etc. with given length 32
"""

import argparse
import string
import secrets
from typing import Union

DEFAULT_PASSWORD_CHARS = string.ascii_letters + string.digits + string.punctuation
LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
PUNCTUATION = string.punctuation


def generate_random_password(pw_length: int = 40, pw_char_set: Union[str, list] = DEFAULT_PASSWORD_CHARS) -> str:
    """ create random password """

    if not isinstance(pw_length, int) or not hasattr(pw_char_set, '__iter__'):
        raise TypeError('invalid type of pw length or pw char set')

    if pw_length < 1 or len(pw_char_set) < 1 or False in [isinstance(char, str) for char in pw_char_set]:
        raise ValueError('invalid values for create_random_password')

    return ''.join(secrets.SystemRandom(None).choice(pw_char_set) for _ in range(pw_length))


def password_is_compose_of_all_selected_charsets(use_lower: bool, use_upper: bool, use_digit: bool,
                                                 use_punctuation: bool, password: str) -> bool:
    """ this function checks weather all selected charsets are used to compose the password """

    if use_lower and True not in [char in LOWERCASE for char in password]:
        return False

    if use_upper and True not in [char in UPPERCASE for char in password]:
        return False

    if use_digit and True not in [char in DIGITS for char in password]:
        return False

    if use_punctuation and True not in [char in PUNCTUATION for char in password]:
        return False

    return True


def main() -> None:
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

    char_set_and_bool = [(LOWERCASE, args.include_lowercase), (UPPERCASE, args.include_uppercase),
                         (DIGITS, args.include_digit), (PUNCTUATION, args.include_symbol)]

    used_char_set = ''.join([char_set if condition else None for char_set, condition in char_set_and_bool])

    generated_password = generate_random_password(pw_length=args.length, pw_char_set=used_char_set)

    if not password_is_compose_of_all_selected_charsets(
            use_lower=args.include_lowercase, use_upper=args.include_uppercase, use_digit=args.include_digit,
            use_punctuation=args.include_symbol, password=generated_password):
        print('\033[5;31;40mWARNING:\033[0mthe password is not composed out of every selected charset\n')

    print(f'generated password: \033[1;31;40m{generated_password}\033[0m')


if __name__ == "__main__":
    main()
