"""
This software helps automate a more secure password given a set of criteria,
    e.g. include lower vs upper-case letters, digits, symbols, etc. with given length
"""


import argparse
import sys
import string
import random


class PasswordGenerator:
    # symbols = list('`~!@#$%^&*()-=_+[]{}|\\;\',./<>?')
    SYMBOLS = list('@~!#$%^&*()\\-=+,.?')
    LOWER_CASES = list(string.ascii_lowercase)
    UPPER_CASES = list(string.ascii_uppercase)
    DIGITS = list(string.digits)

    def __init__(self, length, include_lowercase, include_uppercase, include_digit, include_symbol,
                 max_consecutive, max_identical):
        self.__length = length
        self.__include_lowercase = include_lowercase
        self.__include_uppercase = include_uppercase
        self.__include_digit = include_digit
        self.__include_symbol = include_symbol
        self.__max_consecutive = max_consecutive
        self.__max_identical = max_identical

        self.__character_space = self.__get_character_space()

    def __get_character_space(self):
        all_chars = []

        if self.__include_lowercase:
            all_chars += PasswordGenerator.LOWER_CASES

        if self.__include_uppercase:
            all_chars += PasswordGenerator.UPPER_CASES

        if self.__include_digit:
            all_chars += PasswordGenerator.DIGITS

        if self.__include_symbol:
            all_chars += PasswordGenerator.SYMBOLS

        return all_chars

    def validate_password_requirements(self):
        minimum_length = 0

        if self.__include_lowercase:
            minimum_length += 1

        if self.__include_uppercase:
            minimum_length += 1

        if self.__include_digit:
            minimum_length += 1

        if self.__include_symbol:
            minimum_length += 1

        if self.__length < minimum_length:
            raise Exception(f'Specified length of {self.__length} is not satisfied by minimum length of {minimum_length} by required parameters')

        if self.__max_consecutive <= 1:
            raise Exception(f'Maximum consecutive must be at least 2')

        if self.__max_identical * len(self.__character_space) < self.__length:
            raise Exception(f'Cannot satisfy max identical character of {self.__max_identical} time(s). Please relax requirement.')

    def get_password(self):
        def __update_frequency_map_and_pw(collection):
            ri = random.randint(0, len(collection) - 1)
            ch = collection[ri]
            frequency_map[ch] = frequency_map.get(ch, 0) + 1
            pw.append(ch)

        frequency_map = {}
        pw = []
        added_lowercase = added_uppercase = added_number = added_symbols = False

        random.shuffle(self.__character_space)

        for _ in range(self.__length):
            if self.__include_lowercase and not added_lowercase:
                __update_frequency_map_and_pw(PasswordGenerator.LOWER_CASES)
                added_lowercase = True

            elif self.__include_uppercase and not added_uppercase:
                __update_frequency_map_and_pw(PasswordGenerator.UPPER_CASES)
                added_uppercase = True

            elif self.__include_digit and not added_number:
                __update_frequency_map_and_pw(PasswordGenerator.DIGITS)
                added_number = True

            elif self.__include_symbol and not added_symbols:
                __update_frequency_map_and_pw(PasswordGenerator.SYMBOLS)
                added_symbols = True

            else:
                occurrences = self.__max_identical
                char = None

                while occurrences >= self.__max_identical:
                    random_index = random.randint(0, len(self.__character_space) - 1)
                    char = self.__character_space[random_index]
                    occurrences = frequency_map.get(char, 0)

                frequency_map[char] = occurrences + 1
                pw += char

        random.shuffle(pw)

        while self.__has_more_consecutive_than_allowed(pw):
            random.shuffle(pw)

        return ''.join(pw)

    def __has_more_consecutive_than_allowed(self, pw):
        consecutive_identical = 1

        for i in range(1, len(pw)):
            if pw[i] == pw[i - 1]:
                consecutive_identical += 1

                if consecutive_identical >= self.__max_consecutive:
                    return True
            else:
                consecutive_identical = 1

        return False


def main():
    parser = argparse.ArgumentParser(description="Generate random password")
    parser.add_argument("--length", "-l", required=False, type=int, default=15, help="Length of password")
    parser.add_argument("--include_lowercase", "-lc", required=False, type=str, default='y',
                        help="Include lowercase character in the password")
    parser.add_argument("--include_uppercase", "-uc", required=False, type=str, default='y',
                        help="Include uppercase character in the password")
    parser.add_argument("--include_digit", "-d", required=False, type=str, default='y',
                        help="Include numeric character in the password")
    parser.add_argument("--include_symbol", "-s", required=False, type=str, default='y',
                        help="Include special character in the password")
    parser.add_argument("--max_consecutive", "-c", required=False, type=int, default=2,
                        help="Maximum consecutive same characters")
    parser.add_argument("--max_identical", "-mi", required=False, type=int, default=4,
                        help="Maximum identical characters")
    args = parser.parse_args()

    try:
        length = int(args.length)
        include_lowercase = args.include_lowercase.lower() == 'y'
        include_uppercase = args.include_uppercase.lower() == 'y'
        include_digit = args.include_digit.lower() == 'y'
        include_symbol = args.include_symbol.lower() == 'y'
        max_consecutive = int(args.max_consecutive)
        max_identical = int(args.max_identical)

        pw_gen = PasswordGenerator(length, include_lowercase, include_uppercase, include_digit, include_symbol,
                                   max_consecutive, max_identical)
        pw_gen.validate_password_requirements()
        password = pw_gen.get_password()
        print(password)
    except:
        print("Unexpected error:", sys.exc_info()[0])
        raise


if __name__ == "__main__":
    main()