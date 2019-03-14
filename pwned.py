#!/usr/bin/env python
import hashlib
import sys

try:
    import requests
except ModuleNotFoundError:
    print("###  pip install requests  ###")
    raise


def lookup_pwned_api(pwd):
    """Returns hash and number of times password was seen in pwned database.

    Args:
        pwd: password to check

    Returns:
        A (sha1, count) tuple where sha1 is SHA-1 hash of pwd and count is number
        of times the password was seen in the pwned database.  count equal zero
        indicates that password has not been found.

    Raises:
        RuntimeError: if there was an error trying to fetch data from pwned
            database.
        UnicodeError: if there was an error UTF_encoding the password.
    """
    sha1pwd = hashlib.sha1(pwd.encode('utf-8')).hexdigest().upper()
    head, tail = sha1pwd[:5], sha1pwd[5:]
    url = 'https://api.pwnedpasswords.com/range/' + head
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError('Error fetching "{}": {}'.format(
            url, res.status_code))
    hashes = (line.split(':') for line in res.text.splitlines())
    count = next((int(count) for t, count in hashes if t == tail), 0)
    return sha1pwd, count


def main(args):
    ec = 0
    for pwd in args or sys.stdin:
        pwd = pwd.strip()
        try:
            sha1pwd, count = lookup_pwned_api(pwd)

            if count:
                foundmsg = "{0} was found with {1} occurrences (hash: {2})"
                print(foundmsg.format(pwd, count, sha1pwd))
                ec = 1
            else:
                print("{} was not found".format(pwd))
        except UnicodeError:
            errormsg = sys.exc_info()[1]
            print("{0} could not be checked: {1}".format(pwd, errormsg))
            ec = 1
            continue
    return ec


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
