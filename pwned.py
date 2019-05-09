#!/usr/bin/env python

from hashlib import sha1
from getpass import getpass

try:
    from requests import get
except ModuleNotFoundError:
    print("###  pip install requests  ###")
    raise


class Pwned:

    def __init__(self):
        self.api = 'https://api.pwnedpasswords.com/range/'

    def hash_pwd(self, pwd):
        hash = sha1(pwd.encode()).hexdigest().upper()

        return {
            'hash_full': hash,
            'hash_head': hash[:5],
            'hash_tail': hash[5:]
        }

    def request_api(self, hash_head):
        failed = True

        try:
            resp = get(self.api + hash_head)
            if resp.status_code == 200:
                failed = False
        except:
            pass
        finally:
            if failed:
                raise RuntimeError('Failed to fetch data')
            return resp.text

    def find_match(self, resp, hash_tail):
        data = [int(item.split(':')[-1])
                for item in resp.splitlines() if item.split(':')[0] == hash_tail]

        if data:
            return data[0]

    def lookup_pwned_api(self, pwd):

        hash_info = self.hash_pwd(pwd)
        resp = self.request_api(hash_info['hash_head'])
        amount = self.find_match(resp, hash_info['hash_tail'])

        return hash_info['hash_full'].lower(), amount


if __name__ == '__main__':
    pwd = getpass('Enter password: ')

    pwned = Pwned()
    hash, amount = pwned.lookup_pwned_api(pwd)

    if amount:
        print('Password was found with {} occurrences (hash: {})'.format(
            amount, hash
        ))
    else:
        print('Password was not found')
