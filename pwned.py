import hashlib
import requests
import sys


def lookup_pwned_api(pwd):
    sha1pwd = hashlib.sha1(pwd.encode('ascii')).hexdigest().upper()
    head = sha1pwd[:5]
    tail = sha1pwd[5:]

    url = 'https://api.pwnedpasswords.com/range/' + head
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError('Error fetching "{}": {}'.format(
            url, res.status_code))

    hashes = (s.split(':') for s in r.text.split('\r\n'))
    pred = ((head + t,count) for t,count in hashes if t == tail)
    password_hit = next(pred, None)
    return password_hit


def main(args):
    ec = 0
    for pwd in args or sys.stdin:
        pwd = pwd.strip()
        api_return = lookup_pwned_api(pwd)
        if (api_return):
            print(pwd, "was found")
            print("Hash {0}, {1} occurences".format(
                api_return[0], api_return[1]))
            ec = 1
        else:
            print(pwd, "was not found")
    return ec


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
