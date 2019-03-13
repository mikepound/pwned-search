import requests
import sys
import hashlib

def lookup_pwned_api(pwd):
    sha1pwd = hashlib.sha1()
    sha1pwd.update(pwd)
    sha1pwd = sha1pwd.hexdigest().upper()
    head = sha1pwd[:5]
    tail = sha1pwd[5:]

    r = requests.get('https://api.pwnedpasswords.com/range/{0}'.format(head))
    if r.status_code == 200:
        hashes = (s.split(':') for s in r.text.split('\r\n'))
        pred = ((head + t,count) for t,count in hashes if t == tail)

    password_hit = next(pred, None)
    return password_hit


api_return = lookup_pwned_api(sys.argv[1])
if (api_return):
    print (sys.argv[1], "was found")
    print ("Hash {0}, {1} occurences".format(api_return[0], api_return[1]))
else:
    print (sys.argv[1], "was not found")

exit()
