import requests
import cryptography
from base64 import b16encode
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

def hash_password_sha1_hex(pwd):
    digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
    digest.update(pwd.encode('ASCII'))
    sha1 = b16encode(digest.finalize()).decode('ASCII')
    return sha1

def lookup_pwned_api(pwd):
    sha1pwd = hash_password_sha1_hex(pwd)
    head = sha1pwd[:5]
    tail = sha1pwd[5:]

    r = requests.get('https://api.pwnedpasswords.com/range/{0}'.format(head))
    if r.status_code == 200:
        hashes = (s.split(':') for s in r.text.split('\r\n'))
        pred = ((head + t,count) for t,count in hashes if t == tail)

    password_hit = next(pred, None)
    return password_hit

#build a list of passwords to check
password_list = []
if (sys.argv[1] == '-'):
    #read from stdin
    for line in sys.stdin:
        password_list.append(line.rstrip())
else:
    #read from argv
    password_list.append(sys.argv[1])

#do the lookup and analysis
for password in password_list:
    api_return = lookup_pwned_api(password)
    
    if (api_return):
        print (password, "was found")
        print ("Hash {0}, {1} occurences".format(api_return[0], api_return[1]))
    else:
        print (password, "was not found")

exit()
