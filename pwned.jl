using HTTP
using SHA

function lookup_pwned_api(pwd::AbstractString)
    # Compute the SHA1 hash of pwd and query the pwnedpasswords api
    sha1pwd = bytes2hex(sha1(pwd))
    head,tail = sha1pwd[1:5], sha1pwd[6:end]
    url = "https://api.pwnedpasswords.com/range/$head"
    res = HTTP.request("GET",url)
    if (res.status != 200)
        @error "The API lookup failed!"
    end
    hashes = split(String(res.body),"\r\n")
    hashes = [split(st,':') for st in hashes]
    found = 0
    re = Regex(tail,"i")
    for h in hashes
        if match(re,h[1]) != nothing
            found = h[2]
            break
        end
    end
    return sha1pwd,found
end

function check_pwd(pwd::AbstractString)
    sha1pwd,cnt = "",0
    try
        sha1pwd,cnt = lookup_pwned_api(pwd)
    catch e
        # Error Message is printed elsewhere. Just return silently
        return
    end
    print("Password $pwd with the hash $sha1pwd was ")
    if (cnt != 0)
        print("found $cnt times!\n")
    else
        print("not found!\n")
    end
end

if ARGS == []
    while true
        pwd = readline()
        if pwd == "exit"
            break
        end
        check_pwd(pwd)
    end
else
    for pwd in ARGS
        check_pwd(pwd)
    end
end
