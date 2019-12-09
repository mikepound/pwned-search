using HTTP
using SHA

function lookup_pwned_api(pwd::AbstractString)
    # Compute the SHA1 hash of pwd and split it at the fifth position
    sha1pwd = bytes2hex(sha1(pwd))
    head,tail = sha1pwd[1:5], sha1pwd[6:end]

    # Query the pwnedpasswords API
    url = "https://api.pwnedpasswords.com/range/$head"
    res = HTTP.request("GET",url)
    if (res.status != 200)
        @error "The API lookup failed!"
    end

    # The hashes are stored in the body of the response as hex characters (notice: NOT integers)
    # To split them, look for line-feeds, which in this case are given by CRLF (boo)
    hashes = split(String(res.body),"\r\n")
    hashes = [split(st,':') for st in hashes]

    # Find whether or not pwd (or rather its hash) appears in the list of all hashes!
    # Because the characters in the response are uppercase (01233456789ABCDEF)
    # and bytes2hex produces lowercase (0123456789abcdef), comparing strings is not good enough.
    # Instead do a RegEx match with the i flag set!
    found = 0
    re = Regex(tail,"i")
    for h in hashes
        # h[1] is the tail of the hash, h[2] is the number of occurances
        if match(re,h[1]) != nothing
            found = h[2]
            break
        end
    end
    return sha1pwd,found
end

function check_pwd(pwd::AbstractString)
    # Check whether (and if so, how often) the string pwd has been pwned.
    sha1pwd,cnt = "",0
    try
        sha1pwd,cnt = lookup_pwned_api(pwd)
    catch e
        # Error Message is printed elsewhere. Just return silently
        return
    end
    # cnt is the number of occurances. If pwd has not been pwned yet, cnt is zero.
    print("Password $pwd with the hash $sha1pwd was ")
    if (cnt != 0)
        print("found $cnt times!\n")
    else
        print("not found!\n")
    end
end

# ARGS stores the command-line arguments passed to pwned.jl
# If none were given, ARGS is empty and pwned.jl will read from stdin
if ARGS == []
    print("Reading passwords from stdin. Type exit or ^C to quit.\n")
    while true
        pwd = readline()
        if pwd == "exit"
            break
        end
        check_pwd(pwd)
    end
else
    @warn "Entering passwords in plain text on a terminal is a bad idea!i\nInstead run this program without any arguments,\nin which case it reads from stdin and no history will be created.\nIt is highly recommended to clear your terminal's history after using this program!"
    for pwd in ARGS
        check_pwd(pwd)
    end
end
