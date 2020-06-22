#!/bin/bash
# FAIR License, Copyright (c) 2019 72Zn
# Usage of the works is permitted provided that this instrument is retained
# with the works, so that any entity that uses the works is notified of this
# instrument.  
# DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.

# Use the -p flag to 'pad' the results making it harder for attackers to
# determine your hash prefix by looking at https traffic.
# See https://www.troyhunt.com/enhancing-pwned-passwords-privacy-with-padding/

# Usage:
#     ./pwned.sh [-p] [pw1] [pw2] ...
#     ./pwned.sh [-p] < <file_with_passwords>
#     echo pw | ./pwned.sh [-p]

# Examples:
#     ./pwned.sh     # You will be prompted for passwords to check.
#     ./pwned.sh -p passw0rd123456
#     ./pwned.sh < file_with_passwords.txt
#     echo passw0rd123456 | ./pwned.sh
#     echo -e "passw0rd123456\nfoob@r" | ./pwned.sh -p

PWNAPI="https://api.pwnedpasswords.com/range"

lookup_pwned_api() {
	local pass="$1"
	local pwhash=$(printf "%s" "$pass" | sha1sum | cut -d" " -f1)
	local curlrv=$(curl ${PADDING_HEAD} -s "$PWNAPI/${pwhash:0:5}")
	[ -z "$curlrv" ] && echo "$pass could not be checked" && return
	local result=$(echo "$curlrv" | grep -i "${pwhash:5:35}")

	if [ -n "$result" ]; then
		local occ=$(printf "%s" "${result}" | cut -d: -f2 | sed 's/[^0-9]*//g')
		printf "%s was found with %s occurrences (hash: %s)\n" "$pass" "$occ" "$pwhash"
	else
		printf "%s was not found\n" "$pass"
	fi
}

# If the first parameter is the -p flag, then ask the server to pad the results.
if [[ "$1" == "-p" ]]; then
  PADDING_HEAD="-H 'Add-Padding: true'"
  shift # Remove the '-p' from $@
fi

if [[ $# -eq 0 ]]; then
	# read from file or stdin (one password per line)
	while IFS=$'\r\n' read -r pw; do
		lookup_pwned_api "$pw"
	done
else
	# read arguments
	for pw in "$@"; do
		lookup_pwned_api "$pw"
	done
fi

