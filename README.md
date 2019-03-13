# pwned-search
Pwned Password API lookup

Usage:

* `python pwned.py` – reads passwords from standard input;
* `python pwned.py <[file-with-passwords]` – reads passwords from
  a file;
* `another-command | python pwned.py` – reads
  passwords written to standard output by another command;
* `python pwned.py [password]` – checks passwords given as command line
  arguments (beware the password may be saved in shell history and that
  other users on the system ma be able to observe the command line).

Thanks to those who fixed my dodgy code :)

Have fun! Oh, and if you find one of your own passwords, change it asap!
