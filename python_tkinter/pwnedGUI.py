#!/usr/bin/env python
from tkinter import Tk, Label, Button, Entry, StringVar, IntVar, END, W, E
import hashlib
import sys

try:
    import requests
except ModuleNotFoundError:
    print("###  pip install requests  ###")
    raise



class Calculator:

    def __init__(self, master):
        self.master = master
        master.title("pwned GUI")
        self.p = "";

        self.head_label_text = ""
        self.head_label = Label(master, textvariable=self.head_label_text)
        self.label = Label(master, text="Enter the password to check : ")

        vcmd = master.register(self.validate) # we have to wrap the command
        self.entry = Entry(master, validate="key", validatecommand=(vcmd, '%P'))

        self.submit_button = Button(master, text="Check", command=lambda: self.update("submit"))
        
        self.total_label_text = "Number of times Password found : ...."
        self.total_text = StringVar()
        self.total_text.set(self.total_label_text)
        self.total_label = Label(master, textvariable=self.total_text)
        self.total = Label(master, text="")

        # LAYOUT

        self.label.grid(row=0, column=0, sticky=W, padx=(25, 25), pady=(25, 10))

        self.head_label.grid(row=0, column=1, columnspan=4, sticky=E, padx=(25, 25), pady=(10, 10))

        self.entry.grid(row=2, column=0, columnspan=3, sticky=W+E, padx=(25, 25), pady=(10, 10))

        self.submit_button.grid(row=2, column=4, sticky=W+E, padx=(25, 25), pady=(10, 10))

        self.total_label.grid(row=4, column=0, columnspan=3, sticky=W, padx=(25, 25), pady=(10, 20))

    def validate(self, new_text):
        if not new_text: # the field is being cleared
            return True
        try:
            self.p = new_text
            return True
        except ValueError:
            return False

    def update(self, method):        
        self.total = "Number of times Password found : " + str(lookup_pwned_api(self.p))
        self.total_text.set(self.total)
        self.entry.delete(0, END)


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
    return count


root = Tk()
my_gui = Calculator(root)
root.mainloop()