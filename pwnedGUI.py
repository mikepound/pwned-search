#!/usr/bin/env python
from tkinter import Tk, Label, Button, Entry, StringVar, IntVar, END, W, E
from pwned import lookup_pwned_api
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
        master.title("pwned GUI by PPC")
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
        self.total = "Number of times Password found : " + str(lookup_pwned_api(self.p)[1])
        self.total_text.set(self.total)
        self.entry.delete(0, END)


root = Tk()
my_gui = Calculator(root)
root.mainloop()