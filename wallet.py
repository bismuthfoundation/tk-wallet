# todo: re-add timeouts
# icons created using http://www.winterdrache.de/freeware/png2ico/

import json
import ast
import csv
import glob
import os
import random
import platform
import re
import tarfile
import threading
import time
import webbrowser
from ipfs import ipfs
import base64
import hashlib
from datetime import datetime
from decimal import *
# from operator import itemgetter
from tkinter import (DISABLED, END, INSERT, LEFT, NORMAL, NW, WORD, BooleanVar,
                     Button, Canvas, Checkbutton, E, Entry, Frame, Label,
                     Listbox, Menu, N, S, Scrollbar, StringVar, Text, Tk,
                     Toplevel, W, filedialog, messagebox, ttk)

import PIL.Image
import PIL.ImageTk
import pyqrcode
import requests
import socks
import recovery
from bismuthclient import bismuthmultiwallet

from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Hash import SHA
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Signature import PKCS1_v1_5

from bisbasic import essentials, options
from polysign.signerfactory import SignerFactory
from bisbasic.quantizer import quantize_eight
from tokensv2 import *

#NEW
from bismuthclient.bismuthclient import rpcconnections
from bismuthclient import bismuthutil
from bismuthclient.simplecrypt import encrypt, decrypt
from bismuthclient.bismuthcrypto import keys_check, keys_load, keys_load_new, keys_save
from bismuthclient import bismuthmultiwallet

bismuth_util = bismuthutil.BismuthUtil()

#import matplotlib
#matplotlib.use('TkAgg')
# from tkinter import filedialog, messagebox, ttk

class Keys:
    def __init__(self):
        self.key = None
        self.public_key_readable = None
        self.private_key_readable = None
        self.encrypted = None
        self.unlocked = None
        self.public_key_b64encoded = None
        self.myaddress = None
        self.keyfile = None


# Wallet needs a version for itself
__version__ = '0.9.2'


class Wallet():
    def __init__(self):
        self.block_height_old = None
        self.statusget = None
        self.s = None
        self.socket_wait = threading.Lock()

        self.ip = None
        self.port = None
        self.tx_tree = None

        self.balance = None
        self.block_height_old = None
        self.mempool_total = None
        self.stats_timestamp = None
        self.timeout = 9
        self.first_run = True
        self.nbtabs = None

        self.reconnect = False
        self.connected = False
        self.protocol = None

        self.height_main = None
        self.height_root = None
        self.width_main = None
        self.width_root = None

        self.connecting = False

def mempool_clear():
    wallet.s._send("mpclear")


def connection_invalidate():
    wallet.connected = False
    wallet.port = None
    wallet.ip = None


def asterisk_check(data):
    if data in ["*"]:
        app_log.warning(f"Received {data} instead of data, reconnecting")
        connection_invalidate()
        node_connect()


def mempool_get(s):
    # result = [['1524749959.44', '2ac10094cc1d3dd2375f8e1aa51115afd33926e3fa69472f2ea987f5', 'edf2d63cdf0b6275ead22c9e6d66aa8ea31dc0ccb367fad2e7c08a25', '11.15000000', 'rd7Op7gZlp7bBkdL5EogrhkHB3WFGNKfc2cGqzrKzwtFCJf/3nKt13y/1MggR5ioA1RAHFn/8m5q+ot7nv6bTcAOhXHgK/CcqplNBNEp3J+RFf1IbEbhbckJsdVbRvrkQoMRZmSrwCwJm+v/pB9KYqG3R5OVKmEyc5KbUZsRuTUrZjPL6lPd+VfYy6x2Wnr5JgC+q7zvQPH0+yqVqOxcbgYggbbNyHHfYIj+0k0uK+8hwmRCe+SfG+/JZwiSp8ZO4Teyd6/NDmss0AaDRYfAVmxLMEg0aOf1xPbURL3D9gyUsDWupRFVT88eS22cRTPgvS5fwpPt/rV8QUa58eRHSMJ3MDwxpkJ7KeMkN5dfiQ/NZ0HFQc3vDwnGJ1ybyVDnw/i7ioRsJtTC0hGNO33lNVqKnbQ8yQ/7yihqfUsCM1qXA/a5Q+9bRx1mr0ff+h7BYxK7qoVF/2KeiS7Ia8OiX8EPUSiwFxCnGsY+Ie+AgQlaiUIlen2LoGw41NGmZufvWXFqK9ww8e50n35OmKw0MQrJrzOr/7iBoCOXmW0/jEzbJNM7NKEni7iFNwbfk3Xzkoh8A2/m9hdDPKZASdF1hFpNVnGJnDvuINRNn3xBUqoxCQUY50b9mGO4hdkLgVOQOVvzYvdYjB0B+XJTvmfLtWQKOcAJ4/E7tr8dSrC7sPY=', 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQ0lqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FnOEFNSUlDQ2dLQ0FnRUE0SjdSS2VPWGN2OXhaTGN6R2IvSQprV2MvanU3cktvLzIrNGJuS0NsQituT0VwNDY5Vzd5YmF3eW1mR2xVUmpvYjg3MjZ6eWFDdDVrOEJqNXU1Y25MCk1XaENueGNwdGltUytmeHA1WGx5NGs5TUNQUDlYODZFc1U0ZjBrcVBhZjhnais1MG5LdjM4a01ZMHFSR0k0U0QKNS9wVlpCY1ptRjN0eVFPYzh0SWJERk9vUHJta0FpTy9LQnAxWHA4Q0dFK24zaTdKdS9zUFlzcDZFRERobjVrVAptVDMxUGVOZ2tUOTh4OW5rSmhSTmxmQTE2Mi9ia2gva2JISE1hUE1JYUhsUDhSbGVNazlqS0hCNjVOWFVMVHNLCjZZa2FNK2F3aGVpUWIwVDE2cm5tY3N4NHZBbWViUEFBWTQ1WWNqMWx3L3lpU0ZXWWpvdkcrQjBkZ0JuTDVXbUUKb2d6bnQxN04zYzZnU1JBNEYrUUhrVlA1RjBUejdTSXFuWnZDeCtEMDhjam9hVWgxUi9SeFNlT1Mwd3pEdWdNOQpMZjhSQXZweVRxR0xmUWpYY252YnVaMGNBc1g4SzFCR3lvTDZIZ3h2U3kzeUJBMlZvSjlnM1JncVUxU3NraHgrCktsdlg0S0VWeXUxLzlMbXRpc3dKSFZGTitEdVhTV1VqMjk0RURsZktsTlRKY0h1LytQWHFyeGVzbkpjOGttYisKWVlYS0R3YnRKNDFRMnRZalBwd1BOSmpDdm1Ca2haSzR2VEFIQXNKVTVEV1pQZkRJeEN6WDVFbFFRUGNhVUV6MApvbnAzNDVpeVV0TFZZcmdIdTJCNmIvNkNqMWlCNm90SitNV1RUYXVOUHcrYXczeVRHK1NUM3dxeG5qS3I3YkoyCnJGVkFnUFBCRlI5cmVoUUpmTXBoTGtVQ0F3RUFBUT09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ==', '0', '672ce4daaeb73565'], ['1524749904.95', '4edadac9093d9326ee4b17f869b14f1a2534f96f9c5d7b48dc9acaed', '4edadac9093d9326ee4b17f869b14f1a2534f96f9c5d7b48dc9acaed', '0.00000000', 'bQmnTD79aL1hjoyVF/ARfMLFfMtQiqpmvk88fPAGW1LUqLQen87+6i+2flBCuSPOWvjHQBMJ3Ctyk5MtuWj6KtoltWSKXev2tYfgNSiAOuo1YIbUhDwTBtHI5UY6X9eNmFjB5Iny0/7VB+cotV1ZBPpgCx1xQn45CtAVk4IYaXc=', 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FES3ZMVGJEeDg1YTF1Z2IvNnhNTWhWT3E2VQoyR2VZVDgrSXEyejlGd0lNUjQwbDJ0dEdxTks3dmFyTmNjRkxJdThLbjRvZ0RRczNXU1dRQ3hOa2haaC9GcXpGCllZYTMvSXRQUGZ6clhxZ2Fqd0Q4cTRadDRZbWp0OCsyQmtJbVBqakZOa3VUUUl6Mkl1M3lGcU9JeExkak13N24KVVZ1OXRGUGlVa0QwVm5EUExRSURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ==', '0', '']]
    mempool_window = Toplevel()
    mempool_window.title("Mempool")

    def update():
        for child in mempool_window.winfo_children():  # prevent hangup
            child.destroy()

        mp_tree = ttk.Treeview(mempool_window, selectmode="extended", columns=('sender', 'recipient', 'amount'))
        # mp_tree.grid(row=0, column=0)

        # table
        mp_tree.heading("#0", text='time')
        mp_tree.column("#0", anchor='center', width=100)

        mp_tree.heading("#1", text='sender')
        mp_tree.column("#1", anchor='center', width=350)

        mp_tree.heading("#2", text='recipient')
        mp_tree.column("#2", anchor='center', width=350)

        mp_tree.heading("#3", text='amount')
        mp_tree.column("#3", anchor='center', width=100)

        mp_tree.grid(sticky=N + S + W + E)
        # table

        for tx in wallet.mempool_total:
            mp_tree.insert('', 'end', text=datetime.fromtimestamp(float(tx[0])).strftime('%y-%m-%d %H:%M'), values=(tx[1], tx[2], tx[3]))

        clear_mempool_b = Button(mempool_window, text="Clear Mempool", command=lambda: mempool_clear(), height=1, width=20, font=("Tahoma", 8))
        clear_mempool_b.grid(row=1, column=0, sticky=N + S + W + E)
        close_mempool_b = Button(mempool_window, text="Close", command=lambda: mempool_window.destroy(), height=1, width=20, font=("Tahoma", 8))
        close_mempool_b.grid(row=2, column=0, sticky=N + S + W + E)

    def refresh_mp_auto():

        try:
            # global frame_chart
            root.after(0, update())
            root.after(10000, refresh_mp_auto)
        except Exception as e:
            app_log.warning(f"Mempool window closed, disabling auto-refresh ({e})")

    refresh_mp_auto()


def recover():
    result = recovery.recover(keyring.key)
    messagebox.showinfo("Recovery Result", result)


def create_url_clicked(recipient, amount, operation, openfield):
    result = bismuth_util.create_bis_url(recipient, amount, operation, openfield)
    url_r.delete(0, END)
    url_r.insert(0, result)


def read_url_clicked(url):
    result = bismuth_util.read_url(url)

    recipient.delete(0, END)
    amount.delete(0, END)
    operation.delete(0, END)
    openfield.delete("1.0", END)

    recipient.insert(0, result['recipient'])  # amount
    amount.insert(0, result['amount'])  # recipient

    operation.insert(INSERT, result['operation'])  # operation
    openfield.insert(INSERT, result['openfield'])  # openfield

def establish(ip,port):
    try:
        app_log.warning(f"Status: Attempting to connect to {ip}:{port} out of {wallet.light_ip}")

        wallet.s = rpcconnections.Connection((ip, int(port)))

        refresh(keyring.myaddress)  # validate the connection

        app_log.warning("Connection OK")
        app_log.warning(f"Status: Wallet connected to {ip}:{port}")
        ip_connected_var.set(f"{ip}:{port}")

        wallet.ip = ip
        wallet.port = port
        wallet.connected = True
        wallet.first_run = False

    except Exception as e:
        app_log.warning(f"Status: Cannot connect to {ip}:{port} because {e}")
        #raise #temporary


def dict_shuffle(dictinary):
    l = list(dictinary.items())
    random.shuffle(l)
    return dict(l)

def node_connect(ip_param=None,port_param=None):
    wallet.connecting = True
    if wallet.first_run:
        if version == "regnet":
            port_adjusted = 3030
        elif version == "testnet":
            port_adjusted = 2829
        else:
            port_adjusted = 5658
        establish("127.0.0.1", port_adjusted)

    if not ip_param:
        print(wallet.light_ip)
        for ip, port in dict_shuffle(wallet.light_ip).items():
            while not wallet.connected:
                establish(ip,port)
    else:
        establish(ip_param, port_param)
    wallet.connecting = False



def replace_regex(string, replace):
    replaced_string = re.sub(r'^{}'.format(replace), "", string)
    return replaced_string


def alias_register(alias_desired):

    with wallet.socket_wait:
        wallet.s._send("aliascheck")
        wallet.s._send(alias_desired)
        result = wallet.s._receive()

    asterisk_check(result)

    if result == "Alias free":
        # app_log.warning("0", keyring.myaddress, "alias:register", alias_desired) #FUTURE
        # send("0", keyring.myaddress, "alias:register", alias_desired) #FUTURE
        send("0", keyring.myaddress, "", "alias=" + alias_desired)
    else:
        messagebox.showinfo("Conflict", "Name already registered")


def help():
    top13 = Toplevel()
    top13.title("Help")
    aliases_box = Text(top13, width=100)
    aliases_box.grid(row=0, pady=0)

    aliases_box.insert(INSERT, "Encrypt with PK:\n Encrypt the data with the recipient's private key. Only they will be able to view it.")
    aliases_box.insert(INSERT, "\n\n")
    aliases_box.insert(INSERT, "Mark as Message:\n Mark data as message. The recipient will be able to view it in the message section.")
    aliases_box.insert(INSERT, "\n\n")
    aliases_box.insert(INSERT, "Base64 Encoding:\n Encode the data with base64, it is a group of binary-to-text encoding scheme that representd binary data in an ASCII string format by translating it into a radix-64 representation.")
    aliases_box.insert(INSERT, "\n\n")
    aliases_box.insert(INSERT, "Operation:\n A static operation for blockchain programmability.")
    aliases_box.insert(INSERT, "\n\n")
    aliases_box.insert(INSERT, "Data:\n A variable operation for blockchain programmability.")
    aliases_box.insert(INSERT, "\n\n")
    aliases_box.insert(INSERT, "Alias Recipient:\n Use an alias of the recipient in the recipient field if they have one registered")
    aliases_box.insert(INSERT, "\n\n")
    aliases_box.insert(INSERT, "Resolve Aliases:\n Show aliases instead of addressess where applicable in the table below.")
    aliases_box.insert(INSERT, "\n\n")

    close = Button(top13, text="Close", command=top13.destroy)
    close.grid(row=3, column=0, sticky=W + E)


def data_insert_clear():
    openfield.delete('1.0', END)  # remove previous


def all_spend_clear():
    all_spend_var.set(False)

    amount.delete(0, END)
    amount.insert(0, 0)


def all_spend():
    # all_spend_var.set(True)
    all_spend_check()


def all_spend_check():
    if all_spend_var.get():
        openfield_fee_calc = openfield.get("1.0", END).strip()

        if encode_var.get() and not msg_var.get():
            openfield_fee_calc = base64.b64encode(openfield_fee_calc.encode("utf-8")).decode("utf-8")

        if msg_var.get() and encode_var.get():
            openfield_fee_calc = "bmsg=" + base64.b64encode(openfield_fee_calc.encode("utf-8")).decode("utf-8")
        if msg_var.get() and not encode_var.get():
            openfield_fee_calc = "msg=" + openfield_fee_calc
        if encrypt_var.get():
            openfield_fee_calc = "enc=" + str(openfield_fee_calc)

        fee_from_all = essentials.fee_calculate(openfield_fee_calc)
        amount.delete(0, END)
        amount_to_insert = Decimal(balance_raw.get()) - Decimal(fee_from_all)
        if amount_to_insert < 0:
            amount_to_insert = 0
        amount.insert(0, (amount_to_insert))


def fingerprint():
    root.filename = filedialog.askopenfilename(multiple=True, initialdir="", title="Select files for fingerprinting")
    dict = {}
    for file in root.filename:
        with open(file, 'rb') as fp:
            data = hashlib.blake2b(fp.read()).hexdigest()
            dict[os.path.split(file)[-1]] = data
    openfield.insert(INSERT, dict)
    wallet.nbtabs.select(tab_send)

def keys_untar(archive):
    with open(archive, "r") as archive_file:
        tar = tarfile.open(archive_file.name)
        name = tar.getnames()
        tar.extractall()
    app_log.warning(f"{name} file untarred successfully")
    return name


def keys_load_dialog():
    wallet_file = filedialog.askopenfilename(multiple=False, initialdir="", title="Select wallet")

    if wallet_file.endswith('.gz'):
        app_log.warning(wallet_file)
        wallet_file = keys_untar(wallet_file)[0]

    try:
        keyring.key, keyring.public_key_readable, keyring.private_key_readable, keyring.encrypted, keyring.unlocked, keyring.public_key_b64encoded, keyring.myaddress, keyring.keyfile = keys_load_new(wallet_file)  # upgrade later, remove blanks
    except: #tornado format
       
        with open(wallet_file) as wf:
            wf_loaded = json.load(wf)

            all_wallets = (wf_loaded["addresses"])

            picked_wallet = (all_wallets[-1]) #latest one for now

            compat_wallet = {"Address": picked_wallet["address"],
                             "Private Key": picked_wallet["private_key"],
                             "Public Key": picked_wallet["public_key"],
                             }

            compat_wallet_file = "temp.der"

            with open(compat_wallet_file, "w") as cwf:
                cwf.write(json.dumps(compat_wallet))

            keyring.key, keyring.public_key_readable, keyring.private_key_readable, keyring.encrypted, keyring.unlocked, keyring.public_key_b64encoded, keyring.myaddress, keyring.keyfile = keys_load_new(compat_wallet_file)

            os.remove(compat_wallet_file)
        

    encryption_button_refresh()

    gui_address_t.delete(0, END)
    gui_address_t.insert(INSERT, keyring.myaddress)

    credit_var.set("")
    debit_var.set("")
    fees_var.set("")
    rewards_var.set("")
    app_log.warning("")
    balance_var.set("Loading stats...")

    recipient_address.config(state=NORMAL)
    recipient_address.delete(0, END)
    recipient_address.insert(INSERT, keyring.myaddress)
    recipient_address.config(state=DISABLED)

    sender_address.config(state=NORMAL)
    sender_address.delete(0, END)
    sender_address.insert(INSERT, keyring.myaddress)
    sender_address.config(state=DISABLED)

    refresh(keyring.myaddress)


def keys_backup():
    root.filename = filedialog.asksaveasfilename(initialdir="", title="Select backup file")
    if not root.filename == "":
        if not root.filename.endswith(".tar.gz"):
            root.filename = root.filename + ".tar.gz"

        files = []
        types = ("*.der", "*.json")
        for type in types:
            files.extend(glob.glob(type))
        tar = tarfile.open(root.filename, "w:gz")
        for wallet_file in files:
            tar.add(wallet_file, arcname=wallet_file)
        tar.close()


def watch():
    address = gui_address_t.get()

    t_watch = threading.Thread(target=refresh, args=(address,))
    t_watch.start()


def unwatch():
    gui_address_t.delete(0, END)
    gui_address_t.insert(INSERT, keyring.myaddress)

    t_unwatch = threading.Thread(target=refresh, args=(keyring.myaddress,))
    t_unwatch.start()


def aliases_list():
    top12 = Toplevel()
    top12.title("Your aliases")
    aliases_box = Text(top12, width=100)
    aliases_box.grid(row=0, pady=0)

    with wallet.socket_wait:
        wallet.s._send("aliasget")
        wallet.s._send(keyring.myaddress)
        aliases_self = wallet.s._receive()
    asterisk_check(aliases_self)

    for x in aliases_self:
        aliases_box.insert(INSERT, replace_regex(x[0], "alias="))
        aliases_box.insert(INSERT, "\n")

    close = Button(top12, text="Close", command=top12.destroy)
    close.grid(row=3, column=0, sticky=W + E, padx=15, pady=(5, 5))


def recipient_insert():
    recipient.delete(0, END)
    recipient.insert(0, root.clipboard_get())


def address_insert():
    gui_address_t.delete(0, END)
    gui_address_t.insert(0, root.clipboard_get())


def data_insert():
    openfield.delete('1.0', END)  # remove previous
    openfield.insert(INSERT, root.clipboard_get())


def data_insert_r():
    openfield_r.delete('1.0', END)  # remove previous
    openfield_r.insert(INSERT, root.clipboard_get())


def url_insert():
    url.delete(0, END)  # remove previous
    url.insert(0, root.clipboard_get())


def address_copy():
    root.clipboard_clear()
    root.clipboard_append(keyring.myaddress)


def url_copy():
    root.clipboard_clear()
    root.clipboard_append(url_r.get())


def recipient_copy():
    root.clipboard_clear()
    root.clipboard_append(recipient.get())


def percentage(percent, whole):
    return (Decimal(percent) * Decimal(whole) / 100)


def alias():
    alias_var = StringVar()

    # enter password
    top8 = Toplevel()
    top8.title("Enter Desired Name")

    alias_label = Label(top8, text="Input name")
    alias_label.grid(row=0, column=0, sticky=N + W, padx=15, pady=(5, 0))

    input_alias = Entry(top8, textvariable=alias_var)
    input_alias.grid(row=1, column=0, sticky=N + E, padx=15, pady=(0, 5))

    dismiss = Button(top8, text="Register", command=lambda: alias_register(alias_var.get().strip()))
    dismiss.grid(row=2, column=0, sticky=W + E, padx=15, pady=(15, 0))

    dismiss = Button(top8, text="Dismiss", command=top8.destroy)
    dismiss.grid(row=3, column=0, sticky=W + E, padx=15, pady=(5, 5))


def encrypt_get_password():
    if keyring.encrypted:
        messagebox.showwarning("Error", "Already encrypted")
        return

    # enter password
    top3 = Toplevel()
    top3.title("Enter Password")

    password_label = Label(top3, text="Input password")
    password_label.grid(row=0, column=0, sticky=N + W, padx=15, pady=(5, 0))

    password_var_enc.set("")
    input_password = Entry(top3, textvariable=password_var_enc, show='*')
    input_password.grid(row=1, column=0, sticky=N + E, padx=15, pady=(0, 5))

    confirm_label = Label(top3, text="Confirm password")
    confirm_label.grid(row=2, column=0, sticky=N + W, padx=15, pady=(5, 0))

    password_var_con.set("")
    input_password_con = Entry(top3, textvariable=password_var_con, show='*')
    input_password_con.grid(row=3, column=0, sticky=N + E, padx=15, pady=(0, 5))

    enter = Button(top3, text="Encrypt", command=lambda: encrypt_fn(top3))
    enter.grid(row=4, column=0, sticky=W + E, padx=15, pady=(5, 5))

    cancel = Button(top3, text="Cancel", command=top3.destroy)
    cancel.grid(row=5, column=0, sticky=W + E, padx=15, pady=(5, 5))
    # enter password


def lock_fn(button):
    key = None
    decrypt_b.configure(text="Unlock", state=NORMAL)
    lock_b.configure(text="Locked", state=DISABLED)
    messagemenu.entryconfig("Sign Messages", state=DISABLED)  # messages
    walletmenu.entryconfig("Recovery", state=DISABLED)  # recover
    walletmenu.entryconfig("Decrypt Wallet", state=DISABLED)
    password_var_dec.set("")

def encrypt_fn(destroy_this):
    password = password_var_enc.get()
    password_conf = password_var_con.get()

    if password == password_conf:
        busy(destroy_this)
        try:
            ciphertext = encrypt(password, keyring.private_key_readable)
            ciphertext_export = base64.b64encode(ciphertext).decode()
            keys_save(ciphertext_export, keyring.public_key_readable, keyring.myaddress, keyring.keyfile)
            # encrypt_b.configure(text="Encrypted", state=DISABLED)
            keyring.key, keyring.public_key_readable, keyring.private_key_readable, keyring.encrypted, keyring.unlocked, keyring.public_key_b64encoded, keyring.myaddress, keyring.keyfile = keys_load_new(keyring.keyfile.name)
            encryption_button_refresh()
        finally:
            notbusy(destroy_this)
        destroy_this.destroy()
        # lock_b.configure(text="Lock", state=NORMAL)
    else:
        messagebox.showwarning("Mismatch", "Password Mismatch")


def skin_up():
    if os.path.exists("theme"):
        with open("theme", "r") as themefile:
            themes(themefile.read())  # load last selected theme
    else:
        with open("theme", "w") as theme_file:
            theme_file.write("Barebone")


def decrypt_get_password():
    # enter password
    top4 = Toplevel()
    top4.title("Enter Password")

    input_password = Entry(top4, textvariable=password_var_dec, show='*')
    input_password.grid(row=0, column=0, sticky=N + E, padx=15, pady=(5, 5))

    enter = Button(top4, text="Unlock", command=lambda: decrypt_fn(top4))
    enter.grid(row=1, column=0, sticky=W + E, padx=15, pady=(5, 5))

    cancel = Button(top4, text="Cancel", command=top4.destroy)
    cancel.grid(row=2, column=0, sticky=W + E, padx=15, pady=(5, 5))
    # enter password

def decrypt_fn(destroy_this):
    busy(destroy_this)
    try:
        keyring.password = password_var_dec.get()
        keyring.decrypted_privkey = decrypt(keyring.password, base64.b64decode(keyring.private_key_readable))  # decrypt privkey
        keyring.key = RSA.importKey(keyring.decrypted_privkey)  # be able to sign

        notbusy(destroy_this)
        destroy_this.destroy()

        decrypt_b.configure(text="Unlocked", state=DISABLED)
        lock_b.configure(text="Lock", state=NORMAL)
        messagemenu.entryconfig("Sign Messages", state=NORMAL)  # messages
        walletmenu.entryconfig("Recovery", state=NORMAL)  # recover
        walletmenu.entryconfig("Decrypt Wallet", state=NORMAL)
    except:
        notbusy(destroy_this)
        messagebox.showwarning("Locked", "Wrong password")

    password_var_dec.set("")


def send_confirm(amount_input, recipient_input, operation_input, openfield_input):
    amount_input = quantize_eight(amount_input)
    # Exchange check
    exchange_addresses = {
        "f6c0363ca1c5aa28cc584252e65a63998493ff0a5ec1bb16beda9bac": "qTrade",
    }
    if recipient_input in exchange_addresses and len(openfield_input) < 16:
        messagebox.showinfo(f"Cannot send, Identification message is missing for {exchange_addresses[recipient_input]}, please include it")
        return

    top10 = Toplevel()
    top10.title("Confirm")

    if alias_cb_var.get():  # alias check

        with wallet.socket_wait:
            wallet.s._send("addfromalias")
            wallet.s._send(recipient_input)
            recipient_input = wallet.s._receive()

        asterisk_check(recipient_input)

    # encr check
    if encrypt_var.get():
        # get recipient's public key

        with wallet.socket_wait:
            wallet.s._send("pubkeyget")
            wallet.s._send(recipient_input)
            target_public_key_b64encoded = wallet.s._receive()

        asterisk_check(target_public_key_b64encoded)

        recipient_key = RSA.importKey(base64.b64decode(target_public_key_b64encoded).decode("utf-8"))

        # openfield_input = str(target_public_key.encrypt(openfield_input.encode("utf-8"), 32))

        data = openfield_input.encode("utf-8")
        # app_log.warning (open("pubkey.der").read())
        session_key = get_random_bytes(16)
        cipher_aes = AES.new(session_key, AES.MODE_EAX)

        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(recipient_key)

        # Encrypt the data with the AES session key
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)
        enc_session_key = (cipher_rsa.encrypt(session_key))
        openfield_input = str([x for x in (cipher_aes.nonce, tag, ciphertext, enc_session_key)])

    # encr check

    if encode_var.get() and not msg_var.get():
        openfield_input = base64.b64encode(openfield_input.encode("utf-8")).decode("utf-8")
    if msg_var.get() and encode_var.get():
        openfield_input = "bmsg=" + base64.b64encode(openfield_input.encode("utf-8")).decode("utf-8")
    if msg_var.get() and not encode_var.get():
        openfield_input = "msg=" + openfield_input
    if encrypt_var.get():
        openfield_input = "enc=" + str(openfield_input)

    fee = essentials.fee_calculate(openfield_input, operation_input)

    confirmation_dialog = Text(top10, width=100)
    confirmation_dialog.insert(INSERT, ("Amount: {}\nFee: {}\nTotal: {}\nTo: {}\nOperation: {}\nData: {}".format('{:.8f}'.format(amount_input), '{:.8f}'.format(fee), '{:.8f}'.format(Decimal(amount_input) + Decimal(fee)), recipient_input, operation_input, openfield_input)))
    confirmation_dialog.configure(state="disabled")
    confirmation_dialog.grid(row=0, pady=0)

    enter = Button(top10, text="Confirm", command=lambda: send_confirmed(amount_input, recipient_input, operation_input, openfield_input, top10))
    enter.grid(row=1, column=0, sticky=W + E, padx=15, pady=(5, 5))

    done = Button(top10, text="Cancel", command=top10.destroy)
    done.grid(row=2, column=0, sticky=W + E, padx=15, pady=(5, 5))


def send_confirmed(amount_input, recipient_input, operation_input, openfield_input, top10):
    send(amount_input, recipient_input, operation_input, openfield_input)
    top10.destroy()


def send(amount_input, recipient_input, operation_input, openfield_input):
    all_spend_check()

    if keyring.key is None:
        messagebox.showerror("Locked", "Wallet is locked")
        wallet.nbtabs.select(tab_send)

    app_log.warning("Received tx command")

    try:
        Decimal(amount_input)
    except:
        messagebox.showerror("Invalid Amount", "Amount must be a number")

    if not SignerFactory.address_is_valid(recipient_input):
        messagebox.showerror("Invalid Address", "Invalid address format")
    else:

        app_log.warning(f"Amount: {amount_input}")
        app_log.warning(f"Recipient: {recipient_input}")
        app_log.warning(f"Data: {openfield_input}")

        tx_timestamp = '%.2f' % (float(wallet.stats_timestamp) - abs(float(wallet.stats_timestamp) - time.time()))  # randomize timestamp for unique signatures
        transaction = (str(tx_timestamp), str(keyring.myaddress), str(recipient_input), '%.8f' % float(amount_input), str(operation_input), str(openfield_input))  # this is signed, float kept for compatibility

        h = SHA.new(str(transaction).encode("utf-8"))
        signer = PKCS1_v1_5.new(keyring.key)
        signature = signer.sign(h)
        signature_enc = base64.b64encode(signature)
        app_log.warning(f"Client: Encoded Signature: {signature_enc.decode('utf-8')}")
        verifier = PKCS1_v1_5.new(keyring.key)

        if verifier.verify(h, signature):
            app_log.warning("Client: The signature is valid, proceeding to save transaction, signature, new txhash and the public key to mempool")
            # app_log.warning(str(timestamp), str(address), str(recipient_input), '%.8f' % float(amount_input),str(signature_enc), str(public_key_b64encoded), str(keep_input), str(openfield_input))
            tx_submit = str(tx_timestamp), str(keyring.myaddress), str(recipient_input), '%.8f' % float(amount_input), str(signature_enc.decode("utf-8")), str(keyring.public_key_b64encoded.decode("utf-8")), str(operation_input), str(openfield_input)  # float kept for compatibility

            try:

                with wallet.socket_wait:
                    wallet.s._send("mpinsert")
                    wallet.s._send(tx_submit)
                    reply = wallet.s._receive()
                asterisk_check(reply)

                app_log.warning(f"Client: {reply}")
                if reply[-1] == "Success":
                    messagebox.showinfo("OK", "Transaction accepted to mempool")
                else:
                    messagebox.showerror("Error", f"There was a problem with transaction processing. Full message: {reply}")
            except Exception as e:
                messagebox.showerror("Error", f"{e}")
                pass

            t_send = threading.Thread(target=refresh, args=(gui_address_t.get(),))
            t_send.start()

        else:
            app_log.warning("Client: Invalid signature")
        # enter transaction end


def qr(address):
    address_qr = pyqrcode.create(address)
    address_qr.png('address_qr.png')

    # popup
    top = Toplevel()
    top.title("Address QR Code")

    im = PIL.Image.open("address_qr.png")

    photo = PIL.ImageTk.PhotoImage(im.resize((320, 320)))
    label = Label(top, image=photo)
    label.image = photo  # keep a reference!
    label.pack()

    # msg = Message(top, text="hi")
    # msg.pack()

    button = Button(top, text="Dismiss", command=top.destroy)
    button.pack()
    # popup


def msg_dialogue(address):

    with wallet.socket_wait:
        wallet.s._send("addlist")
        wallet.s._send(keyring.myaddress)
        addlist = wallet.s._receive()
    asterisk_check(addlist)
    app_log.warning(addlist)

    def msg_received_get(addlist):

        for x in addlist:
            if x[11].startswith(("msg=", "bmsg=", "enc=msg=", "enc=bmsg=")) and x[3] == address:
                # app_log.warning(x[11])

                with wallet.socket_wait:
                    wallet.s._send("aliasget")
                    wallet.s._send(x[2])
                    msg_address = wallet.s._receive()[0][0]

                asterisk_check(msg_address)

                if x[11].startswith("enc=msg="):
                    msg_received_digest = replace_regex(x[11], "enc=msg=")
                    try:
                        # msg_received_digest = key.decrypt(ast.literal_eval(msg_received_digest)).decode("utf-8")

                        (cipher_aes_nonce, tag, ciphertext, enc_session_key) = ast.literal_eval(msg_received_digest)
                        # Decrypt the session key with the public RSA key
                        cipher_rsa = PKCS1_OAEP.new(keyring.key)
                        session_key = cipher_rsa.decrypt(enc_session_key)
                        # Decrypt the data with the AES session key
                        cipher_aes = AES.new(session_key, AES.MODE_EAX, cipher_aes_nonce)
                        msg_received_digest = cipher_aes.decrypt_and_verify(ciphertext, tag).decode("utf-8")

                    except:
                        msg_received_digest = "Could not decrypt message"

                elif x[11].startswith("enc=bmsg="):
                    msg_received_digest = replace_regex(x[11], "enc=bmsg=")
                    try:
                        msg_received_digest = base64.b64decode(msg_received_digest).decode("utf-8")

                        # msg_received_digest = key.decrypt(ast.literal_eval(msg_received_digest)).decode("utf-8")
                        (cipher_aes_nonce, tag, ciphertext, enc_session_key) = ast.literal_eval(msg_received_digest)
                        # Decrypt the session key with the public RSA key
                        cipher_rsa = PKCS1_OAEP.new(keyring.key)
                        session_key = cipher_rsa.decrypt(enc_session_key)
                        # Decrypt the data with the AES session key
                        cipher_aes = AES.new(session_key, AES.MODE_EAX, cipher_aes_nonce)
                        msg_received_digest = cipher_aes.decrypt_and_verify(ciphertext, tag).decode("utf-8")

                    except:
                        msg_received_digest = "Could not decrypt message"

                elif x[11].startswith("bmsg="):
                    msg_received_digest = replace_regex(x[11], "bmsg=")
                    try:
                        msg_received_digest = base64.b64decode(msg_received_digest).decode("utf-8")
                    except:
                        msg_received_digest = "Could not decode message"

                elif x[11].startswith("msg="):
                    msg_received_digest = replace_regex(x[11], "msg=")

                msg_received.insert(INSERT, ((time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(Decimal(x[1])))) + " From " + replace_regex(msg_address, "alias=") + ": " + msg_received_digest) + "\n")

    def msg_sent_get(addlist):
        for x in addlist:
            if x[11].startswith(("msg=", "bmsg=", "enc=msg=", "enc=bmsg=")) and x[2] == address:
                # app_log.warning(x[11])

                with wallet.socket_wait:
                    wallet.s._send("aliasget")
                    wallet.s._send(x[3])
                    received_aliases = wallet.s._receive()

                asterisk_check(received_aliases)
                msg_recipient = received_aliases[0][0]

                if x[11].startswith("enc=msg="):
                    msg_sent_digest = replace_regex(x[11], "enc=msg=")
                    try:
                        # msg_sent_digest = key.decrypt(ast.literal_eval(msg_sent_digest)).decode("utf-8")
                        (cipher_aes_nonce, tag, ciphertext, enc_session_key) = ast.literal_eval(msg_sent_digest)
                        # Decrypt the session key with the public RSA key
                        cipher_rsa = PKCS1_OAEP.new(keyring.key)
                        session_key = cipher_rsa.decrypt(enc_session_key)
                        # Decrypt the data with the AES session key
                        cipher_aes = AES.new(session_key, AES.MODE_EAX, cipher_aes_nonce)
                        msg_sent_digest = cipher_aes.decrypt_and_verify(ciphertext, tag).decode("utf-8")

                    except:
                        msg_sent_digest = "Could not decrypt message"

                elif x[11].startswith("enc=bmsg="):
                    msg_sent_digest = replace_regex(x[11], "enc=bmsg=")
                    try:
                        msg_sent_digest = base64.b64decode(msg_sent_digest).decode("utf-8")
                        # msg_sent_digest = key.decrypt(ast.literal_eval(msg_sent_digest)).decode("utf-8")
                        (cipher_aes_nonce, tag, ciphertext, enc_session_key) = ast.literal_eval(msg_sent_digest)
                        # Decrypt the session key with the public RSA key
                        cipher_rsa = PKCS1_OAEP.new(keyring.key)
                        session_key = cipher_rsa.decrypt(enc_session_key)
                        # Decrypt the data with the AES session key
                        cipher_aes = AES.new(session_key, AES.MODE_EAX, cipher_aes_nonce)
                        msg_sent_digest = cipher_aes.decrypt_and_verify(ciphertext, tag).decode("utf-8")
                    except:
                        msg_sent_digest = "Could not decrypt message"

                elif x[11].startswith("bmsg="):
                    msg_sent_digest = replace_regex(x[11], "bmsg=")
                    try:
                        msg_sent_digest = base64.b64decode(msg_sent_digest).decode("utf-8")
                    except:
                        msg_sent_digest = "Could not decode message"

                elif x[11].startswith("msg="):
                    msg_sent_digest = replace_regex(x[11], "msg=")

                msg_sent.insert(INSERT, ((time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(Decimal(x[1])))) + " To " + replace_regex(msg_recipient, "alias=") + ": " + msg_sent_digest) + "\n")

    # popup
    top11 = Toplevel()
    top11.title("Messaging")

    Label(top11, text="Received:", width=20).grid(row=0)

    msg_received = Text(top11, width=100, height=20, font=("Tahoma", 8))
    msg_received.grid(row=1, column=0, sticky=W, padx=5, pady=(5, 5))
    msg_received_get(addlist)

    Label(top11, text="Sent:", width=20).grid(row=2)

    msg_sent = Text(top11, width=100, height=20, font=("Tahoma", 8))
    msg_sent.grid(row=3, column=0, sticky=W, padx=5, pady=(5, 5))
    msg_sent_get(addlist)

    dismiss = Button(top11, text="Dismiss", command=top11.destroy)
    dismiss.grid(row=5, column=0, sticky=W + E, padx=15, pady=(5, 5))
    # popup


def keepalive():
    try:
        with wallet.socket_wait:
            wallet.s._send("aliasget") #some lighter function should be added to node.py (api_ping)
            wallet.s._send("test")  # keep non-threaded connection alive
            reply = wallet.s._receive()
        asterisk_check(reply)
        app_log.warning(f"Keepalive triggered: {reply}")
    except Exception:
        node_connect()


def refresh_auto():

    t_refresh_auto = threading.Thread(target=refresh, args=(gui_address_t.get(),))
    root.after(0, t_refresh_auto.start())
    root.after(30000, refresh_auto)
    #root.after(29000, keepalive)


def csv_export(s):

    with wallet.socket_wait:
        wallet.s._send("addlist")  # senders
        wallet.s._send(keyring.myaddress)
        tx_list = wallet.s._receive()

    asterisk_check(tx_list)
    app_log.warning(tx_list)

    root.filename = filedialog.asksaveasfilename(initialdir="", title="Select CSV file")

    with open(root.filename, 'w', newline='') as csvfile:
        for transaction in tx_list:
            writer = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)
            writer.writerow([transaction[0], transaction[1], transaction[3], transaction[4], transaction[5], transaction[6], transaction[7], transaction[8], transaction[9], transaction[10], transaction[11]])

    return


def token_transfer(token, amount, window):
    operation.delete(0, END)
    operation.insert(0, "token:transfer")
    openfield.delete('1.0', END)  # remove previous
    openfield.insert(INSERT, f"{token}:{amount}")
    window.destroy()
    wallet.nbtabs.select(tab_send)
    send_confirm(0, recipient.get(), "token:transfer", "{token}:{amount}")


def token_issue(token, amount, window):
    operation.delete(0, END)
    operation.insert(0, "token:issue")
    openfield.delete('1.0', END)  # remove previous
    openfield.insert(INSERT, f"{token}:{amount}")
    recipient.delete(0, END)
    recipient.insert(INSERT, keyring.myaddress)
    window.destroy()
    wallet.nbtabs.select(tab_send)
    send_confirm(0, recipient.get(), f"token:issue", "{token}:{amount}")


def tokens():
    # callback
    def callback(event):
        token_select = (token_box.get(token_box.curselection()[0]))
        token_name_var.set(token_select[0])
        token_amount_var.set(token_select[2])

    tokens_main = Frame(tab_tokens, relief='ridge', borderwidth=0)
    tokens_main.grid(row=0, column=0, pady=5, padx=5, sticky=N + W + E + S)
    # tokens_main.title ("Tokens")

    token_box = Listbox(tokens_main, width=100)
    token_box.grid(row=0, pady=0)

    scrollbar_v = Scrollbar(tokens_main, command=token_box.yview)
    scrollbar_v.grid(row=0, column=1, sticky=N + S + E)

    try:
        with wallet.socket_wait:
            wallet.s._send("tokensget")
            wallet.s._send(gui_address_t.get())
            tokens_results = wallet.s._receive()

        asterisk_check(tokens_results)

        app_log.warning(tokens_results)
        for pair in tokens_results:
            token = pair[0]
            balance = pair[1]
            token_box.insert(END, (token, ":", balance))
    except Exception as e:
        connection_invalidate()
        node_connect()
        messagebox.showerror("Error", f"There was an issue fetching tokens: {e}")

    token_box.bind('<Double-1>', callback)

    token_name_var = StringVar()
    token_name = Entry(tokens_main, textvariable=token_name_var, width=80)
    token_name.grid(row=2, column=0, sticky=E, padx=15, pady=(5, 5))

    token_name_label_var = StringVar()
    token_name_label_var.set("Token Name:")
    token_name_label = Label(tokens_main, textvariable=token_name_label_var)
    token_name_label.grid(row=2, column=0, sticky=W, padx=15, pady=(0, 0))

    # balance_var = StringVar()
    # balance_msg_label = Label(frame_buttons, textvariable=balance_var)

    token_amount_var = StringVar()
    token_amount = Entry(tokens_main, textvariable=token_amount_var, width=80, )
    token_amount.grid(row=3, column=0, sticky=E, padx=15, pady=(5, 5))

    token_amount_label_var = StringVar()
    token_amount_label_var.set("Token Amount:")
    token_amount_label = Label(tokens_main, textvariable=token_amount_label_var)
    token_amount_label.grid(row=3, column=0, sticky=W, padx=15, pady=(0, 0))

    transfer = Button(tokens_main, text="Transfer", command=lambda: token_transfer(token_name_var.get(), token_amount_var.get(), tokens_main))
    transfer.grid(row=4, column=0, sticky=W + E, padx=5)

    issue = Button(tokens_main, text="Issue", command=lambda: token_issue(token_name_var.get(), token_amount_var.get(), tokens_main))
    issue.grid(row=5, column=0, sticky=W + E, padx=5)
    # cancel = Button (tokens_main, text="Cancel", command=tokens_main.destroy)
    # cancel.grid (row=6, column=0, sticky=W + E, padx=5)

def decrypt_wallet():
    keys_save(keyring.key.exportKey().decode("utf-8"), keyring.public_key_readable, keyring.myaddress, keyring.keyfile)
    keyring.key, keyring.public_key_readable, keyring.private_key_readable, keyring.encrypted, keyring.unlocked, keyring.public_key_b64encoded, keyring.myaddress, keyring.keyfile = keys_load_new(keyring.keyfile.name)
    encryption_button_refresh()

def selectItem(event):
    curItem = wallet.tx_tree.focus()
    print(wallet.tx_tree.item(curItem))
    root.clipboard_append(wallet.tx_tree.item(curItem))

def tx_tree_define():
    wallet.tx_tree = ttk.Treeview(tab_transactions, selectmode="extended", columns=('sender', 'recipient', 'amount', 'type'), height=20)
    wallet.tx_tree.grid(row=1, column=0)

    # table
    wallet.tx_tree.heading("#0", text='time')
    wallet.tx_tree.column("#0", anchor='center')

    wallet.tx_tree.heading("#1", text='sender')
    wallet.tx_tree.column("#1", anchor='center')

    wallet.tx_tree.heading("#2", text='recipient')
    wallet.tx_tree.column("#2", anchor='center')

    wallet.tx_tree.heading("#3", text='amount')
    wallet.tx_tree.column("#3", anchor='center')

    wallet.tx_tree.heading("#4", text='type')
    wallet.tx_tree.column("#4", anchor='center')

    wallet.tx_tree.grid(sticky=N + S + W + E)

    wallet.tx_tree.bind('<Button-1>', selectItem)

def table(address, addlist_20, mempool_total):
    # transaction table
    # data
    try:
        wallet.tx_tree.destroy()
    except:
        pass
    tx_tree_define()

    for tx in mempool_total:
        tag = "mempool"

        try:
            if tx[1] == address:
                wallet.tx_tree.insert('', 'end', text=datetime.fromtimestamp(float(tx[0])).strftime('%y-%m-%d %H:%M'), values=(tx[1], tx[2], tx[3], "?"), tags=tag)
        except:
            app_log.warning("Mempool empty")

    # aliases
    addlist_addressess = []
    reclist_addressess = []

    for tx in addlist_20:
        addlist_addressess.append(tx[2])  # append address
        reclist_addressess.append(tx[3])  # append recipient

    if resolve_var.get():

        with wallet.socket_wait:
            wallet.s._send("aliasesget")  # senders
            wallet.s._send(addlist_addressess)
            aliases_address_results = wallet.s._receive()
            wallet.s._send("aliasesget")  # recipients
            wallet.s._send(reclist_addressess)
            aliases_rec_results = wallet.s._receive()

        asterisk_check(aliases_rec_results)

        for index, tx in enumerate(addlist_20):
            tx[2] = aliases_address_results[index]
            tx[3] = aliases_rec_results[index]
    # aliases

    # bind local address to local alias
    if resolve_var.get():
        with wallet.socket_wait:
            wallet.s._send("aliasesget")  # local
            wallet.s._send([gui_address_t.get()])
            alias_local_result = wallet.s._receive()[0]

        asterisk_check(alias_local_result)
    # bind local address to local alias

    for tx in addlist_20:
        if tx[3] == gui_address_t.get():
            tag = "received"
        else:
            tag = "sent"

        # case for alias = this address
        if resolve_var.get():
            app_log.warning(tx[3], alias_local_result)
            if tx[3] == alias_local_result:
                tag = "received"
        # case for alias = this address

        if Decimal(tx[9]) > 0:
            symbol = "MIN"
        elif tx[11].startswith("bmsg"):
            symbol = "B64M"
        elif tx[11].startswith("msg"):
            symbol = "MSG"
        else:
            symbol = "TX"

        wallet.tx_tree.insert('', 'end', text=datetime.fromtimestamp(float(tx[1])).strftime('%y-%m-%d %H:%M'), values=(tx[2], tx[3], tx[4], symbol), tags=tag)

        wallet.tx_tree.tag_configure("received", background='palegreen1')
        wallet.tx_tree.tag_configure("sent", background='chocolate1')


def refresh(address):
    # app_log.warning "refresh triggered"
    try:

        with wallet.socket_wait:
            wallet.s._send("statusget")
            wallet.statusget = wallet.s._receive()

        asterisk_check(wallet.statusget)
        wallet.status_version = wallet.statusget[7]
        wallet.stats_timestamp = wallet.statusget[9]
        server_timestamp_var.set("GMT: {}".format(time.strftime("%H:%M:%S", time.gmtime(int(float(wallet.stats_timestamp))))))

        with wallet.socket_wait:
            wallet.s._send("balanceget")
            wallet.s._send(address)  # change address here to view other people's transactions
            stats_account = wallet.s._receive()

        asterisk_check(stats_account)
        balance = stats_account[0]
        credit = stats_account[1]
        credit_var.set("Received Total: {:.8f} BIS".format(Decimal(credit)))

        debit = stats_account[2]
        debit_var.set("Sent Total: {:.8f} BIS".format(Decimal(debit)))

        fees = stats_account[3]
        fees_var.set("Fees Paid: {:.8f} BIS".format(Decimal(fees)))

        rewards = stats_account[4]
        rewards_var.set("Rewards: {:.8f} BIS".format(Decimal(rewards)))

        app_log.warning("Transaction address balance: {}".format(balance))
        balance_var.set("Balance: {:.8f} BIS".format(Decimal(balance)))
        balance_raw.set(balance)

        # 0000000011"statusget"
        # 0000000011"blocklast"

        with wallet.socket_wait:
            wallet.s._send("blocklast")
            block_get = wallet.s._receive()

        asterisk_check(block_get)

        bl_height = block_get[0]
        bl_height_var.set("Block: {}".format(bl_height))
        db_timestamp_last = block_get[1]
        hash_last = block_get[7]
        hash_var.set("Hash: {}...".format(hash_last[:6]))

        # check difficulty

        with wallet.socket_wait:
            wallet.s._send("diffget")
            diff = wallet.s._receive()
        asterisk_check(diff)
        # check difficulty

        app_log.warning(diff)
        diff_msg = int(diff[1])  # integer is enough
        diff_msg_var.set("Difficulty: {}".format(diff_msg))

        # network status
        time_now = str(time.time())
        last_block_ago = Decimal(time_now) - Decimal(db_timestamp_last)
        if last_block_ago > 300:
            sync_msg = "{}m behind".format((int(last_block_ago / 60)))
            sync_msg_label.config(fg='red')
        else:
            sync_msg = "Last block: {}s ago".format((int(last_block_ago)))
            sync_msg_label.config(fg='green')
        sync_msg_var.set(sync_msg)


        # network status

        with wallet.socket_wait:
            wallet.s._send("mpget")  # senders
            wallet.mempool_total = wallet.s._receive()

        asterisk_check(wallet.mempool_total)
        mempool_count_var.set("Mempool txs: {}".format(len(wallet.mempool_total)))

        # fees_current_var.set("Current Fee: {}".format('%.8f' % float(fee)))

        # address_var.set("Address: {}".format(address))

        with wallet.socket_wait:
            wallet.s._send("addlistlim")
            wallet.s._send(address)
            wallet.s._send("20")
            addlist = wallet.s._receive()
        asterisk_check(addlist)
        app_log.warning(addlist)

        table(address, addlist, wallet.mempool_total)
        # root.after(1000, refresh)

        # canvas bg
        root.update()
        wallet.width_root = root.winfo_width()
        wallet.height_root = root.winfo_height()

        # frame_main.update()
        wallet.width_main = tab_main.winfo_width()
        wallet.height_main = tab_main.winfo_height()

        canvas_main.configure(width=wallet.width_main, height=wallet.height_main)
        # photo_main.resize (wallet.width_main,wallet.height_main)

        # canvas bg

        all_spend_check()

    except Exception as e:
        #raise #temporary

        if not wallet.connecting:
            node_connect()
        app_log.warning(e)
        connection_invalidate()

    finally:
        skin_up()


def sign():
    def verify_this():
        try:
            received_public_key = RSA.importKey(public_key_gui.get("1.0", END))
            verifier = PKCS1_v1_5.new(received_public_key)
            hash = SHA.new(input_text.get("1.0", END).encode("utf-8"))
            received_signature_dec = base64.b64decode(output_signature.get("1.0", END))

            if verifier.verify(hash, received_signature_dec):
                messagebox.showinfo("Validation Result", "Signature valid")
            else:
                messagebox.showinfo("Validation Result", "Signature invalid")
        except:
            messagebox.showerror("Validation Result", "Signature invalid")

    def sign_this():
        h = SHA.new(input_text.get("1.0", END).encode("utf-8"))
        signer = PKCS1_v1_5.new(keyring.key)
        signature = signer.sign(h)
        signature_enc = base64.b64encode(signature)

        output_signature.delete('1.0', END)  # remove previous
        output_signature.insert(INSERT, signature_enc)

    # popup
    top = Toplevel()
    top.title("Sign message")
    # top.geometry("%dx%d%+d%+d" % (800, 600, 0, 0))
    # top.grid_propagate(False)

    Label(top, text="Message:", width=20).grid(row=0, pady=0)
    input_text = Text(top, height=10)
    # label.image = photo  # keep a reference!
    input_text.grid(row=1, column=0, sticky=N + E, padx=15, pady=(0, 0))

    Label(top, text="Public Key:", width=20).grid(row=2, pady=0)
    public_key_gui = Text(top, height=10)
    public_key_gui.insert(INSERT, keyring.public_key_readable)
    public_key_gui.grid(row=3, column=0, sticky=N + E, padx=15, pady=(0, 0))

    Label(top, text="Signature:", width=20).grid(row=4, pady=0)
    output_signature = Text(top, height=10)
    output_signature.grid(row=5, column=0, sticky=N + E, padx=15, pady=(0, 0))

    # msg = Message(top, text="hi")
    # msg.pack()

    sign_message = Button(top, text="Sign Message", command=sign_this)
    sign_message.grid(row=6, column=0, sticky=W + E, padx=15, pady=(5, 0))

    sign_message = Button(top, text="Verify Message", command=verify_this)
    sign_message.grid(row=7, column=0, sticky=W + E, padx=15, pady=(15, 0))

    dismiss = Button(top, text="Dismiss", command=top.destroy)
    dismiss.grid(row=8, column=0, sticky=W + E, padx=15, pady=(15, 5))
    # popup

def click_on_tab_tokens(event):
    if str(wallet.nbtabs.index(wallet.nbtabs.select())) == "4":
        tokens()

def themes(theme):
    # global photo_bg, photo_main
    global photo_main

    if theme == "Barebone" or not theme:
        # canvas_bg.delete("all")
        canvas_main.delete("all")

    else:
        # img_bg = PIL.Image.open ("themes/{}_bg.jpg".format(theme))
        # photo_bg = PIL.ImageTk.PhotoImage (img_bg)
        # canvas_bg.create_image (0, 0, image=photo_bg, anchor=NW)

        wallet.width_main = tab_main.winfo_width()
        wallet.height_main = tab_main.winfo_height()

        #main_bg = PIL.Image.open("themes/{}.jpg".format(theme)).resize((wallet.width_main, wallet.height_main), PIL.Image.ANTIALIAS)
        main_bg = PIL.Image.open("themes/{}.jpg".format(theme))
        photo_main = PIL.ImageTk.PhotoImage(main_bg)
        canvas_main.create_image(0, 0, image=photo_main, anchor=NW)

    with open("theme", "w") as theme_file:
        theme_file.write(theme)


def encryption_button_refresh():
    if keyring.unlocked:
        decrypt_b.configure(text="Unlocked", state=DISABLED)
    if not keyring.unlocked:
        decrypt_b.configure(text="Unlock", state=NORMAL)
        messagemenu.entryconfig("Sign Messages", state=DISABLED)  # messages
        walletmenu.entryconfig("Recovery", state=DISABLED)  # recover
        walletmenu.entryconfig("Decrypt Wallet", state=DISABLED)
    if not keyring.encrypted:
        encrypt_b.configure(text="Encrypt", state=NORMAL)
    if keyring.encrypted:
        encrypt_b.configure(text="Encrypted", state=DISABLED)
    lock_b.configure(text="Lock", state=DISABLED)
    resolve_var.set(False)


def busy(an_item=None):
    an_item = an_item if an_item else root
    an_item.config(cursor="watch")


def notbusy(an_item=None):
    an_item = an_item if an_item else root
    an_item.config(cursor="")


if __name__ == "__main__":

    keyring = Keys()
    wallet = Wallet()
    #statistics = Statistics()


    if os.path.exists("privkey.der"):
        private_key_load = "privkey.der"
    else:
        private_key_load = "privkey_encrypted.der"
    public_key_load = "pubkey.der"

    # app_log.warning(getcontext())
    config = options.Get()

    config.read()
    debug_level = config.debug_level
    wallet.light_ip = config.light_ip
    node_ip = config.node_ip
    version = config.version
    terminal_output = config.terminal_output
    gui_scaling = config.gui_scaling


    wallet.port = int(config.port)

    app_log = log.log("wallet.log", debug_level, terminal_output)

    app_log.warning(f"Protocol versoion: {version}")

    keys_check(app_log, "wallet.der")

    keyring.key, keyring.public_key_readable, keyring.private_key_readable, keyring.encrypted, keyring.unlocked, keyring.public_key_b64encoded, keyring.myaddress, keyring.keyfile = keys_load(private_key_load, public_key_load)
    print(f"Keyfile: {keyring.keyfile.name}")

    #update wallet to json
    json_wallet = bismuthmultiwallet.BismuthMultiWallet()

    try:
        json_wallet.import_der(keyring.keyfile.name)
        json_wallet.save()
        print(f"Wallet upgraded to Tornado JSON")
    except Exception as e:
        print(f"Skipping wallet upgrade: {e}")
    #update wallet to json

    #if not os.path.exists("wallet.json"):
    #    wallet_modern.import_der()

    try:
        suggested_wallet_servers = requests.get("http://api.bismuth.live/servers/wallet/legacy.json")
        if suggested_wallet_servers.status_code == 200:
            wallet.light_ip.clear()

            for entry in suggested_wallet_servers.json():
                if entry["active"]:
                    wallet.light_ip[entry["ip"]] = str(entry["port"])

    except Exception as e:
        app_log.warning("Error {} getting Server list from API, using local list instead".format(e))

    # light_ip.insert(0,node_ip)
    # light_ip = "127.0.0.1:8150"
    app_log.warning(f"Connecting to {wallet.light_ip}")

    root = Tk()
    root.resizable(width=False, height=False)

    root.wm_title(f"Bismuth Light Wallet - v{__version__}")
    # root.geometry("1310x700") #You want the size of the app to be 500x500

    # root['bg']="black"

    root.resizable(0, 0)  # Don't allow resizing in the x or y direction / resize #nuitka
    img_icon = PIL.Image.open("graphics/icon.jpg")  # nuitka
    photo_icon = PIL.ImageTk.PhotoImage(img_icon)  # nuitka
    root.tk.call('wm', 'iconphoto', root._w, photo_icon, )  # nuitka

    if gui_scaling == "adapt":
        dpi_value = root.winfo_fpixels('1i')
        root.tk.call('tk', 'scaling', dpi_value / 72)

    elif gui_scaling != "default":
        root.tk.call("tk", "scaling", gui_scaling)

    password_var_enc = StringVar()
    password_var_con = StringVar()
    password_var_dec = StringVar()

    frame_bottom = Frame(root, relief='sunken', borderwidth=1)
    frame_bottom.grid(row=5, column=0, sticky='NESW', pady=5, padx=5)

    # notebook widget
    wallet.nbtabs = ttk.Notebook(root)
    wallet.nbtabs.grid(row=1, column=0, sticky='NESW', pady=5, padx=5)

    # tab_main Main
    tab_main = ttk.Frame(wallet.nbtabs)
    wallet.nbtabs.add(tab_main, text='Overview')

    canvas_main = Canvas(tab_main, highlightthickness=0)
    canvas_main.grid(row=0, column=0, sticky=W + E + N + S, columnspan=99, rowspan=99)

    frame_logo = Frame(tab_main, relief='ridge', borderwidth=4)
    frame_logo.grid(row=1, column=0, pady=5, padx=5, sticky=W)

    frame_coins = Frame(tab_main, relief='ridge', borderwidth=4)
    frame_coins.grid(row=0, column=0, sticky=W + E + N, pady=5, padx=5)

    frame_hyperlinks = Frame(tab_main, relief='ridge', borderwidth=4)
    frame_hyperlinks.grid(row=0, column=98, pady=5, padx=5, sticky=W + N)

    frame_support = Frame(tab_main, relief='ridge', borderwidth=4)
    frame_support.grid(row=98, column=98, pady=5, padx=5, sticky=W + N)

    # frame_mainstats = Frame(tab_main, relief = 'ridge', borderwidth = 4)
    # frame_mainstatistics.grid(row=5, column=1, sticky=W + E + N, pady=5, padx=5)

    # tab_transactions transactions
    tab_transactions = ttk.Frame(wallet.nbtabs)


    wallet.nbtabs.add(tab_transactions, text='History')

    frame_entries_t = Frame(tab_transactions, relief='ridge', borderwidth=0)
    frame_entries_t.grid(row=0, column=0, pady=5, padx=5)

    # frame_labels_t = Frame(tab_transactions,relief = 'ridge', borderwidth = 0)
    # frame_labels_t.grid(row=0, column=0, pady=5, padx=5, sticky=N+W+E+S)

    frame_table = Frame(tab_transactions, relief='ridge', borderwidth=0)
    frame_table.grid(row=1, column=0, sticky=W + E + N, pady=5, padx=5)

    # refresh(myaddress, s)

    # tab_send sendcoin tab
    tab_send = ttk.Frame(wallet.nbtabs)
    wallet.nbtabs.add(tab_send, text='Send')

    frame_entries = Frame(tab_send)
    frame_entries.grid(row=0, column=0, pady=5, padx=5, sticky=N + W + E + S)

    frame_send = Frame(tab_send, relief='ridge', borderwidth=1)
    frame_send.grid(row=0, column=2, pady=5, padx=5, sticky=N)

    frame_tick = Frame(frame_send, relief='ridge', borderwidth=1)
    frame_tick.grid(row=4, column=0, pady=5, padx=5, sticky=S)

    # tab_receive receive
    tab_receive = ttk.Frame(wallet.nbtabs)
    wallet.nbtabs.add(tab_receive, text='Receive')

    frame_entries_r = Frame(tab_receive, relief='ridge', borderwidth=0)
    frame_entries_r.grid(row=0, column=0, pady=5, padx=5, sticky=N + W + E + S)

    recipient_address = Entry(frame_entries_r, width=60, text=keyring.myaddress)
    recipient_address.insert(0, keyring.myaddress)

    recipient_address.grid(row=0, column=1, sticky=W, pady=5, padx=5)
    recipient_address.configure(state=DISABLED)

    amount_r = Entry(frame_entries_r, width=60)
    amount_r.grid(row=2, column=1, sticky=W, pady=5, padx=5)
    amount_r.insert(0, "0.00000000")

    openfield_r = Text(frame_entries_r, width=60, height=5, font=("Tahoma", 8))
    openfield_r.grid(row=3, column=1, sticky=W, pady=5, padx=5)

    operation_r = Entry(frame_entries_r, width=60)
    operation_r.grid(row=4, column=1, sticky=W, pady=5, padx=5)

    url_r = Entry(frame_entries_r, width=60)
    url_r.grid(row=5, column=1, sticky=W, pady=5, padx=5)
    url_r.insert(0, "bis://")

    # tab5 tokens
    tab_tokens = ttk.Frame(wallet.nbtabs)
    wallet.nbtabs.add(tab_tokens, text='Tokens')
    wallet.nbtabs.bind('<<NotebookTabChanged>>', click_on_tab_tokens)


    # tab6 ipfs
    def check_ipfs():
        returned = ipfs.init()
        if returned:
            messagebox.showinfo("OK", f"IPFS initialized properly: {returned}")
        else:
            messagebox.showerror("Error", "You need to install IPFS to the wallet directory first")

    def ipfs_upload(ipfs_output_op, ipfs_output_hash, ipfs_output_file, ipfs_fingerprint):
        ipfs_file = filedialog.askopenfilename(initialdir="", title="Select file to upload")

        ipfs_output_hash.configure(state="normal")
        ipfs_output_file.configure(state="normal")
        ipfs_output_op.configure(state="normal")
        ipfs_fingerprint.configure(state="normal")

        result = ipfs.store(ipfs_file)
        print(result)
        ipfs.save_local(result)

        ipfs_output_op.delete(0, END)
        ipfs_output_hash.delete(0, END)
        ipfs_output_file.delete(0, END)
        ipfs_fingerprint.delete(0, END)

        ipfs_output_op.insert(0, result["operation"])
        ipfs_output_hash.insert(0, result["hash"])
        ipfs_output_file.insert(0, result["filename"])

        with open(ipfs_file, 'rb') as fp:
            data = hashlib.blake2b(fp.read()).hexdigest()
            ipfs_fingerprint.insert(0, data)

        ipfs_output_hash.configure(state="readonly")
        ipfs_output_file.configure(state="readonly")
        ipfs_output_op.configure(state="readonly")
        ipfs_fingerprint.configure(state="readonly")

        return result

    def ipfs_to_bis():
        if not ipfs_output_op.get():
            messagebox.showinfo("Not uploaded", "You need to upload your file first")
            return

        wallet.nbtabs.select(tab_send)

        recipient.delete(0, END)
        amount.delete(0, END)
        operation.delete(0, END)
        openfield.delete("1.0", END)

        recipient.insert(0, keyring.myaddress)  # amount
        amount.insert(0, 0)  # recipient

        operation.insert(INSERT, "ipfs")  # operation
        openfield.insert(INSERT, f"operation={ipfs_output_op.get()},"
                                 f"hash={ipfs_output_hash.get()},"
                                 f"filename={ipfs_output_file.get()},"
                                 f"fingerprint={ipfs_fingerprint.get()}")  # openfield

    tab_ipfs = ttk.Frame(wallet.nbtabs)

    wallet.nbtabs.add(tab_ipfs, text='IPFS')

    frame_entries_i = Frame(tab_ipfs, relief='ridge', borderwidth=0)
    frame_entries_i.grid(row=0, column=0, pady=5, padx=5)

    frame_table = Frame(tab_ipfs, relief='ridge', borderwidth=0)
    frame_table.grid(row=1, column=0, sticky=W + E + N, pady=5, padx=5)

    ipfs_output_op_stringvar = StringVar()
    ipfs_output_op_stringvar.set("Operation:")
    ipfs_output_op_label = Label(tab_ipfs, textvariable=ipfs_output_op_stringvar)
    ipfs_output_op_label.grid(row=3, column=0, sticky=E, pady=5, padx=5)

    ipfs_output_op = Entry(tab_ipfs, width=60)
    ipfs_output_op.grid(row=3, column=1, sticky=W, pady=5, padx=5)

    ipfs_output_hash_stringvar = StringVar()
    ipfs_output_hash_stringvar.set("Hash:")
    ipfs_output_hash_label = Label(tab_ipfs, textvariable=ipfs_output_hash_stringvar)
    ipfs_output_hash_label.grid(row=4, column=0, sticky=E, pady=5, padx=5)

    ipfs_output_hash = Entry(tab_ipfs, width=60)
    ipfs_output_hash.grid(row=4, column=1, sticky=W, pady=5, padx=5)

    ipfs_output_filename_stringvar = StringVar()
    ipfs_output_filename_stringvar.set("Filename:")
    ipfs_output_filename_label = Label(tab_ipfs, textvariable=ipfs_output_filename_stringvar)
    ipfs_output_filename_label.grid(row=5, column=0, sticky=E, pady=5, padx=5)

    ipfs_output_file = Entry(tab_ipfs, width=60)
    ipfs_output_file.grid(row=5, column=1, sticky=W, pady=5, padx=5)

    ipfs_output_fingerprint_stringvar = StringVar()
    ipfs_output_fingerprint_stringvar.set("Fingerprint:")
    ipfs_output_fingerprint_label = Label(tab_ipfs, textvariable=ipfs_output_fingerprint_stringvar)
    ipfs_output_fingerprint_label.grid(row=6, column=0, sticky=E, pady=5, padx=5)

    ipfs_fingerprint = Entry(tab_ipfs, width=60)
    ipfs_fingerprint.grid(row=6, column=1, sticky=W, pady=5, padx=5)

    ipfs_output_hash.configure(state="readonly")
    ipfs_output_file.configure(state="readonly")
    ipfs_output_op.configure(state="readonly")
    ipfs_fingerprint.configure(state="readonly")


    check_b = Button(frame_table, text="Check IPFS", command=check_ipfs, height=1, width=15)
    check_b.grid(row=0, column=0)

    select_b = Button(frame_table, text="Upload to IPFS", command=lambda: ipfs_upload(ipfs_output_op, ipfs_output_hash, ipfs_output_file, ipfs_fingerprint), height=1, width=15)
    select_b.grid(row=1, column=0)

    save_b = Button(frame_table, text="Reference to BIS", command=ipfs_to_bis, height=1, width=15)
    save_b.grid(row=2, column=0)

    #ipfs end


    # canvas
    menubar = Menu(root)
    walletmenu = Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Wallet", menu=walletmenu)
    walletmenu.add_command(label="Load Wallet", command=keys_load_dialog)
    walletmenu.add_command(label="Backup Wallet", command=keys_backup)
    walletmenu.add_command(label="Encrypt Wallet", command=encrypt_get_password)
    walletmenu.add_command(label="Decrypt Wallet", command=decrypt_wallet)
    walletmenu.add_separator()
    walletmenu.add_command(label="Recovery", command=recover)
    walletmenu.add_separator()
    # walletmenu.add_command(label="Spending URL QR", command=lambda: qr(url.get()))
    # walletmenu.add_command(label="Reception URL QR", command=lambda: qr(url_r.get()))
    walletmenu.add_command(label="Alias Registration...", command=alias)
    walletmenu.add_command(label="Show Alias", command=aliases_list)
    walletmenu.add_command(label="Fingerprint...", command=fingerprint)
    walletmenu.add_separator()
    walletmenu.add_command(label="Exit", command=root.quit)

    messagemenu = Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Message", menu=messagemenu)
    messagemenu.add_command(label="Show Messages", command=lambda: msg_dialogue(gui_address_t.get()))
    messagemenu.add_command(label="Sign Messages", command=sign)

    if not os.path.exists("theme"):
        with open("theme", "w") as theme_file:
            theme_file.write("Barebone")

    theme_menu = Menu(menubar, tearoff=0)

    theme_list = []
    for theme_picture in glob.glob('themes/*.jpg'):
        theme_picture = os.path.basename(theme_picture).split('.jpg')[0]
        theme_list.append(theme_picture)
        theme_menu.add_command(label=theme_picture, command=lambda theme_picture=theme_picture: themes(theme_picture))  # wow this lambda is amazing

    theme_menu.add_command(label="Barebone", command=lambda: themes("Barebone"))
    menubar.add_cascade(label="Themes", menu=theme_menu)

    miscmenu = Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Misc", menu=miscmenu)
    miscmenu.add_command(label="Mempool", command=lambda: mempool_get(wallet.s))
    miscmenu.add_command(label="CSV Export...", command=lambda: csv_export(wallet.s))
    #miscmenu.add_command(label="Statistics", command=lambda: stats())
    miscmenu.add_command(label="Help", command=help)

    connect_menu = Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Connection", menu=connect_menu)
    connect_list = []

    for ip, port in wallet.light_ip.items():
        connect_list.append(f'{ip}:{port}')
        connect_menu.add_command(label=f'{ip}:{port}', command=lambda ip=ip: node_connect(ip, port))

    # labels
    Label(frame_entries, text="My Address:").grid(row=0, sticky=W + N, pady=5, padx=5)
    Label(frame_entries, text="Recipient:").grid(row=1, sticky=W, pady=5, padx=5)
    Label(frame_entries, text="Amount:").grid(row=2, sticky=W, pady=5, padx=5)
    Label(frame_entries, text="Data:", height=4).grid(row=3, sticky=W, pady=5, padx=5)
    Label(frame_entries, text="Operation:", height=4).grid(row=4, sticky=W, pady=5, padx=5)
    Label(frame_entries, text="URL:").grid(row=5, sticky=W + S, pady=5, padx=5)
    Label(frame_entries, text="If you have a BIS URL, copy it, click paste-button\n"
                              "on URL field and then click 'read'."
                              "If you want to send Bismuth\n"
                              "to the shown recipient, click send and then\n"
                              "the confirmation dialog opens.", justify=LEFT).grid(row=6, column=1, sticky=W + S, pady=1, padx=1, columnspan=2)

    Label(frame_entries_r, text="Recipient:").grid(row=0, sticky=W, pady=5, padx=5)
    Label(frame_entries_r, text="Amount:").grid(row=2, sticky=W, pady=5, padx=5)
    Label(frame_entries_r, text="Data:", height=4).grid(row=3, sticky=W, pady=5, padx=5)
    Label(frame_entries_r, text="Operation:", height=4).grid(row=4, sticky=W, pady=5, padx=5)
    Label(frame_entries_r, text="URL:").grid(row=5, sticky=W + S, pady=5, padx=5)

    Label(frame_entries_r, text="Enter amount and if wanted, a message in field Data.\n"
                                "Your address is automatically used. Click create and copy the url.", justify=LEFT).grid(row=6, column=1, sticky=W + S, pady=1, padx=1, columnspan=2)

    Label(frame_entries_t, text="Address:").grid(row=0, column=0, sticky=W + N, pady=5, padx=5)

    resolve_var = BooleanVar()
    resolve = Checkbutton(frame_entries_t, text="Aliases", variable=resolve_var, command=lambda: refresh(gui_address_t.get()), width=14, anchor=W)
    resolve.grid(row=0, column=5, sticky=W)

    # display the menu
    root.config(menu=menubar)

    # buttons
    send_b = Button(frame_send, text="Send Bismuth", command=lambda: send_confirm(str(amount.get()).strip(), recipient.get().strip(), operation.get().strip(), (openfield.get("1.0", END)).strip()), height=2, width=22, font=("Tahoma", 12))
    send_b.grid(row=0, column=0)

    frame_logo_buttons = Frame(frame_send)
    frame_logo_buttons.grid(row=5, column=0, padx=5, pady=5)

    encrypt_b = Button(frame_logo_buttons, text="Encrypt", command=encrypt_get_password, height=1, width=8)
    encrypt_b.grid(row=0, column=0)
    decrypt_b = Button(frame_logo_buttons, text="Unlock", command=decrypt_get_password, height=1, width=8)
    decrypt_b.grid(row=0, column=1)
    lock_b = Button(frame_logo_buttons, text="Locked", command=lambda: lock_fn(lock_b), height=1, width=8, state=DISABLED)
    lock_b.grid(row=0, column=2)

    encryption_button_refresh()
    # buttons

    # refreshables

    # update balance label
    balance_raw = StringVar()
    balance_var = StringVar()

    # address_var = StringVar()
    # address_var_label = Label(frame_coins, textvariable=address_var, font=("Tahoma", 8, "bold"))
    # address_var_label.grid(row=0, column=0, sticky=S, padx=15)

    balance_msg_label = Label(frame_coins, textvariable=balance_var, font=("Tahoma", 16, "bold"))
    balance_msg_label.grid(row=1, column=0, sticky=S, padx=15)

    balance_msg_label_sendtab = Label(frame_send, textvariable=balance_var, font=("Tahoma"))
    balance_msg_label_sendtab.grid(row=3, column=0, sticky=N + S)

    debit_var = StringVar()
    spent_msg_label = Label(frame_coins, textvariable=debit_var, font=("Tahoma", 12))
    spent_msg_label.grid(row=2, column=0, sticky=N + E, padx=15)

    credit_var = StringVar()
    received_msg_label = Label(frame_coins, textvariable=credit_var, font=("Tahoma", 12))
    received_msg_label.grid(row=3, column=0, sticky=N + E, padx=15)

    fees_var = StringVar()
    fees_paid_msg_label = Label(frame_coins, textvariable=fees_var, font=("Tahoma", 12))
    fees_paid_msg_label.grid(row=4, column=0, sticky=N + E, padx=15)

    rewards_var = StringVar()
    rewards_paid_msg_label = Label(frame_coins, textvariable=rewards_var, font=("Tahoma", 12))
    rewards_paid_msg_label.grid(row=5, column=0, sticky=N + E, padx=15)

    bl_height_var = StringVar()
    block_height_label = Label(frame_bottom, textvariable=bl_height_var)
    block_height_label.grid(row=0, column=7, sticky=S + E, padx=5)

    ip_connected_var = StringVar()
    ip_connected_label = Label(frame_bottom, textvariable=ip_connected_var)
    ip_connected_label.grid(row=0, column=8, sticky=S + E, padx=5)

    diff_msg_var = StringVar()
    diff_msg_label = Label(frame_bottom, textvariable=diff_msg_var)
    diff_msg_label.grid(row=0, column=5, sticky=S + E, padx=5)

    sync_msg_var = StringVar()
    sync_msg_label = Label(frame_bottom, textvariable=sync_msg_var)
    sync_msg_label.grid(row=0, column=0, sticky=N + E, padx=15)

    hash_var = StringVar()
    hash_var_label = Label(frame_bottom, textvariable=hash_var)
    hash_var_label.grid(row=0, column=4, sticky=S + E, padx=5)

    mempool_count_var = StringVar()
    mempool_count_var_label = Label(frame_bottom, textvariable=mempool_count_var)
    mempool_count_var_label.grid(row=0, column=3, sticky=S + E, padx=5)

    server_timestamp_var = StringVar()
    server_timestamp_label = Label(frame_bottom, textvariable=server_timestamp_var)
    server_timestamp_label.grid(row=0, column=9, sticky=S + E, padx=5)

    encode_var = BooleanVar()
    alias_cb_var = BooleanVar()
    msg_var = BooleanVar()
    encrypt_var = BooleanVar()
    all_spend_var = BooleanVar()

    # address and amount

    # gui_address.configure(state="readonly")

    gui_copy_address = Button(frame_entries, text="Copy", command=address_copy, font=("Tahoma", 7))
    gui_copy_address.grid(row=0, column=2, sticky=W)

    gui_copy_recipient = Button(frame_entries, text="Copy", command=recipient_copy, font=("Tahoma", 7))
    gui_copy_recipient.grid(row=1, column=2, sticky=W)

    gui_insert_recipient = Button(frame_entries, text="Paste", command=recipient_insert, font=("Tahoma", 7))
    gui_insert_recipient.grid(row=1, column=3, sticky=W)

    # gui_help = Button(frame_entries, text="Help", command=help, font=("Tahoma", 7))
    # gui_help.grid(row=4, column=2, sticky=W + E, padx=(5, 0))

    gui_all_spend = Checkbutton(frame_entries, text="All", variable=all_spend_var, command=all_spend, font=("Tahoma", 7))
    gui_all_spend.grid(row=2, column=2, sticky=W)

    gui_all_spend_clear = Button(frame_entries, text="Clear", command=all_spend_clear, font=("Tahoma", 7))
    gui_all_spend_clear.grid(row=2, column=3, sticky=W)

    data_insert_clipboard = Button(frame_entries, text="Paste", command=data_insert, font=("Tahoma", 7))
    data_insert_clipboard.grid(row=3, column=2)

    data_insert_clear = Button(frame_entries, text="Clear", command=data_insert_clear, font=("Tahoma", 7))
    data_insert_clear.grid(row=3, column=3, sticky=W)

    url_insert_clipboard = Button(frame_entries, text="Paste", command=url_insert, font=("Tahoma", 7))
    url_insert_clipboard.grid(row=5, column=2, sticky=W)

    read_url_b = Button(frame_entries, text="Read", command=lambda: read_url_clicked(url.get()), font=("Tahoma", 7))
    read_url_b.grid(row=5, column=3, sticky=W)

    data_insert_clipboard = Button(frame_entries_r, text="Paste", command=data_insert_r, font=("Tahoma", 7))
    data_insert_clipboard.grid(row=3, column=2)

    data_insert_clear = Button(frame_entries_r, text="Clear", command=data_insert_clear, font=("Tahoma", 7))
    data_insert_clear.grid(row=3, column=3, sticky=W)

    gui_copy_address_r = Button(frame_entries_r, text="Copy", command=address_copy, font=("Tahoma", 7))
    gui_copy_address_r.grid(row=0, column=2, sticky=W)

    gui_copy_url_r = Button(frame_entries_r, text="Copy", command=url_copy, font=("Tahoma", 7))
    gui_copy_url_r.grid(row=5, column=3, sticky=W)

    create_url_b = Button(frame_entries_r, text="Create", command=lambda: create_url_clicked(gui_address_t.get(), amount_r.get(), operation_r.get(), openfield_r.get("1.0", END).strip()), font=("Tahoma", 7))
    create_url_b.grid(row=5, column=2, sticky=W)

    gui_paste_address = Button(frame_entries_t, text="Paste", command=address_insert, font=("Tahoma", 7))
    gui_paste_address.grid(row=0, column=2, sticky=W)

    gui_watch = Button(frame_entries_t, text="Watch", command=watch, font=("Tahoma", 7))
    gui_watch.grid(row=0, column=3, sticky=W)

    gui_unwatch = Button(frame_entries_t, text="Reset", command=unwatch, font=("Tahoma", 7))
    gui_unwatch.grid(row=0, column=4, sticky=W, padx=(0, 5))

    # hyperlinks
    hyperlink_blog = Button(frame_hyperlinks, text="Github Repository", command=lambda: webbrowser.open("https://hypernodes.bismuth.live/?page_id=20", new=1), font=("Tahoma", 7))
    hyperlink_blog.grid(row=0, column=0, sticky=N + E + S + W, padx=1, pady=1)

    hyperlink_BISGit = Button(frame_hyperlinks, text="Github Repository", command=lambda: webbrowser.open("https://github.com/bismuthfoundation/Bismuth/releases", new=1), font=("Tahoma", 7))
    hyperlink_BISGit.grid(row=0, column=0, sticky=N + E + S + W, padx=1, pady=1)

    hyperlink_BE = Button(frame_hyperlinks, text="Blockchain Explorer", command=lambda: webbrowser.open("https://bismuth.online", new=1), font=("Tahoma", 7))
    hyperlink_BE.grid(row=1, column=0, sticky=N + E + S + W, padx=1, pady=1)

    hyperlink_howto = Button(frame_hyperlinks, text="Guides", command=lambda: webbrowser.open("https://github.com/EggPool/BismuthHowto", new=1), font=("Tahoma", 7))
    hyperlink_howto.grid(row=2, column=0, sticky=N + E + S + W, padx=1, pady=1)

    hyperlink_bct = Button(frame_hyperlinks, text="Bitcointalk", command=lambda: webbrowser.open("https://bitcointalk.org/index.php?topic=1896497.0", new=1), font=("Tahoma", 7))
    hyperlink_bct.grid(row=3, column=0, sticky=N + E + S + W, padx=1, pady=1)

    hyperlink_tornado = Button(frame_hyperlinks, text="Tornado Wallet", fg="red", command=lambda: webbrowser.open("https://github.com/bismuthfoundation/TornadoWallet/releases", new=1), font=("Tahoma", 7))
    hyperlink_tornado.grid(row=4, column=0, sticky=N + E + S + W, padx=1, pady=1)
    # hyperlinks

    # supportbutton
    #dev_support = Button(frame_support, text="Collect Info for Support", command=lambda: support_collection(str(sync_msg_var), str(version_var)), font=("Tahoma", 7))
    #dev_support.grid(row=98, column=98, sticky=N + E + S + W, padx=1, pady=1)
    # supportbutton

    gui_address_t = Entry(frame_entries_t, width=60)
    gui_address_t.grid(row=0, column=1, sticky=W, pady=5, padx=5)
    gui_address_t.insert(0, keyring.myaddress)

    sender_address = Entry(frame_entries, width=60)
    sender_address.insert(0, keyring.myaddress)
    sender_address.grid(row=0, column=1, sticky=W, pady=5, padx=5)
    sender_address.configure(state=DISABLED)

    recipient = Entry(frame_entries, width=60)
    recipient.grid(row=1, column=1, sticky=W, pady=5, padx=5)

    amount = Entry(frame_entries, width=60)
    amount.grid(row=2, column=1, sticky=W, pady=5, padx=5)
    amount.insert(0, "0.00000000")

    openfield = Text(frame_entries, width=60, height=5, font=("Tahoma", 8))
    openfield.grid(row=3, column=1, sticky=W, pady=5, padx=5)

    operation = Entry(frame_entries, width=60)
    operation.grid(row=4, column=1, sticky=W, pady=5, padx=5)

    url = Entry(frame_entries, width=60)
    url.grid(row=5, column=1, sticky=W, pady=5, padx=5)
    url.insert(0, "bis://")

    encode = Checkbutton(frame_tick, text="Base64 Encoding", variable=encode_var, command=all_spend_check, width=14, anchor=W)
    encode.grid(row=0, column=0, sticky=W)

    msg = Checkbutton(frame_tick, text="Message", variable=msg_var, command=all_spend_check, width=14, anchor=W)
    msg.grid(row=1, column=0, sticky=W)

    encr = Checkbutton(frame_tick, text="Encrypt with PK", variable=encrypt_var, command=all_spend_check, width=14, anchor=W)
    encr.grid(row=2, column=0, sticky=W)

    alias_cb = Checkbutton(frame_tick, text="Alias Recipient", variable=alias_cb_var, command=None, width=14, anchor=W)
    alias_cb.grid(row=4, column=0, sticky=W)

    balance_enumerator = Entry(frame_entries, width=5)
    # address and amount

    # logo

    # logo_hash_decoded = base64.b64decode(icons.logo_hash)
    # logo = PhotoImage(data="graphics/logo.png")

    logo_img = PIL.Image.open("graphics/logo.png")
    logo = PIL.ImageTk.PhotoImage(logo_img)

    Label(frame_logo, image=logo).grid(column=0, row=0)
    # logo

    node_connect()
    refresh_auto()
    root.mainloop()

