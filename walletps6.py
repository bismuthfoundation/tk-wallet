#!/usr/bin/env python3
"""
Bismuth Light Wallet - PySide6 Version
Complete rewrite with proper logging and error handling
"""

import ast
import base64
import csv
import glob
import hashlib
import json
import os
import random
import re
import sys
import tarfile
import threading
import time
import webbrowser
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Optional, Tuple, Dict, List, Any
from dataclasses import dataclass

# PySide6 imports
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QLabel, QLineEdit, QPushButton, QTextEdit,
    QTabWidget, QCheckBox, QTreeWidget, QTreeWidgetItem,
    QFrame, QMessageBox, QFileDialog, QDialog,
    QDialogButtonBox, QMenu, QMenuBar, QGroupBox, QListWidget,
    QTextBrowser, QSplitter
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer, QObject, Slot
from PySide6.QtGui import QAction, QPixmap, QIcon, QFont

# External imports
try:
    import PIL.Image
    import pyqrcode
    import requests
    from Cryptodome.Cipher import AES, PKCS1_OAEP
    from Cryptodome.Hash import SHA
    from Cryptodome.PublicKey import RSA
    from Cryptodome.Random import get_random_bytes
    from Cryptodome.Signature import PKCS1_v1_5
except ImportError as e:
    print(f"Missing required library: {e}")
    sys.exit(1)

# Bismuth specific imports
try:
    from bisbasic import essentials, options
    from bisbasic.quantizer import quantize_eight
    from bismuthclient import bismuthmultiwallet, bismuthutil
    from bismuthclient.bismuthclient import rpcconnections
    from bismuthclient.bismuthcrypto import keys_load, keys_load_new, keys_save
    from bismuthclient.simplecrypt import encrypt, decrypt
    from polysign.signerfactory import SignerFactory
    import recovery
    from ipfs import ipfs
except ImportError as e:
    print(f"Missing Bismuth library: {e}")
    sys.exit(1)

__version__ = '0.9.4'


class SimpleLogger:
    """Simple logger that doesn't cause attribute errors"""

    def __init__(self, name='wallet'):
        self.name = name

    def info(self, msg):
        print(f"[INFO] {msg}")

    def warning(self, msg):
        print(f"[WARNING] {msg}")

    def error(self, msg):
        print(f"[ERROR] {msg}")

    def debug(self, msg):
        print(f"[DEBUG] {msg}")


@dataclass
class Keys:
    """Data class for key management"""
    key: Optional[Any] = None
    public_key_readable: Optional[str] = None
    private_key_readable: Optional[str] = None
    encrypted: bool = False
    unlocked: bool = False
    public_key_b64encoded: Optional[bytes] = None
    myaddress: Optional[str] = None
    keyfile: Optional[Any] = None


class WalletState:
    """Manages wallet state and connection"""

    def __init__(self):
        self.connected = False
        self.connecting = False
        self.s = None
        self.socket_wait = threading.Lock()
        self.ip = None
        self.port = None
        self.light_ip = {}
        self.mempool_total = []
        self.balance = None
        self.first_run = True
        self.stats_timestamp = None


class NetworkWorker(QThread):
    """Worker thread for network operations"""
    status_update = Signal(dict)
    balance_update = Signal(dict)
    transactions_update = Signal(list)
    mempool_update = Signal(list)
    error_occurred = Signal(str)

    def __init__(self, wallet_state: WalletState, address: str):
        super().__init__()
        self.wallet_state = wallet_state
        self.address = address

    def run(self):
        """Execute network operations in thread"""
        try:
            if not self.wallet_state.s:
                self.error_occurred.emit("Not connected")
                return

            with self.wallet_state.socket_wait:
                # Get status
                self.wallet_state.s._send("statusget")
                status = self.wallet_state.s._receive()

                # Get balance
                self.wallet_state.s._send("balanceget")
                self.wallet_state.s._send(self.address)
                balance = self.wallet_state.s._receive()

                # Get transactions
                self.wallet_state.s._send("addlistlim")
                self.wallet_state.s._send(self.address)
                self.wallet_state.s._send("20")
                transactions = self.wallet_state.s._receive()

                # Get mempool
                self.wallet_state.s._send("mpget")
                mempool = self.wallet_state.s._receive()

            # Emit signals with data
            self.status_update.emit({'status': status})
            self.balance_update.emit({
                'balance': balance[0] if balance else 0,
                'credit': balance[1] if balance else 0,
                'debit': balance[2] if balance else 0,
                'fees': balance[3] if balance else 0,
                'rewards': balance[4] if balance else 0
            })
            self.transactions_update.emit(transactions if transactions else [])
            self.mempool_update.emit(mempool if mempool else [])

        except Exception as e:
            self.error_occurred.emit(str(e))


class MainWindow(QMainWindow):
    """Main wallet window"""

    def __init__(self):
        super().__init__()

        # Initialize components first
        self.logger = SimpleLogger()
        self.keyring = Keys()
        self.wallet_state = WalletState()
        self.bismuth_util = bismuthutil.BismuthUtil()
        self.current_balance = Decimal(0)

        # Load configuration
        self.config = options.Get()
        self.config.read()
        self.setup_config()

        # Initialize UI
        self.init_ui()

        # Load wallet keys
        self.load_wallet_keys()

        # Setup connections
        self.setup_initial_connection()

        # Start auto-refresh timer
        self.setup_timers()

    def setup_config(self):
        """Setup configuration from config file"""
        self.wallet_state.light_ip = self.config.light_ip
        self.wallet_state.port = int(self.config.port)
        self.version = self.config.version

        # Update light_ip from API if possible
        try:
            response = requests.get("https://bismuth.world/api/legacy.json", timeout=5)
            if response.status_code == 200:
                self.wallet_state.light_ip.clear()
                for entry in response.json():
                    if entry.get("active"):
                        self.wallet_state.light_ip[entry["ip"]] = str(entry["port"])
        except:
            self.logger.warning("Could not fetch server list from API, using config")

    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle(f"Bismuth Light Wallet - v{__version__}")
        self.setMinimumSize(1200, 700)

        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Main layout
        main_layout = QVBoxLayout(central_widget)

        # Create tab widget
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        # Create all tabs
        self.create_overview_tab()
        self.create_history_tab()
        self.create_send_tab()
        self.create_receive_tab()
        self.create_tokens_tab()

        # Status bar
        self.create_status_bar()

        # Menu bar
        self.create_menu_bar()

    def create_overview_tab(self):
        """Create overview tab"""
        overview_widget = QWidget()
        layout = QGridLayout(overview_widget)

        # Balance group
        balance_group = QGroupBox("Balance Information")
        balance_layout = QVBoxLayout()

        self.balance_label = QLabel("Balance: Loading...")
        self.balance_label.setFont(QFont("Arial", 16, QFont.Bold))
        balance_layout.addWidget(self.balance_label)

        self.received_label = QLabel("Received Total: -")
        balance_layout.addWidget(self.received_label)

        self.sent_label = QLabel("Sent Total: -")
        balance_layout.addWidget(self.sent_label)

        self.fees_label = QLabel("Fees Paid: -")
        balance_layout.addWidget(self.fees_label)

        self.rewards_label = QLabel("Rewards: -")
        balance_layout.addWidget(self.rewards_label)

        balance_group.setLayout(balance_layout)
        layout.addWidget(balance_group, 0, 0)

        # Wallet info group
        wallet_group = QGroupBox("Wallet")
        wallet_layout = QVBoxLayout()

        # Address field
        address_layout = QHBoxLayout()
        address_layout.addWidget(QLabel("Address:"))
        self.address_field = QLineEdit()
        self.address_field.setReadOnly(True)
        address_layout.addWidget(self.address_field)

        copy_btn = QPushButton("Copy")
        copy_btn.clicked.connect(self.copy_address)
        address_layout.addWidget(copy_btn)
        wallet_layout.addLayout(address_layout)

        # Encryption buttons
        enc_layout = QHBoxLayout()
        self.encrypt_btn = QPushButton("Encrypt")
        self.encrypt_btn.clicked.connect(self.encrypt_wallet)
        enc_layout.addWidget(self.encrypt_btn)

        self.unlock_btn = QPushButton("Unlock")
        self.unlock_btn.clicked.connect(self.unlock_wallet)
        enc_layout.addWidget(self.unlock_btn)

        self.lock_btn = QPushButton("Lock")
        self.lock_btn.clicked.connect(self.lock_wallet)
        self.lock_btn.setEnabled(False)
        enc_layout.addWidget(self.lock_btn)

        wallet_layout.addLayout(enc_layout)
        wallet_group.setLayout(wallet_layout)
        layout.addWidget(wallet_group, 0, 1)

        self.tabs.addTab(overview_widget, "Overview")

    def create_history_tab(self):
        """Create transaction history tab"""
        history_widget = QWidget()
        layout = QVBoxLayout(history_widget)

        # Address controls
        controls = QHBoxLayout()
        controls.addWidget(QLabel("Address:"))

        self.watch_address = QLineEdit()
        controls.addWidget(self.watch_address)

        watch_btn = QPushButton("Watch")
        watch_btn.clicked.connect(self.watch_address_clicked)
        controls.addWidget(watch_btn)

        reset_btn = QPushButton("Reset")
        reset_btn.clicked.connect(self.reset_watch)
        controls.addWidget(reset_btn)

        layout.addLayout(controls)

        # Transaction tree
        self.tx_tree = QTreeWidget()
        self.tx_tree.setHeaderLabels(['Time', 'Sender', 'Recipient', 'Amount', 'Type'])
        self.tx_tree.setAlternatingRowColors(True)
        layout.addWidget(self.tx_tree)

        self.tabs.addTab(history_widget, "History")

    def create_send_tab(self):
        """Create send transaction tab"""
        send_widget = QWidget()
        layout = QGridLayout(send_widget)

        row = 0

        # Recipient
        layout.addWidget(QLabel("Recipient:"), row, 0)
        self.recipient_field = QLineEdit()
        layout.addWidget(self.recipient_field, row, 1)
        row += 1

        # Amount
        layout.addWidget(QLabel("Amount:"), row, 0)
        self.amount_field = QLineEdit("0.00000000")
        layout.addWidget(self.amount_field, row, 1)

        self.all_checkbox = QCheckBox("Send All")
        layout.addWidget(self.all_checkbox, row, 2)
        row += 1

        # Data field
        layout.addWidget(QLabel("Data:"), row, 0, Qt.AlignTop)
        self.data_field = QTextEdit()
        self.data_field.setMaximumHeight(100)
        layout.addWidget(self.data_field, row, 1)
        row += 1

        # Operation
        layout.addWidget(QLabel("Operation:"), row, 0)
        self.operation_field = QLineEdit()
        layout.addWidget(self.operation_field, row, 1)
        row += 1

        # Options
        options_group = QGroupBox("Options")
        options_layout = QVBoxLayout()

        self.base64_checkbox = QCheckBox("Base64 Encoding")
        options_layout.addWidget(self.base64_checkbox)

        self.message_checkbox = QCheckBox("Mark as Message")
        options_layout.addWidget(self.message_checkbox)

        self.encrypt_checkbox = QCheckBox("Encrypt with Public Key")
        options_layout.addWidget(self.encrypt_checkbox)

        options_group.setLayout(options_layout)
        layout.addWidget(options_group, row, 0, 1, 2)
        row += 1

        # Send button
        self.send_btn = QPushButton("Send Transaction")
        self.send_btn.setMinimumHeight(50)
        self.send_btn.clicked.connect(self.send_transaction)
        layout.addWidget(self.send_btn, row, 0, 1, 3)

        self.tabs.addTab(send_widget, "Send")

    def create_receive_tab(self):
        """Create receive tab"""
        receive_widget = QWidget()
        layout = QGridLayout(receive_widget)

        row = 0

        # Address
        layout.addWidget(QLabel("Your Address:"), row, 0)
        self.receive_address = QLineEdit()
        self.receive_address.setReadOnly(True)
        layout.addWidget(self.receive_address, row, 1)
        row += 1

        # Amount
        layout.addWidget(QLabel("Amount:"), row, 0)
        self.receive_amount = QLineEdit("0.00000000")
        layout.addWidget(self.receive_amount, row, 1)
        row += 1

        # Message
        layout.addWidget(QLabel("Message:"), row, 0, Qt.AlignTop)
        self.receive_message = QTextEdit()
        self.receive_message.setMaximumHeight(100)
        layout.addWidget(self.receive_message, row, 1)
        row += 1

        # URL
        layout.addWidget(QLabel("Payment URL:"), row, 0)
        self.url_field = QLineEdit()
        layout.addWidget(self.url_field, row, 1)

        create_btn = QPushButton("Create URL")
        create_btn.clicked.connect(self.create_payment_url)
        layout.addWidget(create_btn, row, 2)
        row += 1

        # QR button
        qr_btn = QPushButton("Show QR Code")
        qr_btn.clicked.connect(self.show_qr)
        layout.addWidget(qr_btn, row, 0, 1, 3)

        self.tabs.addTab(receive_widget, "Receive")

    def create_tokens_tab(self):
        """Create tokens tab"""
        tokens_widget = QWidget()
        layout = QVBoxLayout(tokens_widget)

        self.tokens_list = QListWidget()
        layout.addWidget(self.tokens_list)

        # Token controls
        controls = QHBoxLayout()
        self.token_name = QLineEdit()
        self.token_name.setPlaceholderText("Token name")
        controls.addWidget(self.token_name)

        self.token_amount = QLineEdit()
        self.token_amount.setPlaceholderText("Amount")
        controls.addWidget(self.token_amount)

        transfer_btn = QPushButton("Transfer")
        transfer_btn.clicked.connect(self.transfer_token)
        controls.addWidget(transfer_btn)

        layout.addLayout(controls)

        # Connect tab changed signal
        self.tabs.currentChanged.connect(self.on_tab_changed)

        self.tabs.addTab(tokens_widget, "Tokens")

    def create_status_bar(self):
        """Create status bar"""
        self.status_bar = self.statusBar()

        self.connection_status = QLabel("Disconnected")
        self.status_bar.addWidget(self.connection_status)

        self.block_height = QLabel("Block: -")
        self.status_bar.addWidget(self.block_height)

        self.sync_status = QLabel("Sync: -")
        self.status_bar.addWidget(self.sync_status)

    def create_menu_bar(self):
        """Create menu bar"""
        menubar = self.menuBar()

        # Wallet menu
        wallet_menu = menubar.addMenu("Wallet")

        load_action = QAction("Load Wallet", self)
        load_action.triggered.connect(self.load_wallet_dialog)
        wallet_menu.addAction(load_action)

        backup_action = QAction("Backup Wallet", self)
        backup_action.triggered.connect(self.backup_wallet)
        wallet_menu.addAction(backup_action)

        wallet_menu.addSeparator()

        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        wallet_menu.addAction(exit_action)

        # Connection menu
        connection_menu = menubar.addMenu("Connection")
        for ip, port in self.wallet_state.light_ip.items():
            action = QAction(f"{ip}:{port}", self)
            action.triggered.connect(lambda checked, i=ip, p=port: self.connect_to_node(i, p))
            connection_menu.addAction(action)

    def load_wallet_keys(self):
        """Load wallet keys with proper error handling"""
        try:
            # Determine which key file to use
            if os.path.exists("privkey.der"):
                private_key_file = "privkey.der"
            else:
                private_key_file = "privkey_encrypted.der"

            public_key_file = "pubkey.der"

            # Check for wallet.der, create if needed
            if not os.path.exists("wallet.der"):
                self.logger.info("Creating new wallet...")
                # This would normally call the key generation function
                # For now, we'll just check for existing keys

            # Load keys
            result = keys_load(private_key_file, public_key_file)

            if result:
                (self.keyring.key, self.keyring.public_key_readable,
                 self.keyring.private_key_readable, self.keyring.encrypted,
                 self.keyring.unlocked, self.keyring.public_key_b64encoded,
                 self.keyring.myaddress, self.keyring.keyfile) = result

                # Update UI elements
                if self.keyring.myaddress:
                    self.address_field.setText(self.keyring.myaddress)
                    self.receive_address.setText(self.keyring.myaddress)
                    self.watch_address.setText(self.keyring.myaddress)

                self.update_encryption_buttons()
                self.logger.info(f"Wallet loaded: {self.keyring.myaddress}")
            else:
                self.logger.error("Failed to load wallet keys")

        except Exception as e:
            self.logger.error(f"Error loading wallet: {e}")
            QMessageBox.critical(self, "Error", f"Failed to load wallet: {e}")

    def setup_initial_connection(self):
        """Setup initial node connection"""
        # Try connecting to a node
        for ip, port in self.wallet_state.light_ip.items():
            if self.connect_to_node(ip, port):
                break

    def connect_to_node(self, ip, port):
        """Connect to a specific node"""
        try:
            self.logger.info(f"Connecting to {ip}:{port}")
            self.wallet_state.s = rpcconnections.Connection((ip, int(port)))
            self.wallet_state.ip = ip
            self.wallet_state.port = port
            self.wallet_state.connected = True

            self.connection_status.setText(f"Connected: {ip}:{port}")
            self.refresh_wallet_data()
            return True

        except Exception as e:
            self.logger.error(f"Failed to connect to {ip}:{port}: {e}")
            self.wallet_state.connected = False
            self.connection_status.setText("Disconnected")
            return False

    def setup_timers(self):
        """Setup auto-refresh timer"""
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_wallet_data)
        self.refresh_timer.start(30000)  # 30 seconds

        # Initial refresh
        QTimer.singleShot(1000, self.refresh_wallet_data)

    @Slot()
    def refresh_wallet_data(self):
        """Refresh wallet data from network"""
        if not self.wallet_state.connected or not self.keyring.myaddress:
            return

        # Create and start worker thread
        self.worker = NetworkWorker(self.wallet_state, self.keyring.myaddress)
        self.worker.status_update.connect(self.update_status)
        self.worker.balance_update.connect(self.update_balance)
        self.worker.transactions_update.connect(self.update_transactions)
        self.worker.mempool_update.connect(self.update_mempool)
        self.worker.error_occurred.connect(self.handle_error)
        self.worker.start()

    @Slot(dict)
    def update_status(self, data):
        """Update status information"""
        try:
            status = data.get('status', [])
            if len(status) > 9:
                self.wallet_state.stats_timestamp = status[9]

                # Get additional blockchain info
                with self.wallet_state.socket_wait:
                    self.wallet_state.s._send("blocklast")
                    block_info = self.wallet_state.s._receive()

                if block_info:
                    height = block_info[0]
                    self.block_height.setText(f"Block: {height}")

                    # Calculate sync status
                    timestamp = block_info[1]
                    time_diff = time.time() - float(timestamp)
                    if time_diff > 300:
                        self.sync_status.setText(f"Sync: {int(time_diff / 60)}m behind")
                        self.sync_status.setStyleSheet("color: red")
                    else:
                        self.sync_status.setText(f"Sync: OK")
                        self.sync_status.setStyleSheet("color: green")

        except Exception as e:
            self.logger.error(f"Error updating status: {e}")

    @Slot(dict)
    def update_balance(self, data):
        """Update balance display"""
        try:
            balance = Decimal(str(data.get('balance', 0)))
            credit = Decimal(str(data.get('credit', 0)))
            debit = Decimal(str(data.get('debit', 0)))
            fees = Decimal(str(data.get('fees', 0)))
            rewards = Decimal(str(data.get('rewards', 0)))

            self.current_balance = balance

            self.balance_label.setText(f"Balance: {balance:.8f} BIS")
            self.received_label.setText(f"Received Total: {credit:.8f} BIS")
            self.sent_label.setText(f"Sent Total: {debit:.8f} BIS")
            self.fees_label.setText(f"Fees Paid: {fees:.8f} BIS")
            self.rewards_label.setText(f"Rewards: {rewards:.8f} BIS")

        except Exception as e:
            self.logger.error(f"Error updating balance: {e}")

    @Slot(list)
    def update_transactions(self, transactions):
        """Update transaction history"""
        try:
            self.tx_tree.clear()

            for tx in transactions:
                if len(tx) > 11:
                    timestamp = datetime.fromtimestamp(float(tx[1])).strftime('%y-%m-%d %H:%M')
                    sender = tx[2][:12] + "..."
                    recipient = tx[3][:12] + "..."
                    amount = tx[4]

                    # Determine type
                    if tx[11].startswith("msg"):
                        tx_type = "MSG"
                    else:
                        tx_type = "TX"

                    item = QTreeWidgetItem([timestamp, sender, recipient, amount, tx_type])

                    # Color based on direction
                    if tx[3] == self.keyring.myaddress:
                        for i in range(5):
                            item.setBackground(i, Qt.green)
                    else:
                        for i in range(5):
                            item.setBackground(i, Qt.yellow)

                    self.tx_tree.addTopLevelItem(item)

        except Exception as e:
            self.logger.error(f"Error updating transactions: {e}")

    @Slot(list)
    def update_mempool(self, mempool):
        """Update mempool information"""
        self.wallet_state.mempool_total = mempool

    @Slot(str)
    def handle_error(self, error):
        """Handle network errors"""
        self.logger.error(f"Network error: {error}")
        self.wallet_state.connected = False
        self.connection_status.setText("Disconnected")

    def send_transaction(self):
        """Send a transaction"""
        try:
            if not self.keyring.key:
                QMessageBox.warning(self, "Error", "Wallet is locked")
                return

            recipient = self.recipient_field.text().strip()
            amount = self.amount_field.text().strip()
            operation = self.operation_field.text().strip()
            openfield = self.data_field.toPlainText().strip()

            # Validate inputs
            if not recipient:
                QMessageBox.warning(self, "Error", "Recipient address required")
                return

            try:
                amount = quantize_eight(amount)
            except:
                QMessageBox.warning(self, "Error", "Invalid amount")
                return

            # Handle options
            if self.encrypt_checkbox.isChecked():
                openfield = self.encrypt_data(openfield, recipient)

            if self.base64_checkbox.isChecked():
                openfield = base64.b64encode(openfield.encode()).decode()

            if self.message_checkbox.isChecked():
                openfield = "msg=" + openfield

            # Calculate fee
            fee = essentials.fee_calculate(openfield, operation)

            # Confirmation
            reply = QMessageBox.question(
                self, "Confirm Transaction",
                f"Send {amount} BIS to {recipient[:20]}...?\n"
                f"Fee: {fee} BIS\n"
                f"Total: {Decimal(amount) + Decimal(fee)} BIS"
            )

            if reply == QMessageBox.Yes:
                self.execute_send(amount, recipient, operation, openfield)

        except Exception as e:
            self.logger.error(f"Error sending transaction: {e}")
            QMessageBox.critical(self, "Error", str(e))

    def execute_send(self, amount, recipient, operation, openfield):
        """Execute the actual send"""
        try:
            # Create and sign transaction
            timestamp = '%.2f' % time.time()
            transaction = (
                str(timestamp),
                str(self.keyring.myaddress),
                str(recipient),
                '%.8f' % float(amount),
                str(operation),
                str(openfield)
            )

            # Sign
            h = SHA.new(str(transaction).encode())
            signer = PKCS1_v1_5.new(self.keyring.key)
            signature = signer.sign(h)
            signature_enc = base64.b64encode(signature)

            # Submit
            tx_submit = (
                str(timestamp),
                str(self.keyring.myaddress),
                str(recipient),
                '%.8f' % float(amount),
                str(signature_enc.decode()),
                str(self.keyring.public_key_b64encoded.decode()),
                str(operation),
                str(openfield)
            )

            with self.wallet_state.socket_wait:
                self.wallet_state.s._send("mpinsert")
                self.wallet_state.s._send(tx_submit)
                reply = self.wallet_state.s._receive()

            if reply and reply[-1] == "Success":
                QMessageBox.information(self, "Success", "Transaction sent!")
                self.refresh_wallet_data()
            else:
                QMessageBox.warning(self, "Error", f"Transaction failed: {reply}")

        except Exception as e:
            self.logger.error(f"Error executing send: {e}")
            QMessageBox.critical(self, "Error", str(e))

    def encrypt_data(self, data, recipient):
        """Encrypt data for recipient"""
        try:
            # Get recipient's public key
            with self.wallet_state.socket_wait:
                self.wallet_state.s._send("pubkeyget")
                self.wallet_state.s._send(recipient)
                pubkey_b64 = self.wallet_state.s._receive()

            if not pubkey_b64:
                return data

            # Decrypt and import public key
            recipient_key = RSA.importKey(base64.b64decode(pubkey_b64).decode())

            # Encrypt with AES + RSA
            session_key = get_random_bytes(16)
            cipher_aes = AES.new(session_key, AES.MODE_EAX)
            cipher_rsa = PKCS1_OAEP.new(recipient_key)

            ciphertext, tag = cipher_aes.encrypt_and_digest(data.encode())
            enc_session_key = cipher_rsa.encrypt(session_key)

            return str([cipher_aes.nonce, tag, ciphertext, enc_session_key])

        except Exception as e:
            self.logger.error(f"Encryption failed: {e}")
            return data

    def copy_address(self):
        """Copy address to clipboard"""
        QApplication.clipboard().setText(self.keyring.myaddress)
        self.status_bar.showMessage("Address copied", 2000)

    def watch_address_clicked(self):
        """Watch a different address"""
        address = self.watch_address.text().strip()
        if address:
            worker = NetworkWorker(self.wallet_state, address)
            worker.transactions_update.connect(self.update_transactions)
            worker.start()

    def reset_watch(self):
        """Reset to own address"""
        self.watch_address.setText(self.keyring.myaddress)
        self.refresh_wallet_data()

    def create_payment_url(self):
        """Create a payment URL"""
        amount = self.receive_amount.text()
        message = self.receive_message.toPlainText()

        url = self.bismuth_util.create_bis_url(
            self.keyring.myaddress, amount, "", message
        )
        self.url_field.setText(url)
        QApplication.clipboard().setText(url)
        self.status_bar.showMessage("Payment URL created and copied", 2000)

    def show_qr(self):
        """Show QR code for address"""
        try:
            qr = pyqrcode.create(self.keyring.myaddress)
            qr.png('address_qr.png', scale=8)

            dialog = QDialog(self)
            dialog.setWindowTitle("Address QR Code")
            layout = QVBoxLayout()

            label = QLabel()
            pixmap = QPixmap('address_qr.png')
            label.setPixmap(pixmap.scaled(400, 400, Qt.KeepAspectRatio))
            layout.addWidget(label)

            close_btn = QPushButton("Close")
            close_btn.clicked.connect(dialog.close)
            layout.addWidget(close_btn)

            dialog.setLayout(layout)
            dialog.exec()

        except Exception as e:
            self.logger.error(f"QR generation failed: {e}")

    def on_tab_changed(self, index):
        """Handle tab change event"""
        if self.tabs.tabText(index) == "Tokens":
            self.load_tokens()

    def load_tokens(self):
        """Load token list"""
        try:
            if not self.wallet_state.connected:
                return

            with self.wallet_state.socket_wait:
                self.wallet_state.s._send("tokensget")
                self.wallet_state.s._send(self.keyring.myaddress)
                tokens = self.wallet_state.s._receive()

            self.tokens_list.clear()
            if tokens:
                for token, balance in tokens:
                    self.tokens_list.addItem(f"{token}: {balance}")

        except Exception as e:
            self.logger.error(f"Error loading tokens: {e}")

    def transfer_token(self):
        """Transfer tokens"""
        token = self.token_name.text()
        amount = self.token_amount.text()

        if token and amount:
            # Switch to send tab with token operation
            self.operation_field.setText("token:transfer")
            self.data_field.setText(f"{token}:{amount}")
            self.tabs.setCurrentIndex(2)  # Send tab

    def encrypt_wallet(self):
        """Encrypt the wallet file"""
        if self.keyring.encrypted:
            QMessageBox.information(self, "Info", "Wallet already encrypted")
            return

        # Get password
        dialog = QDialog(self)
        dialog.setWindowTitle("Encrypt Wallet")
        layout = QVBoxLayout()

        layout.addWidget(QLabel("Password:"))
        password1 = QLineEdit()
        password1.setEchoMode(QLineEdit.Password)
        layout.addWidget(password1)

        layout.addWidget(QLabel("Confirm:"))
        password2 = QLineEdit()
        password2.setEchoMode(QLineEdit.Password)
        layout.addWidget(password2)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        dialog.setLayout(layout)

        if dialog.exec() == QDialog.Accepted:
            if password1.text() == password2.text():
                try:
                    # Encrypt private key
                    ciphertext = encrypt(password1.text(), self.keyring.private_key_readable)
                    ciphertext_b64 = base64.b64encode(ciphertext).decode()

                    # Save encrypted
                    keys_save(ciphertext_b64, self.keyring.public_key_readable,
                              self.keyring.myaddress, self.keyring.keyfile)

                    # Reload
                    self.load_wallet_keys()
                    QMessageBox.information(self, "Success", "Wallet encrypted")

                except Exception as e:
                    QMessageBox.critical(self, "Error", str(e))
            else:
                QMessageBox.warning(self, "Error", "Passwords don't match")

    def unlock_wallet(self):
        """Unlock encrypted wallet"""
        if not self.keyring.encrypted:
            QMessageBox.information(self, "Info", "Wallet not encrypted")
            return

        # Get password
        dialog = QDialog(self)
        dialog.setWindowTitle("Unlock Wallet")
        layout = QVBoxLayout()

        layout.addWidget(QLabel("Password:"))
        password = QLineEdit()
        password.setEchoMode(QLineEdit.Password)
        layout.addWidget(password)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        dialog.setLayout(layout)

        if dialog.exec() == QDialog.Accepted:
            try:
                # Decrypt private key
                decrypted = decrypt(password.text(),
                                    base64.b64decode(self.keyring.private_key_readable))
                self.keyring.key = RSA.importKey(decrypted)
                self.keyring.unlocked = True

                self.update_encryption_buttons()
                QMessageBox.information(self, "Success", "Wallet unlocked")

            except:
                QMessageBox.critical(self, "Error", "Wrong password")

    def lock_wallet(self):
        """Lock the wallet"""
        self.keyring.key = None
        self.keyring.unlocked = False
        self.update_encryption_buttons()
        self.status_bar.showMessage("Wallet locked", 2000)

    def update_encryption_buttons(self):
        """Update encryption button states"""
        if self.keyring.encrypted:
            self.encrypt_btn.setText("Encrypted")
            self.encrypt_btn.setEnabled(False)
        else:
            self.encrypt_btn.setText("Encrypt")
            self.encrypt_btn.setEnabled(True)

        if self.keyring.unlocked:
            self.unlock_btn.setText("Unlocked")
            self.unlock_btn.setEnabled(False)
            self.lock_btn.setEnabled(True)
        else:
            self.unlock_btn.setText("Unlock")
            self.unlock_btn.setEnabled(True)
            self.lock_btn.setEnabled(False)

    def load_wallet_dialog(self):
        """Load a different wallet file"""
        filename, _ = QFileDialog.getOpenFileName(
            self, "Select Wallet File", "", "Wallet Files (*.der *.json)"
        )

        if filename:
            try:
                result = keys_load_new(filename)
                if result:
                    (self.keyring.key, self.keyring.public_key_readable,
                     self.keyring.private_key_readable, self.keyring.encrypted,
                     self.keyring.unlocked, self.keyring.public_key_b64encoded,
                     self.keyring.myaddress, self.keyring.keyfile) = result

                    self.address_field.setText(self.keyring.myaddress)
                    self.receive_address.setText(self.keyring.myaddress)
                    self.watch_address.setText(self.keyring.myaddress)

                    self.update_encryption_buttons()
                    self.refresh_wallet_data()

                    QMessageBox.information(self, "Success", "Wallet loaded")

            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

    def backup_wallet(self):
        """Backup wallet files"""
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Backup As", "", "Backup Files (*.tar.gz)"
        )

        if filename:
            if not filename.endswith(".tar.gz"):
                filename += ".tar.gz"

            try:
                import tarfile
                files = glob.glob("*.der") + glob.glob("*.json")

                with tarfile.open(filename, "w:gz") as tar:
                    for f in files:
                        if os.path.exists(f):
                            tar.add(f)

                QMessageBox.information(self, "Success", "Wallet backed up")

            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

    def closeEvent(self, event):
        """Handle window close event"""
        if self.refresh_timer:
            self.refresh_timer.stop()
        event.accept()


def main():
    """Main entry point"""
    app = QApplication(sys.argv)
    app.setApplicationName("Bismuth Light Wallet")
    app.setStyle("Fusion")

    # Create main window
    try:
        window = MainWindow()
        window.show()
        sys.exit(app.exec())
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
