#!/usr/bin/env python3
"""
Minimal Bismuth Wallet - Clean and Simple
Essential functions only: View balance, Send transactions, View history
"""

import base64
import os
import sys
import time
from datetime import datetime
from decimal import Decimal

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont, QAction
# PySide6 imports
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QLabel, QLineEdit, QPushButton, QMessageBox, QListWidget, QGroupBox, QFileDialog, QDialog,
    QDialogButtonBox
)

# Bismuth imports
try:
    from bismuthclient.bismuthclient import rpcconnections
    from bismuthclient.bismuthcrypto import keys_load, keys_load_new, keys_save
    from bismuthclient.simplecrypt import encrypt, decrypt
    from bisbasic import essentials
    from bisbasic.quantizer import quantize_eight
    from Cryptodome.Hash import SHA
    from Cryptodome.Signature import PKCS1_v1_5
    from Cryptodome.PublicKey import RSA
    import requests
except ImportError as e:
    print(f"Missing required library: {e}")
    print("Install with: pip install bismuth-client")
    sys.exit(1)

__version__ = '1.0.0'


class PasswordDialog(QDialog):
    """Simple password dialog"""

    def __init__(self, parent, title, message):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(300)

        layout = QVBoxLayout()

        # Message
        layout.addWidget(QLabel(message))

        # Password field
        self.password_field = QLineEdit()
        self.password_field.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_field)

        # Confirm password field for encryption
        if "encrypt" in title.lower():
            layout.addWidget(QLabel("Confirm password:"))
            self.confirm_field = QLineEdit()
            self.confirm_field.setEchoMode(QLineEdit.Password)
            layout.addWidget(self.confirm_field)
        else:
            self.confirm_field = None

        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.setLayout(layout)
        self.password_field.setFocus()

    def accept(self):
        """Override accept to validate passwords"""
        if self.confirm_field:
            if self.password_field.text() != self.confirm_field.text():
                QMessageBox.warning(self, "Error", "Passwords don't match")
                return

        super().accept()

    def get_password(self):
        """Get the entered password"""
        return self.password_field.text()


class MinimalWallet(QMainWindow):
    """Minimal Bismuth wallet with essential functions only"""

    def __init__(self):
        super().__init__()

        # Basic state
        self.connection = None
        self.address = None
        self.private_key = None
        self.private_key_readable = None
        self.public_key_readable = None
        self.public_key_b64 = None
        self.balance = Decimal('0')
        self.connected = False
        self.encrypted = False
        self.unlocked = False
        self.keyfile = None

        # Setup UI first
        self.init_ui()

        # Try to load wallet
        self.load_wallet()

        # Connect to network
        self.connect_to_network()

        # Auto-refresh every 30 seconds
        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh_data)
        self.timer.start(30000)

        # Initial data load
        if self.address:
            QTimer.singleShot(2000, self.refresh_data)

    def load_wallet(self):
        """Load wallet keys from default files"""
        try:
            # Try different key file combinations
            private_key_files = ["privkey.der", "privkey_encrypted.der"]
            public_key_file = "pubkey.der"

            result = None
            for priv_file in private_key_files:
                if os.path.exists(priv_file) and os.path.exists(public_key_file):
                    try:
                        result = keys_load(priv_file, public_key_file)
                        if result:
                            break
                    except:
                        continue

            if result:
                (self.private_key, self.public_key_readable,
                 self.private_key_readable, self.encrypted,
                 self.unlocked, self.public_key_b64,
                 self.address, self.keyfile) = result

                print(f"Wallet loaded: {self.address}")
                if hasattr(self, 'address_field'):
                    self.address_field.setText(self.address or "")
                    self.update_wallet_status()
                return True
            else:
                print("No wallet found. Use File -> Load Wallet or create wallet.der first.")
                if hasattr(self, 'address_field'):
                    self.address_field.setText("No wallet loaded")
                return False

        except Exception as e:
            print(f"Error loading wallet: {e}")
            if hasattr(self, 'address_field'):
                self.address_field.setText("Error loading wallet")
            return False

    def connect_to_network(self):
        """Connect to Bismuth network"""
        # Default servers
        servers = {
            "62.112.10.156": "8150",
            "wallet.bismuth.live": "8150",
            "bismuth.online": "8150"
        }

        # Try to get fresh server list
        try:
            response = requests.get("https://bismuth.world/api/legacy.json", timeout=5)
            if response.status_code == 200:
                servers.clear()
                for entry in response.json():
                    if entry.get("active"):
                        servers[entry["ip"]] = str(entry["port"])
        except:
            pass

        # Try connecting to servers
        for ip, port in servers.items():
            try:
                print(f"Connecting to {ip}:{port}")
                self.connection = rpcconnections.Connection((ip, int(port)))
                self.connected = True
                self.status_label.setText(f"Connected: {ip}:{port}")
                print("Connected successfully")
                return
            except Exception as e:
                print(f"Failed to connect to {ip}:{port}: {e}")

        self.status_label.setText("Connection failed")
        print("Could not connect to any server")

    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle(f"Minimal Bismuth Wallet v{__version__}")
        self.setMinimumSize(650, 600)

        # Create menu bar
        self.create_menu_bar()

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Status
        self.status_label = QLabel("Disconnected")
        self.status_label.setStyleSheet("padding: 5px; background: #f0f0f0;")
        layout.addWidget(self.status_label)

        # Wallet section
        wallet_group = QGroupBox("Wallet")
        wallet_layout = QVBoxLayout()

        # Address and copy button
        addr_layout = QHBoxLayout()
        addr_layout.addWidget(QLabel("Address:"))
        self.address_field = QLineEdit("")
        self.address_field.setReadOnly(True)
        addr_layout.addWidget(self.address_field)

        copy_btn = QPushButton("Copy")
        copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(self.address) if self.address else None)
        addr_layout.addWidget(copy_btn)
        wallet_layout.addLayout(addr_layout)

        # Wallet status and encryption buttons
        status_layout = QHBoxLayout()
        self.wallet_status = QLabel("No wallet loaded")
        status_layout.addWidget(self.wallet_status)

        self.encrypt_btn = QPushButton("Encrypt")
        self.encrypt_btn.clicked.connect(self.encrypt_wallet)
        status_layout.addWidget(self.encrypt_btn)

        self.unlock_btn = QPushButton("Unlock")
        self.unlock_btn.clicked.connect(self.unlock_wallet)
        status_layout.addWidget(self.unlock_btn)

        self.lock_btn = QPushButton("Lock")
        self.lock_btn.clicked.connect(self.lock_wallet)
        status_layout.addWidget(self.lock_btn)

        wallet_layout.addLayout(status_layout)
        wallet_group.setLayout(wallet_layout)
        layout.addWidget(wallet_group)

        # Balance section
        balance_group = QGroupBox("Balance")
        balance_layout = QVBoxLayout()

        self.balance_label = QLabel("0.00000000 BIS")
        self.balance_label.setFont(QFont("Arial", 16, QFont.Bold))
        self.balance_label.setAlignment(Qt.AlignCenter)
        balance_layout.addWidget(self.balance_label)

        balance_group.setLayout(balance_layout)
        layout.addWidget(balance_group)

        # Send section
        send_group = QGroupBox("Send Transaction")
        send_layout = QGridLayout()

        send_layout.addWidget(QLabel("To:"), 0, 0)
        self.to_field = QLineEdit()
        send_layout.addWidget(self.to_field, 0, 1)

        send_layout.addWidget(QLabel("Amount:"), 1, 0)
        self.amount_field = QLineEdit("0.00000000")
        send_layout.addWidget(self.amount_field, 1, 1)

        send_layout.addWidget(QLabel("Message:"), 2, 0)
        self.message_field = QLineEdit()
        send_layout.addWidget(self.message_field, 2, 1)

        self.send_btn = QPushButton("Send")
        self.send_btn.clicked.connect(self.send_transaction)
        send_layout.addWidget(self.send_btn, 3, 0, 1, 2)

        send_group.setLayout(send_layout)
        layout.addWidget(send_group)

        # Transaction history
        history_group = QGroupBox("Recent Transactions")
        history_layout = QVBoxLayout()

        self.history_list = QListWidget()
        history_layout.addWidget(self.history_list)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_data)
        history_layout.addWidget(refresh_btn)

        history_group.setLayout(history_layout)
        layout.addWidget(history_group)

        # Update initial state
        self.update_wallet_status()

    def refresh_data(self):
        """Refresh balance and transaction data"""
        if not self.connected or not self.connection:
            return

        try:
            # Get balance
            self.connection._send("balanceget")
            self.connection._send(self.address)
            balance_data = self.connection._receive()

            if balance_data:
                self.balance = Decimal(str(balance_data[0]))
                self.balance_label.setText(f"{self.balance:.8f} BIS")

            # Get recent transactions
            self.connection._send("addlistlim")
            self.connection._send(self.address)
            self.connection._send("10")  # Last 10 transactions
            transactions = self.connection._receive()

            self.update_history(transactions)

        except Exception as e:
            print(f"Error refreshing data: {e}")
            self.status_label.setText("Connection error")
            self.connected = False

    def update_history(self, transactions):
        """Update transaction history list"""
        self.history_list.clear()

        if not transactions:
            self.history_list.addItem("No transactions found")
            return

        for tx in transactions[:10]:  # Show last 10
            try:
                timestamp = datetime.fromtimestamp(float(tx[1])).strftime('%m-%d %H:%M')
                sender = tx[2]
                recipient = tx[3]
                amount = float(tx[4])

                # Determine direction
                if recipient == self.address:
                    direction = "▼ Received"
                    color = "green"
                else:
                    direction = "▲ Sent"
                    color = "red"

                # Format entry
                entry = f"{timestamp} | {direction} {amount:.4f} BIS"
                if sender != self.address:
                    entry += f" from {sender[:12]}..."
                else:
                    entry += f" to {recipient[:12]}..."

                item = self.history_list.addItem(entry)

            except Exception as e:
                print(f"Error processing transaction: {e}")

    def send_transaction(self):
        """Send a transaction"""
        try:
            if not self.connected:
                QMessageBox.warning(self, "Error", "Not connected to network")
                return

            if not self.private_key:
                QMessageBox.warning(self, "Error", "Wallet is locked or not loaded")
                return

            to_address = self.to_field.text().strip()
            amount_str = self.amount_field.text().strip()
            message = self.message_field.text().strip()

            # Validate inputs
            if not to_address:
                QMessageBox.warning(self, "Error", "Recipient address required")
                return

            if len(to_address) != 56:
                QMessageBox.warning(self, "Error", "Invalid address length")
                return

            try:
                amount = quantize_eight(amount_str)
                if Decimal(amount) <= 0:
                    raise ValueError()
            except:
                QMessageBox.warning(self, "Error", "Invalid amount")
                return

            # Check balance
            fee = essentials.fee_calculate(message, "")
            total = Decimal(amount) + Decimal(fee)

            if total > self.balance:
                QMessageBox.warning(self, "Error",
                                    f"Insufficient balance. Need {total:.8f}, have {self.balance:.8f}")
                return

            # Confirm transaction
            reply = QMessageBox.question(self, "Confirm Transaction",
                                         f"Send {amount} BIS to {to_address[:20]}...?\n"
                                         f"Fee: {fee} BIS\n"
                                         f"Total: {total:.8f} BIS")

            if reply == QMessageBox.Yes:
                self.execute_send(to_address, amount, message)

        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def execute_send(self, to_address, amount, message):
        """Execute the transaction"""
        try:
            # Create transaction
            timestamp = '%.2f' % time.time()
            transaction = (
                str(timestamp),
                str(self.address),
                str(to_address),
                '%.8f' % float(amount),
                "",  # operation
                str(message)
            )

            # Sign transaction
            h = SHA.new(str(transaction).encode())
            signer = PKCS1_v1_5.new(self.private_key)
            signature = signer.sign(h)
            signature_b64 = base64.b64encode(signature).decode()

            # Submit transaction
            tx_submit = (
                str(timestamp),
                str(self.address),
                str(to_address),
                '%.8f' % float(amount),
                str(signature_b64),
                str(self.public_key_b64.decode()),
                "",  # operation
                str(message)
            )

            self.connection._send("mpinsert")
            self.connection._send(tx_submit)
            reply = self.connection._receive()

            if reply and len(reply) > 0 and reply[-1] == "Success":
                QMessageBox.information(self, "Success", "Transaction sent!")

                # Clear fields
                self.to_field.clear()
                self.amount_field.setText("0.00000000")
                self.message_field.clear()

                # Refresh data
                QTimer.singleShot(2000, self.refresh_data)
            else:
                QMessageBox.warning(self, "Error", f"Transaction failed: {reply}")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Send failed: {e}")

    def create_menu_bar(self):
        """Create menu bar"""
        menubar = self.menuBar()

        # Wallet menu
        wallet_menu = menubar.addMenu("Wallet")

        load_action = QAction("Load Wallet", self)
        load_action.triggered.connect(self.load_wallet_dialog)
        wallet_menu.addAction(load_action)

        wallet_menu.addSeparator()

        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        wallet_menu.addAction(exit_action)

    def load_wallet_dialog(self):
        """Load a different wallet file"""
        filename, _ = QFileDialog.getOpenFileName(
            self, "Select Wallet File", "",
            "Wallet Files (*.der *.json);;All Files (*)"
        )

        if filename:
            try:
                result = keys_load_new(filename)
                if result:
                    (self.private_key, self.public_key_readable,
                     self.private_key_readable, self.encrypted,
                     self.unlocked, self.public_key_b64,
                     self.address, self.keyfile) = result

                    self.address_field.setText(self.address)
                    self.update_wallet_status()

                    # Refresh data for new address
                    if self.connected:
                        QTimer.singleShot(1000, self.refresh_data)

                    QMessageBox.information(self, "Success",
                                            f"Wallet loaded:\n{self.address}")
                else:
                    QMessageBox.warning(self, "Error", "Failed to load wallet file")

            except Exception as e:
                QMessageBox.critical(self, "Error", f"Error loading wallet: {e}")

    def update_wallet_status(self):
        """Update wallet status display and button states"""
        if not self.address:
            self.wallet_status.setText("No wallet loaded")
            self.encrypt_btn.setEnabled(False)
            self.unlock_btn.setEnabled(False)
            self.lock_btn.setEnabled(False)
            self.send_btn.setEnabled(False)
            return

        if self.encrypted:
            if self.unlocked:
                self.wallet_status.setText("Wallet: Encrypted & Unlocked")
                self.wallet_status.setStyleSheet("color: green;")
                self.encrypt_btn.setText("Encrypted")
                self.encrypt_btn.setEnabled(False)
                self.unlock_btn.setText("Unlocked")
                self.unlock_btn.setEnabled(False)
                self.lock_btn.setEnabled(True)
                self.send_btn.setEnabled(True)
            else:
                self.wallet_status.setText("Wallet: Encrypted & Locked")
                self.wallet_status.setStyleSheet("color: orange;")
                self.encrypt_btn.setText("Encrypted")
                self.encrypt_btn.setEnabled(False)
                self.unlock_btn.setText("Unlock")
                self.unlock_btn.setEnabled(True)
                self.lock_btn.setEnabled(False)
                self.send_btn.setEnabled(False)
        else:
            self.wallet_status.setText("Wallet: Not Encrypted")
            self.wallet_status.setStyleSheet("color: red;")
            self.encrypt_btn.setText("Encrypt")
            self.encrypt_btn.setEnabled(True)
            self.unlock_btn.setText("Not Encrypted")
            self.unlock_btn.setEnabled(False)
            self.lock_btn.setEnabled(False)
            self.send_btn.setEnabled(True)

    def encrypt_wallet(self):
        """Encrypt the wallet"""
        if self.encrypted:
            QMessageBox.information(self, "Info", "Wallet is already encrypted")
            return

        if not self.private_key_readable:
            QMessageBox.warning(self, "Error", "No wallet loaded or private key not available")
            return

        # Get password
        dialog = PasswordDialog(self, "Encrypt Wallet", "Enter password to encrypt wallet:")
        if dialog.exec() == QDialog.Accepted:
            password = dialog.get_password()
            if not password:
                QMessageBox.warning(self, "Error", "Password cannot be empty")
                return

            try:
                # Encrypt private key
                ciphertext = encrypt(password, self.private_key_readable)
                ciphertext_b64 = base64.b64encode(ciphertext).decode()

                # Save encrypted wallet
                keys_save(ciphertext_b64, self.public_key_readable,
                          self.address, self.keyfile)

                # Reload wallet to update state
                self.load_wallet()

                QMessageBox.information(self, "Success", "Wallet encrypted successfully!")

            except Exception as e:
                QMessageBox.critical(self, "Error", f"Encryption failed: {e}")

    def unlock_wallet(self):
        """Unlock encrypted wallet"""
        if not self.encrypted:
            QMessageBox.information(self, "Info", "Wallet is not encrypted")
            return

        if self.unlocked:
            QMessageBox.information(self, "Info", "Wallet is already unlocked")
            return

        # Get password
        dialog = PasswordDialog(self, "Unlock Wallet", "Enter password to unlock wallet:")
        if dialog.exec() == QDialog.Accepted:
            password = dialog.get_password()
            if not password:
                QMessageBox.warning(self, "Error", "Password cannot be empty")
                return

            try:
                # Decrypt private key
                decrypted = decrypt(password, base64.b64decode(self.private_key_readable))
                self.private_key = RSA.importKey(decrypted)
                self.unlocked = True

                self.update_wallet_status()
                QMessageBox.information(self, "Success", "Wallet unlocked!")

            except Exception as e:
                QMessageBox.critical(self, "Error", "Wrong password or decryption failed")

    def lock_wallet(self):
        """Lock the wallet"""
        if not self.encrypted:
            QMessageBox.information(self, "Info", "Wallet is not encrypted")
            return

        self.private_key = None
        self.unlocked = False
        self.update_wallet_status()
        QMessageBox.information(self, "Info", "Wallet locked")

    def closeEvent(self, event):
        """Clean shutdown"""
        if self.timer:
            self.timer.stop()
        if self.connection:
            try:
                self.connection.close()
            except:
                pass
        event.accept()


def main():
    """Main entry point"""
    app = QApplication(sys.argv)
    app.setApplicationName("Minimal Bismuth Wallet")

    try:
        wallet = MinimalWallet()
        wallet.show()
        return app.exec()
    except Exception as e:
        print(f"Fatal error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
