from PyQt5.QtWidgets import QDialog, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout, QLabel, QMessageBox
import hashlib
from db.db_handler import DBHandler

class LoginDialog(QDialog):
    AUTHORIZED = 1
    ANONYMOUS = 2
    REJECTED = 0
    def __init__(self, parent = None, db_handler: DBHandler = None):
        super().__init__(parent)
        self.textName = QLineEdit(self)
        self.textPass = QLineEdit(self)
        self.button_login = QPushButton('Login', self)
        self.skip_login = QPushButton("Continue without login")
        self.button_login.clicked.connect(self.handleLogin)
        self.skip_login.clicked.connect(self.skipLogin)
        self.db = db_handler
        name = QLabel("Welcome to Mesenj")
        layout = QVBoxLayout(self)
        buttons_layout = QHBoxLayout(self)
        layout.addWidget(name)
        layout.addWidget(self.textName)
        layout.addWidget(self.textPass)
        buttons_layout.addWidget(self.button_login)
        buttons_layout.addWidget(self.skip_login)
        layout.addLayout(buttons_layout)

    def handleLogin(self):
        password = self.textPass.text()
        passhash = hashlib.sha256(password.encode())
        hexdigest = passhash.hexdigest()
        if self.db.check_user(self.textName.text(), passhash):
            self.done(self.AUTHORIZED)
        else:
            QMessageBox.warning(self, "Login failed", "Wrong username or password")

    def skipLogin(self):
        self.done(self.ANONYMOUS)
