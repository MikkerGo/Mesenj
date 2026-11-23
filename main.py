import argparse
import os
import sys
from pathlib import Path

from PyQt5.QtWidgets import QMainWindow, QWidget, QApplication
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap

from cypher.aes import AES
from cypher.rsa import RSA
from gui.main_window import MesMainWindow

def main() -> int:

    app = QApplication(sys.argv)

    window = MesMainWindow()
    window.show()

    def shutdown():
        # receiver.stop()
        # receiver.wait(2000)        # даём потоку до 2 сек на выход
        pass

    app.aboutToQuit.connect(shutdown)

    return app.exec_()

if __name__ == '__main__':
    sys.exit(main())