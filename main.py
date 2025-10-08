import sys
from gui import SDESSimpleGui
from PyQt5.QtWidgets import QApplication
if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = SDESSimpleGui()
    window.show()
    sys.exit(app.exec_())