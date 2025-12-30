import os

def getDeps():
    os.system('wine windowsPyBin/python.exe -m pip install -r ./requirements.txt --break-system-packages')

def build():
    os.system('wine windowsPyBin/python.exe -m PyInstaller --onefile client/app.py')

getDeps()
build()