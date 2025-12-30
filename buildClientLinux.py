import os

def getDeps():
    os.system('python3 -m pip install -r ./requirements.txt --break-system-packages')

def build():
    os.system('python3 -m PyInstaller --onefile client/app.py')

getDeps()
build()