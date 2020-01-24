- On Debian/Ubuntu:

sudo apt install python-venv

cd gsport

python3 -m venv env

. env/bin/activate

pip install -r requirements.txt

python gsport.py [options]

- On Windows:

pip install virtualenv

cd gsport

virtualenv env

env\Scripts\activate.bat

pip install -r requirements.txt

python gsport.py [options]
