from classes import MyCookieJar
from pathlib import Path
import os


cookies = MyCookieJar(filename=os.path.join(str(Path.home()), ".gs_cookies.txt"))