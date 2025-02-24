from classes import MyCookieJar
from pathlib import Path
import os

# <======== Gsport variables ========>
GSPORT_VERSION = "1.8.0"
HOST = "https://portal.genomescan.nl/"
logged_in = False
cookies = MyCookieJar(filename=os.path.join(str(Path.home()), ".gs_cookies.txt"))

# <======== GUI variables ========>
frames = {}
projects = []