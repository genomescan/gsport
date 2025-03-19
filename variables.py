# <======== Gsport variables ========>
from multiprocessing import Queue

GSPORT_VERSION = "1.8.0"
HOST = "https://portal.genomescan.nl/"
logged_in = False


# <======== GUI variables ========>
frames = {}
projects = []
projectFiles = ""

#  <======== Project Chosen ========>
project = ""
md5List = []
localMd5List = []

#  <======== Multiprocessing variables ========>
queue = Queue()
process = Queue()
threads = 4
