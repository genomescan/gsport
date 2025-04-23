import threading
from http.cookiejar import MozillaCookieJar

"""
Custom CookieJar to fix multiprocessing issues on Windows
"""


class MyCookieJar(MozillaCookieJar):
    def __getstate__(self):
        state = self.__dict__.copy()
        del state["_cookies_lock"]
        return state

    def __setstate__(self, state):
        self.__dict__ = state
        self._cookies_lock = threading.RLock()
