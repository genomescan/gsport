import time
import threading
from multiprocessing import Process, Pool, Queue
from queue import Empty

import requests
import json

import variables

import os
import hashlib

from helpers import human_readable_eta, sizeofmetric_fmt

# Create a separate queue for the download progress
download_queue = Queue()


def download_file(url, fsize, fname, cookies):
    try:
        dsize = 0
        start = time.time()
        with requests.get(url, stream=True, cookies=cookies) as r:
            fpath = fname
            fname = os.path.basename(fname)

            with open(fpath, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:  # filter out keep-alive new chunks
                        f.write(chunk)
                        dsize += len(chunk)
                        rate = dsize // (time.time() - start)
                        eta = "NA"
                        if rate != 0:
                            eta = human_readable_eta((fsize - dsize) / rate)

                        # Use a separate queue just for download progress
                        download_queue.put(["PROGRESS", len(chunk), dsize, fsize, fname, eta])

            if os.path.exists(fpath):
                md5Hash = hashlib.md5(open(fpath, "rb").read()).hexdigest()
                if [md5Hash, fname] in variables.md5List:
                    download_queue.put(["SUCCESS", fname])
                else:
                    download_queue.put(["MD5_FAIL", fname])

        download_queue.put(["FILE_DONE", fname])
    except Exception as e:
        download_queue.put(["ERROR", fname, str(e)])
    return


def process_download(download_args):
    url, fsize, filename, cookies = download_args
    download_file(url, fsize, filename, cookies)
    return True


# This function runs in a separate thread, not in the main tkinter thread
def download_manager(datafiles, cookies):
    try:
        print("Download manager starting...")
        dl_list = []
        dl_sum = 0

        # Prepare download list
        for file in datafiles:
            fsize = file["size"] if file["size"] != 0 else 1
            dl_sum += fsize
            filename = "/" + "test_999" + "/" + file["name"]

            try:
                response = requests.get(
                    variables.HOST + "/gen_session_file/",
                    cookies=cookies,
                    params={"project": variables.project, "filename": filename},
                )
                url = variables.HOST + "/session_files2/" + "test_999" + "/" + response.text
                dl_list.append([url, fsize, file["name"], cookies])
            except Exception as e:
                download_queue.put(["PREP_ERROR", file["name"], str(e)])

        download_queue.put(["TOTAL", dl_sum, len(dl_list)])

        # Use a with statement to ensure the pool is properly closed
        with Pool(processes=min(int(variables.threads), len(dl_list))) as pool:
            results = pool.map_async(process_download, dl_list)
            results.wait()  # Wait for all downloads to complete

        download_queue.put(["ALL_DONE"])
    except Exception as e:
        download_queue.put(["MANAGER_ERROR", str(e)])


# This is the function you call from your tkinter UI
def download_all(session, datafiles, cookies):
    # Start the download manager in a separate thread
    download_thread = threading.Thread(
        target=download_manager,
        args=(datafiles, cookies)
    )
    download_thread.daemon = True
    download_thread.start()

    return download_queue  # Return the queue for monitoring progress