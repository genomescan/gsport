import json
import requests
import time

from multiprocessing import Process

from .listings import get_list
from .sizeofmetric import sizeofmetric_fmt
from .eta_readable import human_readable_eta

def download_all(session):
    datafiles = []
    if session.options.recursive:
        response = requests.get(session.options.host + '/data_api_recursive/' +
                                session.options.project,
                                cookies=session.cookies,
                                params={"cd": session.options.dir})
        try:
            datafiles = get_list(response.text, session.options.dir)
        except json.decoder.JSONDecodeError:
            print("[get_listing] Error reading response:", response.text)
            exit(1)
    else:
        response = requests.get(session.options.host + '/data_api2/' + session.options.project + '/n',
                                cookies=session.cookies,
                                params={"cd": session.options.dir})
        try:
            datafiles = json.loads(response.text)
        except json.decoder.JSONDecodeError:
            print("[get_listing] Error reading response:", response.text)
            exit(1)

    # Obtain the MD5 hash of the files, when the file to download is a '.gz' file.
    for file in datafiles:
        if 'checksums.md5' in file['name']:
            # Get the code to obtain the file
            response = requests.get(session.options.host + '/gen_session_file/', cookies=session.cookies,
                                    params={"project": session.options.project,
                                            "filename": "/" + session.options.dir + "/" +
                                                        file['name']
                                            })
            # Create the URL to obtain the file (one time use)
            url = session.options.host + '/session_files2/' + session.options.project + "/" + response.text
            md5 = requests.get(url, stream=True, cookies=session.cookies)

            if session.options.checksumFile:
                # Open the file once for writing. Then loop for writing and then close.
                f = open(session.options.checksumFile, 'a')

            # Split the MD5 file to a list<str,str>
            for lst in md5.text.split("\n"):
                # if empty, skip.
                if not (lst and lst.strip()):
                    continue

                md5Obj = lst.split('  ')
                session.md5List.append(md5Obj)

                # If a local checksum file is provided, add the online ones to the local file.
                if session.options.checksumFile and md5Obj not in session.localMd5List:
                    # Add the new md5 value to the local file.
                    f.write(md5Obj[0] + ', ' + md5Obj[1] + "\n")

                    # Store the object in the list for reference.
                    session.localMd5List.append(md5Obj)

            if session.options.checksumFile:
                f.close()

    dl_list = []
    dl_sum = 0
    session.options.download_all = True

    for file in datafiles:
        fsize = file['size'] if file['size'] != 0 else 1
        dl_sum += fsize
        filename = "/" + (session.options.dir if not session.options.recursive else '') + "/" + file['name']
        response = requests.get(session.options.host + '/gen_session_file/', cookies=session.cookies,
                                params={"project": session.options.project,
                                        "filename": filename
                                        })
        url = session.options.host + '/session_files2/' + session.options.project + "/" + response.text

        dl_list.append([url, fsize, file['name']])


    current_processes = 0
    max_processes = int(session.options.threads)
    number_of_processes = len(dl_list)
    finished_processes = 0
    current_process = 0
    downloaded_bytes = 0
    processes = []

    for dl in dl_list:
        processes.append(Process(target=session.download_file, args=dl))

    start = time.time()
    started = []
    while True:
        if current_processes < max_processes and finished_processes < number_of_processes and current_process < number_of_processes:
            processes[current_process].start()
            started.append(processes[current_process])
            current_process += 1
            current_processes += 1
        if current_processes < max_processes and current_process < number_of_processes:
            continue

        status = session.queue.get()
        downloaded_bytes += status[0]
        for process in started:
            if not process.is_alive():
                if process.exitcode is not None:
                    process.close()
                    started.remove(process)

        if status[1]:
            current_processes -= 1
            finished_processes += 1
        rate = downloaded_bytes // (time.time() - start)
        if dl_sum > 100:  # preventing devision by zero errors
            estimatedtimeofarrival = "NA"
            if rate > 0:
                estimatedtimeofarrival = human_readable_eta((dl_sum - downloaded_bytes) / rate)
            print("\r", str(round(downloaded_bytes / dl_sum * 100)) + "%",
                  "Downloading", sizeofmetric_fmt(downloaded_bytes), "of",
                  sizeofmetric_fmt(dl_sum),
                  str(sizeofmetric_fmt(rate)) + "/sec",
                  "ETA:", estimatedtimeofarrival,
                  end='     ')

        if finished_processes == number_of_processes:
            print("\nDownloading complete")
            break

def download(session):
    response = requests.get(session.options.host + '/data_api2/' + session.options.project + '/n',
                            cookies=session.cookies,
                            params={"cd": session.options.dir})
    fsize = 0
    fname = ''
    try:
        datafiles = json.loads(response.text)

        # Obtain the MD5 hash of the files, when the file to download is a '.gz' file.
        if not session.md5List and '.gz' in session.options.download:
            for file in datafiles:
                if file['name'] == 'checksums.md5':
                    # Get the code to obtain the file
                    response = requests.get(session.options.host + '/gen_session_file/', cookies=session.cookies,
                                            params={"project": session.options.project,
                                                    "filename": "/" + session.options.dir + "/" +
                                                                file['name']
                                                    })
                    # Create the URL to obtain the file (one time use)
                    url = session.options.host + '/session_files2/' + session.options.project + "/" + response.text
                    md5 = requests.get(url, stream=True, cookies=session.cookies)

                    if session.options.checksumFile:
                        # Open the file once for writing. Then loop for writing and then close.
                        f = open(session.options.checksumFile, 'a')

                    # Split the MD5 file to a list<str,str>
                    for lst in md5.text.split("\n"):
                        md5Obj = lst.split('  ')
                        session.md5List.append(md5Obj)

                        # If a local checksum file is provided, add the online ones to the local file.
                        if session.options.checksumFile and md5Obj not in session.localMd5List:
                            # Add the new md5 value to the local file.
                            f.write(md5Obj[0] + ', ' + md5Obj[1] + "\n")

                            # Store the object in the list for reference.
                            session.localMd5List.append(md5Obj)

                    if session.options.checksumFile:
                        f.close()

        for file in datafiles:
            if file['name'] == session.options.download:
                fsize = file['size']
                if fsize == 0:
                    fsize = 1
                fname = file['name']
    except json.decoder.JSONDecodeError:
        print("[download] [get_listing] Error reading response: ", response.text)
        exit(1)
    response = requests.get(session.options.host + '/gen_session_file/', cookies=session.cookies,
                            params={"project": session.options.project,
                                    "filename": "/" + session.options.dir + "/" +
                                                session.options.download
                                    })
    url = session.options.host + '/session_files2/' + session.options.project + "/" + response.text
    session.download_file(url, fsize, fname)
    print()