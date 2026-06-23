import time
from multiprocessing import Process
from typing import List

from src.helpers.eta_readable import human_readable_eta
from src.helpers.print_functions import print_info
from src.helpers.sizeofmetric import size_of_metric_fmt


def download_parallel(session, dl_list: List[list], dl_sum: int) -> None:
    """
        Multithreading of download. It starts by making a process of every download by setting the target to
        session.download_file with the parameters of the file. It will then start the processes until the capacity is reached,
        or there are no more left over processes. It will then add the size of downloaded chunks to the total amount downloaded.
        And close no longer active processes. It will then print the progress.
    :param session: The session object.
    :param dl_list: The list of lists representing a file each. Index 0 is the url, 1 is the size in bytes, 2 is the
                    full filepath to give the downloaded file a name and place it in the correct directory.
    :param dl_sum: The total amount of bytes of all files to be downloaded.
    :return: None
    """

    current_processes_amount = 0  # The amount of processes currently active.
    max_processes = int(
        session.options.threads
    )  # The maximum amount of processes that are allowed to be active at a time.
    number_of_processes = len(dl_list)  # The amount of processes.
    finished_processes_amount = 0  # The amount of finished processes.
    current_process_index = (
        0  # The index of the current process in the list of processes.
    )
    downloaded_bytes = 0  # The total amount of downloaded bytes.
    processes = []

    for dl in dl_list:
        processes.append(Process(target=session.download_file, args=dl))

    start = time.time()
    started = []
    while True:
        if (
            current_processes_amount < max_processes
            and finished_processes_amount < number_of_processes
            and current_process_index < number_of_processes
        ):
            processes[current_process_index].start()
            started.append(processes[current_process_index])
            current_process_index += 1
            current_processes_amount += 1
        if (
            current_processes_amount < max_processes
            and current_process_index < number_of_processes
        ):
            continue

        if finished_processes_amount == number_of_processes:
            # VT100 escape code to clear current line
            print_info("\r\033[2KDownloading complete")
            break

        status = session.queue.get()
        downloaded_bytes += status[0]
        for process in started:
            if not process.is_alive():
                if process.exitcode is not None:
                    process.close()
                    started.remove(process)

        if status[1]:
            current_processes_amount -= 1
            finished_processes_amount += 1
        rate = downloaded_bytes // (time.time() - start)
        if dl_sum > 100:  # Preventing division by zero errors.
            estimated_time_of_arrival = "Never"  # It was this or "After the heat death of the universe" by mmterpstra.
            if rate > 0:
                estimated_time_of_arrival = human_readable_eta(
                    (dl_sum - downloaded_bytes) / rate
                )
            print(
                "\r",
                str(round(downloaded_bytes / dl_sum * 100)) + "%",
                "Downloading",
                size_of_metric_fmt(downloaded_bytes),
                "of",
                size_of_metric_fmt(dl_sum),
                str(size_of_metric_fmt(rate)) + "/sec",
                "ETA:",
                estimated_time_of_arrival,
                end="     ",
            )

        if finished_processes_amount == number_of_processes:
            # VT100 escape code to clear current line
            print_info("\r\033[2KDownloading complete")
            break
