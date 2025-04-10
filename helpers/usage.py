def usage():
    print(
        """
Usage: gsport [options]
GSPORT command-line tool for accessing GenomeScan Customer Portal

Options
-H --host [host], default: https://portal.genomescan.nl
-p --project [project] project (required with -l, -d, -a)
-l --list return a list of all files
-s --size return a list with the size
-d --download [filename]
-a --download-all download all files from project -p or --project
-f --force downloading files even if they already exist
-c --clear-cookies clear session/cookies
-t --workers [n] allow n concurrent workers (defaults to number of logical cpu cores) (works only on Linux)
--dirs show directories instead of files (combined with -l or --list)
--cd [dir] show files (or directories) in dir,
     dirs can be appended with forward slashes: / (eg. "Analysis/Sample 1", with quotes)
     or Analysis/s1/bam (without spaces, no quotes needed)
-r --recursive lists/downloads complete tree from --cd [dir] or everything if no --cd option is given
-h --help prints this help
-v --version show gsport version
-i --ignore Ignore MD5 checksum result and download only files not on the system
-I --includeFile Path to file containing list of files to include in the download. One file per line and save the file using the UTF-8 encoding. only works with the -a flag.
-E --excludeFile Path to file containing list of files to exclude from downloading. One file per line and save the file using the UTF-8 encoding. only works with the -a flag.
-C --checksumFile Path to the file containing a lise of all the file checksums. It will store the md5 checksum of all downloaded files. If the checksum of the file to download is not provided, the script will download the file twice to test if the MD5 match.
-P --path Local location to store the files to.

Note: Using --dirs together with -r / --recursive has no effect

Example usage: gsport -p 100000 -l shows all the files under that project
               gsport -p 100000 -ls shows all the files under that project with the filesize
               gsport -p 100000 -l --dirs shows all the folders/directories under that project
               gsport -p 100000 -l --cd Analysis shows all the files under Analysis for that project
               gsport -p 100000 -l -r shows all the files and folders in Analysis in a tree structure
               gsport -p 100000 -l --dirs cd Analysis shows all the folders under Analysis for that project
               gsport -p 100000 -a -r downloads all the files and folders for that project
               gsport -p 100000 -a -r --cd Analysis downloads all the files and folder under Analysis for that project
               gsport -p 100000 -a --cd Analysis downloads only the files directly under Analysis, no subfolder or files in there.
               gsport -p 100000 -a --cd Analysis/s1 downloads only the files directly under Analysis/s1
               gsport -p 100000 -a -I "C:\\project\\include.txt"
               gsport -p 100000 -a -E "C:\\project\\exclude.txt"
               gsport -p 100000 -a -C "C:\\project\\localChecksums.md5"
               gsport -p 100000 -a -P "C:\\project\\exclude.txt"
"""
    )
