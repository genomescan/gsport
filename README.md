# GSport

GSport is a command-line tool designed to accelerate file downloads from the GenomeScan Customer Portal. It leverages multiprocessing to significantly improve download speeds and efficiency. Works on linux, windows and macOS. 

WARNING: This is version 2.0, some of the command line interface has changed partially in preparation for version 3.0 that will be released (hopefully end of 2025) when we start using our new customer portal. Verion 1.x should still be usable during version 2.0, but when version 3.0 is introduced both version 1 and 2 will no longer work.

## Prerequisites

Ensure you have the following installed:
- Python 3.8.X
- Pip (Python package manager)
- python-venv (Linux/ macOS) or virtualenv(windows)

## Installation

There are 2 options for installing GSport.
- Pip install
- Manual installation

### Pip install
```bash
pip install gsport
```

### Manual install
#### Linux/macOS

```bash
git clone https://github.com/genomescan/gsport.git
cd gsport
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
```

#### Windows

```bash
git clone https://github.com/genomescan/gsport.git
cd gsport
virtualenv env
env\Scripts\activate.bat
pip install -r requirements.txt
```

## Usage

To see all available options, run:

```bash
python gsport.py --help
```

This will print a full list of available options and flags.

### List Files

```bash
# shows all the files associated with the project from the top level but not any directory or files within directories
gsport list 100000
 # shows all the folders/directories under that project but not their content   
gsport list 100000 -m
# shows all the files under a directory for that project, no subfolder or files in there
gsport list 100000 -d directory
# shows all the files and folders under a directory for that project but not the content of the folders
gsport list 100000 -m -d directory
# shows all the files and folders in a tree like structure
gsport list 100000 -r
# shows all the files and folders in a tree like structure under a directory for that project
gsport list 100000 -r -d directory
```

### Download All Files

```bash
# downloads al the files associated with the project from the top level but not any files within directories
gsport all 100000
# downloads only the files directly under a directory, no subfolder or files in there
gsport all 100000 -d directory
# downloads all the files and folders for that project
gsport all 100000 -r
# downloads all the files and folders under a directory for that project
gsport all 100000 -r -d directory
# downloads all the files associated with the project from the top level but not any files within directories and outputs them in a directory called outputdir
gsport all 100000 -o outputdir
```

### Download Specific Files

```bash
# downloads the specific files, they have to be in the root directory
gsport download 100000 test.txt test2.txt
# downloads the specific files and outputs them in a directory called outputdir
gsport download 100000 test.txt -o outputdir
```

### Show available projects

```bash
# List all projects you have access to
gsport -p
```
