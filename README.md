# GSport

GSport is a command-line tool designed to accelerate file downloads from the GenomeScan Customer Portal. It leverages multiprocessing to significantly improve download speeds and efficiency.

## Key Features

- Fast, parallel file downloads using multiple processes
- Supports recursive and selective downloads
- Multithreading compatibility on Windows
- Include/exclude lists for fine-grained control
- Optional MD5 checksum verification

## Prerequisites

Ensure you have the following installed:
- Python 3.x
- Pip (Python package manager)
- python-venv (Linux/ macOS) or virtualenv(windows)

## Installation

### Linux/macOS

```bash
git clone https://github.com/genomescan/gsport.git
cd gsport
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
```

### Windows

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
gsport list 100000
gsport list 100000 -m
gsport list 100000 -d directory
gsport list 100000 -m -d directory
gsport list 100000 -r
gsport list 100000 -r -d directory
```

### Download All Files

```bash
gsport all 100000
gsport all 100000 -d directory
gsport all 100000 -r
gsport all 100000 -r -d directory
gsport all 100000 -o outputdir
```

### Download Specific Files

```bash
gsport download 100000 path/to/file1.txt path/to/file2.txt
gsport download 100000 path/to/file.txt -o outputdir
```

### Advanced Examples

```bash
gsport -p 100000 -l                        # List all files in the project
gsport -p 100000 -ls                       # List files with size
gsport -p 100000 -l --dirs                 # List only folders/directories
gsport -p 100000 -l --cd Analysis          # List files under "Analysis"
gsport -p 100000 -l -r                     # List all in a recursive tree
gsport -p 100000 -l --dirs --cd Analysis   # List folders under Analysis
```