
# GSport

GSport is a command-line program designed to accelerate file downloads from the customer portal by the use of many processes . This significantly improves download speeds and efficiency, making the process faster.

## Improvements

-   Multithreading is now supported on Windows

## Prerequisites

Ensure you have the following installed on your system before proceeding:

-   Python 3.x
    
-   Pip (Python package manager)
    

## Installation and Setup

### Debian/Ubuntu (Linux/macOS)

1.  Install virtual environment support:
    
    ```
    sudo apt install python-venv
    ```
    
2.  Clone the repository and navigate into the project directory:
    
    ```
    cd gsport
    ```
    
3.  Create a virtual environment:
    
    ```
    python3 -m venv env
    ```
    
4.  Activate the virtual environment:
    
    ```
    source env/bin/activate
    ```
    
5.  Install dependencies:
    
    ```
    pip install -r requirements.txt
    ```
    
6.  Run GSport:
    
    ```
    python gsport.py [options]
    ```
    

### Windows

1.  Install virtual environment support:
    
    ```
    pip install virtualenv
    ```
    
2.  Navigate into the project directory:
    
    ```
    cd gsport
    ```
    
3.  Create a virtual environment:
    
    ```
    virtualenv env
    ```
    
4.  Activate the virtual environment:
    
    ```
    env\Scripts\activate.bat
    ```
    
5.  Install dependencies:
    
    ```
    pip install -r requirements.txt
    ```
    
6.  Run GSport:
    
    ```
    python gsport.py [options]
    ```
    

## Usage

Run the application with the appropriate options:

```
python gsport.py --help
```

This command will display a list of available options and usage instructions.
