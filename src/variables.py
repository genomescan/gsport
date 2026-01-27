GSPORT_VERSION = "2.0.1"
ALL_PROJECTS_API = "get_projects/"
LOGIN_URL = "/login/"
LOGGED_IN_URL = "/logged_in_api/"
TWO_FACTOR_AUTH_URL = "/otp_ok/"
DOWNLOAD_RECURSIVE = "/data_api_recursive/"
LOGOUT_URL = "/accounts/logout/"
HOST_URL = "https://portal.genomescan.nl/"
VERIFY_FILES_URL = "/gen_session_file/"
DOWNLOAD_FILE_URL = "/data_api2/"

LIST_EXAMPLE_MESSAGE = """
example usage:
  gsport list 100000                     shows all the files associated with the project from the top level but not any directory or files within directories
  gsport list 100000 -m                  shows all the folders/directories under that project but not their content
  gsport list 100000 -d directory        shows all the files under a directory for that project, no subfolder or files in there
  gsport list 100000 -m -d directory     shows all the files and folders under a directory for that project but not the content of the folders
  gsport list 100000 -r                  shows all the files and folders in a tree like structure
  gsport list 100000 -r -d directory     shows all the files and folders in a tree like structure under a directory for that project
"""
DOWNLOAD_ALL_EXAMPLE_MESSAGE = """
example usage:
  gsport all 100000                    downloads al the files associated with the project from the top level but not any files within directories
  gsport all 100000 -d directory       downloads only the files directly under a directory, no subfolder or files in there
  gsport all 100000 -r                 downloads all the files and folders for that project
  gsport all 100000 -r -d directory    downloads all the files and folders under a directory for that project
  gsport all 100000 -o outputdir       downloads all the files associated with the project from the top level but not any files within directories and outputs them in a directory called outputdir
"""
DOWNLOAD_EXAMPLE_MESSAGE = """
example usage:
  gsport download 100000 test.txt test2.txt                     downloads the specific files, they have to be in the root directory
  gsport download 100000 test.txt -o outputdir                  downloads the specific files and outputs them in a directory called outputdir
"""
