GSPORT_VERSION = "2.0"

ALL_PROJECTS_API = "api/projects-all"
LOGIN_URL = "/login/"
LOGGED_IN_URL = "/logged_in_api/"
TWO_FACTOR_AUTH_URL = "/otp_ok/"
PROJECT_DATA_API = '/data_api_recursive/'
LOGOUT_URL = 'api/logout'
HOST_URL = "https://portal.genomescan.nl/"
VERIFY_FILES_URL = "api/download/verify/"
DOWNLOAD_FILE_URL = "api/download/"

LIST_EXAMPLE_MESSAGE = """
example usage: 
  gsport list 100000                     shows all the files associated with the project from the top level but not any files within directories
  gsport list 100000 -m                  shows all the folders/directories under that project but not their content
  gsport list 100000 -d directory        shows all the files under a directory for that project, no subfolder or files in there
  gsport list 100000 -m -d directory     shows all the folders under a directory for that project but not their content
  gsport list 100000 -r                  shows all the files and folders in a tree like structure
  gsport list 100000 -r -d directory     shows all the files and folders in a tree like structure under a directory for that project
"""
DOWNLOAD_ALL_EXAMPLE_MESSAGE = """
example usage: 
  gsport all 100000                    downloads al the files associated with the project from the top level but not any files within directories
  gsport all 100000 -d directory       downloads only the files directly under a directory, no subfolder or files in there
  gsport all 100000 -r                 downloads all the files and folders for that project
  gsport all 100000 -r -d directory    downloads all the files and folders under a directory for that project
  gsport all 100000 -o outputdir       downloads al the files associated with the project from the top level but not any files within directories and outputs them in a directory called outputdir
"""
DOWNLOAD_EXAMPLE_MESSAGE = """
example usage: 
  gsport download 100000 100000/testdir/test.txt 100000/testdir2/test2.txt     downloads the specific files
  gsport download 100000 100000/testdir/test.txt -o outputdir                  downloads the specific files and outputs them in a directory called outputdir
"""