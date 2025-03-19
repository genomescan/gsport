import GUI.downloads as downloads
import sys
import ast

filesDict = ast.literal_eval(sys.argv[1])

if __name__ == '__main__':
    downloads.download_all(None, filesDict)