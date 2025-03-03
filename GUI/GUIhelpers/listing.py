import requests
import json
import variables

def print_rec(dic, depth):
    for item in dic:
        if item["type"] == "directory":
            for i in range(depth * 2):
                print("  ", end="")
            print("└──", item["name"])
            print_rec(item["children"], depth + 1)
        else:
            for i in range(depth * 2):
                print("  ", end="")
            print("├──", item["name"], "Size: ", item["size"], "bytes")

def get_files(name, HOST, cookies):
    print(f"Opening project: {HOST + "/data_api_recursive/" + name,}")
    response = requests.get(
        HOST + "/data_api_recursive/" + name,
        cookies=cookies,
        params={"cd": ""},
    )
    try:
        datafiles = json.loads(response.text)
        variables.projectFiles = datafiles
        print_rec(datafiles["children"], 0)

        return datafiles
    except json.decoder.JSONDecodeError:
        print("[get_listing] Error reading response:", response.text)
        exit(1)