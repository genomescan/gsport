import os
import json
from sys import argv


def get_folder(folder):
    def path_to_dict(path):
        d = {'name': os.path.basename(path)}
        if os.path.isdir(path):
            d['type'] = "directory"
            d['children'] = [path_to_dict(os.path.join(path,x)) for x in os.listdir(path)]
        else:
            d['type'] = "file"
            d['size'] = os.path.getsize(path)
        return d

    return json.dumps(path_to_dict(folder))


res = get_folder(argv[1])

#print(res)


def print_rec(dic, depth):
    for item in dic:
        if item['type'] == 'directory':
            for i in range(depth*2):
                print("  ", end='')
            print("└──", item["name"])
            print_rec(item['children'], depth+1)
        else:
            for i in range(depth*2):
                print("  ", end='')
            print("├──", item["name"], item['size'])


print_rec(json.loads(res)['children'], 0)


def get_list(res):

    flist = []

    def print_list(dic, path):
        for item in dic:
            if item['type'] == 'directory':
                # print(path + "/" + item["name"])
                print_list(item['children'], path + "/" + item['name'])
            else:
                print(os.path.getsize(argv[1] + "/" + path + "/" + item["name"]))
                flist.append({"name": path + "/" + item["name"],
                              "size": os.path.getsize(argv[1] + "/" + path + "/" + item["name"])})

    print_list(json.loads(res)['children'], '.')
    return flist


print(get_list(res))
