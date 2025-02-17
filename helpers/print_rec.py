def print_rec(dic, depth):
    for item in dic:
        if item['type'] == 'directory':
            for i in range(depth * 2):
                print("  ", end='')
            print("└──", item["name"])
            print_rec(item['children'], depth + 1)
        else:
            for i in range(depth * 2):
                print("  ", end='')
            print("├──", item["name"], 'Size: ', item['size'], 'bytes')