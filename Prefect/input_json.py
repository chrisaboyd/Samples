import json

def print_types(json_object):
    for key, value in json_object.items():
        if isinstance(value, dict):
            print(f'Item with key "{key}" is a dictionary.')
            print_types(value)
        elif isinstance(value, list):
            print(f'Item with key "{key}" is a list.')
            for i, item in enumerate(value):
                print(f'Type of item at index {i} in list "{key}" is: {type(item)}')
        else:
            print(f'Type of the item with key "{key}" is: {type(value)}')

def load_json_and_print_types(filename):
    with open(filename, 'r') as file:
        data = json.load(file)
        print_types(data)

load_json_and_print_types('json')