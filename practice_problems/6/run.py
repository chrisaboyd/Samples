#!/usr/bin/env python3

import os
#import requests
import json

#34.133.35.74

files=os.listdir("/Users/christopherboyd/repos/test/")
values = []
dictKeys = ["title", "name", "date", "feedback"]

for file in files:
    with open("/Users/christopherboyd/repos/test/" + file, "r") as f:
        data =  {"title": "", "name": "", "date": "", "feedback": ""}
        for line, v in zip(f, dictKeys):
            data[v] = line.strip()
        payload = json.dumps(data)
        print (payload)
        #values.append(data)
        #values.append({"title":f.readline().rstrip("\n"),
        #    "name":f.readline().rstrip("\n"),
        #    "date":f.readline().rstrip("\n"),
        #    "feedback":f.readline().rstrip("\n")})
    f.close()
#print (values)
#for item in values:
#    print (item)
#    response = requests.post("http://34.133.35.74/feedback/", json=item)
#    print (response.status_code)
    #print (response.content)