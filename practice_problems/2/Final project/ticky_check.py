#!/usr/bin/env python3

import operator
import re
import os

userDict = {}
errorDict = {}
match_error = r'(INFO|ERROR)'

with open("/Users/christopherboyd/repos/coursera_python/2/Final project/syslog.log", "r") as f:
    for line in f.readlines():
        line = line.strip()
        print (match_error)
        if re.search(match_error, line):
            user = re.search(r'(\(\w+\))', line)
            newUser = re.sub("[()]", "", user.group(0))
            userDict[newUser] = userDict.get(newUser, 0) + 1
        try:
            test_value = re.search(match_error, line)
            if test_value.group(0) == "ERROR":
                match = r"ERROR: ([\w \[\]]*) (\([\w]*\))"
                find_error = re.search(match, line)[1]
                errorDict[find_error] = errorDict.get(find_error, 0) + 1
        except AttributeError:
            pass
f.close()

def user_stats(sortedUser):
    with open("user_statistics.csv", "w") as f:
        for item in sortedUser:
            f.write("{}, {}\n".format(item[0], item[1]))
    f.close()

def error_stats(sortedError):
    with open("error_message.csv", "w") as f:
        for item in sortedError:
            f.write("{}, {}\n".format(item[0], item[1]))
    f.close()
    
sortedError = sorted(errorDict.items(), key=operator.itemgetter(1), reverse=True)
sortedUser = sorted(userDict.items(), key=operator.itemgetter(0))

error_stats(sortedError)
user_stats(sortedUser)