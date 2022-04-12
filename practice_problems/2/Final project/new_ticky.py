#!/usr/bin/env python3

import operator
import os
import re

userDict = {}
errorDict = {}
match_error = r'(INFO|ERROR)'

f = open("/home/student-04-4ae3aa7990eb/syslog.log", "r")
for line in f.readlines():
    line = line.strip()
    try:
        if re.search(match_error, line):
            val = re.search(match_error, line).group(0)
            user = re.search(r'(\(.*)\)', line).group(0)
            newUser = re.sub("[()]", "", user)
            if newUser not in userDict.keys():
                userDict[newUser] = {}
                userDict[newUser]["INFO"] = 0
                userDict[newUser]["ERROR"] = 0
            if val == "INFO":
                userDict[newUser]["INFO"] += 1
            elif val == "ERROR":
                userDict[newUser]["ERROR"] += 1
    except AttributeError:
        pass
    try:
        test_value = re.search(match_error, line)
        if test_value.group(0) == "ERROR":
            match = r"(ERROR|INFO) ([\w+ ']*)"
            find_error = re.search(match,line).group(2).strip()
            errorDict[find_error] = errorDict.get(find_error, 0) + 1
    except AttributeError:
         pass
f.close()

sortedUser = sorted(userDict.items(), key=operator.itemgetter(0))
sortedError = sorted(errorDict.items(), key=operator.itemgetter(1), reverse=True)

g = open("/home/student-04-4ae3aa7990eb/user_statistics.csv", "w")
g.write("Username,INFO,ERROR\n")
for key in sortedUser:
    a, b = key
    g.write(str(a) + "," + str(b["INFO"])+"," + str(b["ERROR"]) + "\n")
g.close()

g = open("/home/student-04-4ae3aa7990eb/error_messages.csv", "w")
g.write("Error,Count\n")
for key in sortedError:
    g.write(str(key[0] + "," + str(key[1])+ "\n"))
g.close()