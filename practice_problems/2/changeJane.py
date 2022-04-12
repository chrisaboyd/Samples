#!/usr/bin/env python3

import sys
import subprocess

with open(sys.argv[1], "r") as f:
    oldFiles = f.readlines()
    for line in oldFiles:
        newline = line.replace("jane", "jdoe").strip()
        print (line, newline)
f.close()
