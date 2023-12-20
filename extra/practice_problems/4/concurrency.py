#!/usr/bin/env python
import subprocess
import os
from multiprocessing import Pool

# Set the source path for backups
src = "/home/student-04-22be09d2c058/data/prod/"

# Define the destination, and call the rsync
def runprocess(folder):
    dest = "/home/student-04-22be09d2c058/data/prod_backup/"
    subprocess.call(["rsync", "-arq", folder, dest])
    print("Handling {}".format(folder))

# Create the folders list to copy

if __name__ == "__main__":
    folders = []
# Root = current directory
    root = next(os.walk(src))[0]
# Dirs = sub-directories in os.walk(src)
    dirs = next(os.walk(src))[1]

# Append / Walk the directories to the folders list
    for dir in dirs:
        folders.append(os.path.join(root, dir))

# Create the pool of tasks; 1 item per folder
    pool = Pool(len(folders))
# Map the runprocess (copy) task to the list of dirs in folders
    pool.map(runprocess, folders)