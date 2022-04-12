#!/usr/bin/env python3
import csv

# Reads in the csv_file_location (passed in)
# Registers a dialect ; this tells csv to ignore the first space, and fail if bad csv format is passed
# Reads in the contents of csv_file_location using csv.Dictreader, and assigns it to employee_file
# Defines the list of employees, and adds them from the employee_file
# Returns the employee_list
def read_employees(csv_file_location):
    csv.register_dialect('empDialect', skipinitialspace=True, strict=True)
    employee_file = csv.DictReader(open(csv_file_location), dialect = 'empDialect')
    employee_list = []
    for data in employee_file:
        employee_list.append(data)
    return employee_list

# Takes the employee_list from read_employees as parameter
# Creates a department list; iterates through the employee list. 
# For each item in employee_list, appends the Department to the department list
# For each department in the department list, assigns a key value pair ; The department name is the key, and the count is the value
# Returns that dictionary

def process_data(employee_list):
    department_list = []
    for employee_data in employee_list:
            department_list.append(employee_data['Department'])
    department_data = {}
    for department_name in set(department_list):
        department_data[department_name] = department_list.count(department_name)
    return department_data

# Takes the dictionary created by process_data (department_data), and the output file as parameters
# Creates the file
# For each item in the sorted dictionary (so it's alphabetical):
# Write the key : value pair, and new line
def write_report(dictionary, report_file):
    with open(report_file, "w+") as f:
        for k in sorted(dictionary):
            f.write(str(k)+':'+str(dictionary[k])+'\n')
        f.close()

employee_list = read_employees('/home/student-04-70301b588226/data/employees.csv')
dictionary = process_data(employee_list)
write_report(dictionary, '/home/student-04-70301b588226/test_report.txt')