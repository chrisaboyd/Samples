import argparse
import re
import subprocess
import os
import sys


if sys.platform.startswith('linux'):
    OUTPUT_PATH = os.getcwd() + "/output.txt"
else:
    OUTPUT_PATH = os.getcwd() + "\output.txt"

def extract_ips(file_path):
    with open(file_path, 'r') as file:
        content = file.read()
    
    # Remove all non-numeric characters except '.' and '/'
    cleaned_content = re.sub(r'[^\d./ ]', '', content)
    # Extract IP addresses and CIDR notations from the cleaned content
    ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?\b')
    return ip_pattern.findall(cleaned_content)

def run_command(ip, user, password, enum_users, enum_shares, dry=False):
    # Replace this with the actual command you want to run

    cmd = ["crackmapexec", "smb", ip, "-u", user, "-p", password]

    if enum_users:
        cmd.append("--users")

    if enum_shares:
        cmd.append("--shares")

    if dry:
        return (' '.join(cmd))
    else:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode('utf-8'), result.stderr.decode('utf-8')

def main():
    parser = argparse.ArgumentParser(description='Run comands against a list of IP addresses.')
    
    #  python subnet_parser.py --user '' --password '' --users true --shares true --file ./nets.txt
    
    # Set default values for --user and --password to an empty string
    parser.add_argument('--user', type=str, default='', help='User for the command')
    parser.add_argument('--password', dest='password', type=str, default='', help='Password for the command')
    parser.add_argument('--dry', action='store_true', help='Print the command instead of executing it')
    parser.add_argument('--users', type=bool, help='Enumerate users boolean')
    parser.add_argument('--shares', type=bool, help='Enumerate Shares boolean')
    parser.add_argument('--file', type=str, required=True, help='File containing IP addresses')
    


    args = parser.parse_args()

    if not args.password:
        args.password = '\'\''

    if not args.user:
        args.user = '\'\''

    ips = extract_ips(args.file)

    with open('cleaned_ips.out', 'w') as f:
        for ip in ips:
            f.write(ip + "\n")


    print (f"Writing output to {OUTPUT_PATH}")
    for ip in ips:

        if args.dry:
            print (run_command(ip, args.user, args.password, args.users, args.shares, args.dry))
        else:
            stdout, stderr = run_command(ip, args.user, args.password, args.users, args.shares, args.dry)

            with open('output.txt', 'a') as output_file:
                output_file.write(f"Command result for IP: {ip}\n")
                output_file.write(f"STDOUT:\n{stdout}\n")
                output_file.write(f"STDERR:\n{stderr}\n")
                output_file.write("="*40 + "\n")
    print (f"Output written to {OUTPUT_PATH}")

if __name__ == "__main__":
    main()
