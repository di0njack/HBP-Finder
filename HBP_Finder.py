#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# DEVELOPED BY Di0nJ@ck - September 2018 - v1.0
__author__      = 'Di0nj@ck'
__version__     = 'v1.0'
__last_update__ = 'September 2018'

import          \
    argparse,   \
    sys,        \
    textwrap,   \
    re, time

try:
    import requests
except Exception as e:
    print(str(e))
    print("""[!] ERROR. You need to install the Python 'requests' module.  Install PIP (https://bootstrap.pypa.io/get-pip.py).
     Then 'pip install requests' """)
    sys.exit(0)


'''FUNCTIONS'''

# Function to run USER ARGUMENTS
def run_args(args):

    f_input = open("mails_list.txt", "r")
    f_output = open("results.txt", "w")

    num_lines = sum(1 for line in open("mails_list.txt"))

    print ("- A total of " + str(num_lines) + " email addresses will be analyzed" + "\n")

    i = 1
    while (i <= num_lines):

        u_mail = f_input.readline().rstrip('\n')
        print ("- Analyzing the email: " + u_mail + "\n")
        print ("    * Retrieving info..." + "\n")

        try:
            resp = requests.get('https://haveibeenpwned.com/api/v2/breachedaccount/' + u_mail + '?truncateResponse=true', timeout=10)
            print ("    * Results successfuly retrieved" + "\n")        
        except Exception as e:
            print (str(e))
        

        if resp:

            print ("    * Result: KO. Account compromised!" + "\n")
            f_output.write(u_mail)
            f_output.write(";")
            f_output.write(resp.content)
            f_output.write("\n")

        else:
            print ("    * Result: OK" + "\n")
            f_output.write(u_mail)
            f_output.write(";")
            f_output.write("OK")
            f_output.write("\n")

        time.sleep(1.51)
        i = i + 1

    f_input.close()
    f_output.close()


def check_valid_domain(domain):

    # Check if domain has valid format
    if re.match(r"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$", domain):
        return True
    else:
        print("[!] ERROR. Specified invalid domain. Please, see help data with -h or --help" + "\n")
        return False

# Function to validate email address format [*@domain.com]
def check_valid_email(email):

    # Check if user email address has valid format
    if re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return True
    else:
        print("[!] ERROR. Specified invalid user email address. Please, see help data with -h or --help" + "\n")
        return False

# Function to read user submitted commands
def read_args():

    # General application info
    parser = argparse.ArgumentParser(
        prog='HBP_Finder',
        description='Search for Leaks and Paste data using HaveIBeenPwned Public API (v2.0).',
        epilog=textwrap.dedent('''\
         USAGE EXAMPLES
         --------------------------------
            HBP_Finder.py user@mydomain.com -f
            HBP_Finder.py -u user@mydomain.com -d adobe.com
            HBP_Finder.py -l myemailslist.txt -f
            HBP_Finder.py -l myemailslist.txt -d adobe.com
            HBP_Finder.py -s
         '''),
        formatter_class=argparse.RawDescriptionHelpFormatter)

    # Required arguments
    parser.add_argument(
        'user',
        metavar='[USER EMAIL]',
        nargs='+',
        help='user email to check on Leaks and Paste databases (e.g user@mydomain.com)')

    # Optional arguments
    parser.add_argument(
        '-l', '--list',
        nargs='?',
        type=argparse.FileType(mode='r'),
        help='inputs file containing a list of email employees')
    parser.add_argument(
        '-o', '--output',
        nargs='?',
        type=argparse.FileType(mode='w'),
        help='output file for save results data')
    parser.add_argument(
        '-d', '--domain',
        nargs='?',
        help='specific leak domain to check for (e.g adobe.com)')
    parser.add_argument(
        '-s', '--show',
        action='store_true',
        help='only shows last leaks within one week time frame')
    parser.add_argument(
        '-f', '--full',
        action='store_true',
        help='check data against all available leaks (by default only last week is checked)')

    # Load arguments on an object
    args = parser.parse_args()
    # Check arguments format and validity
    valid_user=check_valid_email(args.user)
    if valid_user:
        if args.domain:
            if check_valid_domain(args.domain):
                return args
            else:
                sys.exit(0)
        else:
            return args

def main():

    # Argument reading and format checking
    args=read_args()

    # Run program
    if args.show: #Only show available breaches on API database
        run_args(args)

if __name__ == "__main__":
    main()