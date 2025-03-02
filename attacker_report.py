#!/usr/bin/env python3
"""
@author Jason Yeung
"""

import re
import os
import platform
import subprocess
from collections import defaultdict
from geoip import geolite2

def text():
    index = 0 # index used for ip address
    ip_address, fails = num_attempts() # get a list of ips and number of attempts
    date = subprocess.check_output(["date"], 
        universal_newlines = True) # command date

    # for current date and time
    date = date.split()
    sp_date = date[0] + " " + date[1] + " " + date[2] + " " + date[5] + " " + date[3]

    ip_dict = defaultdict(list) # ip dictionary
    for i in fails: # iterate through the keys
        if i >= 10: # if attempts are more than or equal to 10
            i_a = ip_address[index] # get the ip from the list
            ip_dict[i].append(i_a) # append it to the dictionary using the key(attempts)
        index+=1
    print("\033[1;32;40mAttacker Report\033[0;0m -", sp_date ,"\n")
    print("\033[1;31;40mCOUNT\tIP ADDRESS\tCOUNTRY\033[0;0m")
    for count in sorted(ip_dict.keys()): # iterate through the keys sorted
        ip_a = ip_dict[count][0] # get the ip of the current key
        geo = geolite2.lookup(ip_a)
        print(count, "\t", ip_a, "\t", geo.country, sep = "")

def num_attempts(): 
    ip_address = [] # ip list
    fails = [] # fail/attempts list
    cat_f = subprocess.Popen(["cat", "syslog.log"],
        stdout = subprocess.PIPE) # cat the syslog
    num_at = subprocess.check_output(["grep", "Failed password for"],
        stdin = cat_f.stdout, universal_newlines = True) # grep the attempts
    cat_f.wait() # wait till it finished
    num_at = num_at.split("\n") # split at new line
    for i in num_at:
        try:
            # uses find and makes a string 'from' to end of line
            re1 = re.search(r"from", i)
            l_str = i[re1.start():len(i)]
            a_str = l_str.split()
            if a_str[1] not in ip_address: # if the ip address is not in the list
                fails.append(1) # add 1 to failed attempts
                ip_address.append(a_str[1]) # add the ip
            else:
                in_dex = ip_address.index(a_str[1]) # get the index of the given ip
                fails[in_dex] += 1 # increment failed attempts by 1
        except:
            continue 
    return ip_address, fails

def main():
    os.system("clear") # clear the screen
    text() # text function
    print("\n") # new line

if __name__ == "__main__":
    main()
