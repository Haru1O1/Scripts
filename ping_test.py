"""
This file test for network connectivity depending on the user's choice
    1 - Test connectivity to your gateway
    2 - Test for remote connectivity
    3 - Test for DNS resolution
    4 - Display gateway IP Address
@author Jason Yeung
"""

import os
import time
import subprocess

def ping(ip, selection): # ping method uses a ip and selection(#'s)
    os.system("cls||clear") # clear the screen using cls or clear
    
    if (selection == 1): # selection #1 - connectivity to gateway
        print ("Testing Connectivity to your gateway...")
       
    elif (selection == 2): # selection #2 - remote connectivity
        print ("Testing for remote connectivity... "
            ,"trying IP address", ip)
        
    elif (selection == 3): # selection #3 - diplay gateway IP address
        print("Resolving DNS: trying URL...", ip)
        print("ping: ", ip)
            
    else: # if a error happens
        print ("Error in ping method!!!")
        
    time.sleep(1) # sleep for a sec
    os.system("cls||clear")
    print ("\nRunning test, please wait.\n")
    time.sleep(1) # sleep for a sec
    p = subprocess.Popen(["ping", "-c", "1", ip]) # ping the ip
    p.wait() # wait till the process finishes

    if (p.poll()):
        print("\nPlease inform your system administrator",
                "that the test has \033[1;31;40mFAILED\033[0;0m")
    else:
        print("\nPlease inform your system administrator", # if it works
            "that the test was \033[1;33;40mSUCCESSFUL\033[0;0m")
    time.sleep(1.5) # sleep for one second and a half
    os.system("cls||clear")

def get_defaultgwy(): # gets the default gateway
    output = subprocess.check_output(["ip", "-o", "route", "get", "1.1.1.1"],
        universal_newlines = True) # basically ip route get 1.1.1.1
    return output.split(" ")[2]

def text(): 
    gateway = get_defaultgwy() # store the gateway address

    print("\t******************************",
        "********\033[1;32;40m Ping Test Troubleshooter \033[0;0m********",
        "\t******************************", sep = "\n") # color is green

    print("\n Enter Selection: \n",
        "1 - Test connectivity to your gateway.",
        "2 - Test for remote connectivity",
        "3 - Test for DNS resolution",
        "4 - Display gateway IP Address", sep = "\n\t")

    str = input("\nPlease enter a number\033[2;32;40m (1-4) \033[0;0m or\033[2;32;40m Q,q'\033[0;0m to quit the program: ")

    if (str == 'q' or str == 'Q'): # Quit selection
        return False

    elif (str == '1'): # Selection 1
        ping(gateway, 1)

    elif (str == '2'): # Selection 2
        ping("129.21.3.17", 2) # RIT DNS

    elif (str == '3'): # Selection 3
        ping("www.google.com", 3)
    
    elif (str == '4'): # Selection 4
        os.system("cls||clear")
        print("Your gateway IP address is \033[1;33;40m", get_defaultgwy(),
            "\033[0;0m") # color is yellow
        time.sleep(1.5) # sleep for one second and half
        os.system("cls||clear")
    
    else: 
        print("You entered a \033[1;31;40minvalid\033[0;0m option!",
            "Please select a number between 1 through 4", sep = "\n\n")
        time.sleep(1.5)
        os.system("cls||clear")
    return True

def main():
    b = True # boolean that only turns false after user input q or Q

    os.system("cls||clear")

    while (b):
        b = text()

    print ("\nQuiting program.",
        "\033[1;33;40mHave a wonderful day!\033[0;0m", sep = "\n\n")

if __name__ == "__main__":
    main()
