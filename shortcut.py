#!/usr/bin/env python3
"""
@author Jason Yeung
"""
import os
import subprocess
import platform
import time

def path():
    global hostname # hostname
    global desktop # desktop
    global current_dir # current directory

    hostname = subprocess.check_output(["hostname"]
        ,universal_newlines = True) # command hostname
    desktop = os.path.join(os.path.join(os.path.expanduser('~')), 'Desktop')
    current_dir = subprocess.check_output(["pwd"]
            ,universal_newlines = True) # command pwd

def find_file(a_name): # find the file using locate
    p = subprocess.Popen(["locate", a_name])
    p.wait() # wait till the process finishes

    if (p.poll()):
        print("File " + "\033[1;31;40m" + a_name + "\033[0;0m"
            + " not found")
        time.sleep(1.5)
        return False
    else:
        return True

def grep_link(): # using grep to get shortcut/links
    try:
        grep_l = subprocess.Popen(("ls", "-lhaF")
            ,cwd = desktop, stdout=subprocess.PIPE)
        output = subprocess.check_output(["grep", "^l"]
            ,cwd = desktop, stdin=grep_l.stdout, universal_newlines = True)
        grep_l.wait() # wait till finished
        return output
    except: # error
        return 0

def remove_short(): # remove short/link 
    a_name = input("Enter a shortcut/link to remove: ")
    if (find_file(a_name) == True): # if found
        os.system("clear")
        try:
            dst = os.path.join(desktop, a_name)
            os.remove(dst)
            print("\nShortcut removed, Returning to main menu...")
            time.sleep(1.5)
        except:
            print ("\nShortcut/link not found, Returning to main menu...")
            time.sleep(1.5)
            return True
    else: # if not
        print ("\nShortcut/link not found, Returning to main menu...")
        time.sleep(1.5)
        os.system("clear")
        return True

def text():
    print("\t**********************************",
        "\t********\033[1;32;40m Shortcut Creator \033[0;0m********",
        "\t**********************************", sep = "\n")

    print("\n Enter Selection: \n",
        "1 - Create a shortcut in your home directory.",
        "2 - Remove a shortcut from your home directory.",
        "3 - Run shortcut report.", sep = "\n\t")

    str = input("\nPlease enter a number\033[1;32;40m (1-3) \033[0;0m or\033[1;32;40m Q,q'\033[0;0m to quit the program: ")

    if (str == 'q' or str == 'Q'): # Quit selection
        return False

    elif (str == '1'): # Selection 1
        os.system("clear")
        a_name = input("Enter a file name:\t")
        found = find_file(a_name)
        if (found == False):
            print("\nReturning to the \033[1;33;40mMain Menu\033[0;0m")
            time.sleep(1.5)
            return True
        else:
            output = subprocess.check_output(["locate", a_name],
               universal_newlines = True) # command locate
            os.system("clear")
            output = output.split()
            str = input("Found " + "\033[1;32;40m" + output[0] +"\033[0;0m" +
                " input Y/y " + "to make a shortcut: \t")
            if (str == 'y' or str == 'Y'): # y or Y to create shortcut/link
                print("Creating shortcut for" + output[0])
                dst = os.path.join(desktop, a_name)
                os.symlink(output[0], dst)
                print("\nShortcut created, Returning to main menu...")
                time.sleep(1.5)
            else:
                os.system("clear")
                return True

    elif (str == '2'): # Selection 2
        os.system("clear")
        return remove_short()

    elif (str == '3'): # Selection 3
        os.system("clear")
        print("\t**********************************",
        "\t********\033[1;32;40m Shortcut Report \033[0;0m********",
        "\t**********************************", sep = "\n")
        print("\n\nYour current directory is \033[1;33;40m" + current_dir
            + "\033[0;0m")
        output = grep_link();

        if (output == 0):
            print("No shortcut/links found")
            time.sleep(1.5)
        else:
            output = output.split("\n")
            print("\nThe number of links is \033[1;33;40m"
                , len(output)-1, "\033[0;0m")
            print("\n\033[1;33;40mSymbolic Link\t\t Target Path\033[0;0m")
            for i in range(len(output)-1):
                a_str = output[i] # each link line
                a_st = a_str.split() # split it
                if (len(a_st[8]) > 12): # if the link name is long
                    a_tab = "\t"
                else:
                    a_tab = "\t\t"
                print(a_st[8], a_tab, a_st[10])
            b = True
            while (b): # while enter is pressed or r or R is not inputted
                a_str = input("\nTo return to the \033[1;33;40m Main Menu \033[0;0m"
                    + "press \033[1;33;40m Enter. \033[0;0m" +
                    "Or select \033[1;33;40m R/r \033[0;0m to remove a link.\n")
                if (a_str == 'R' or a_str == 'r'):
                    remove_short()
                elif (a_str == ""):
                    b = False
                else:
                    print ("Please either press \033[1;33;40m Enter. \033[0;0m to return." +
                    "Or select \033[1;33;40m R/r \033[0;0m" +
                    "to remove a link.")
    else:
        print("You entered a \033[1;31;40minvalid\033[0;0m option!",
            "Please select a number between 1 through 4", sep = "\n\n")
        time.sleep(1.5)
        os.system("cls||clear")
    return True

def main():
    b = True # boolean that only turns false after user input q or Q
    os.system("cls||clear")
    path()

    while (b):
        os.system("cls||clear")
        b = text()

    print ("\nQuiting program.",
        "\033[1;33;40mHave a wonderful day!\033[0;0m", sep = "\n\n")

if __name__ == "__main__":
    main()
