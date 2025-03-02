"""
This file creates or overwrites a system report of the os
    dev_info - Hostname and domain
    net_info - IP, gateway, and DNS
    os_info - OS info running the script
    storage - Hard drive space and availability
    processor - Infomation on the processor and the cores
    memory - Information on the ram
@author Jason Yeung
"""
import os
import subprocess
import platform

a_file = ""
hostname = ""
t_path = ""

def create_file():
    # global variables
    global hostname # hostname
    global a_file # file name (hostname_system_report.log)
    global t_path # file path (~/Desktop)

    hostname = subprocess.check_output(["hostname"]
        ,universal_newlines = True) # command hostname
    name = hostname + "_system_report.log"
    desktop = os.path.join(os.path.join(os.path.expanduser('~')), 'Desktop')
    t_path = os.path.join(desktop, name)
    a_file = open(t_path, "w") # open the file if there or create it

def cat_pro(a_str): # cat /proc/cpuinfo and allows specification using grep
    cat_proc = subprocess.Popen(("cat", "/proc/cpuinfo"),stdout=subprocess.PIPE)
    output = subprocess.check_output(["grep", a_str]
        ,stdin=cat_proc.stdout, universal_newlines = True)
    cat_proc.wait() # wait till finished
    return output

def get_defaultgwy(): # gets the default gateway
    output = subprocess.check_output(["ip", "-o", "route", "get", "1.1.1.1"],
        universal_newlines = True) # basically ip route get 1.1.1.1
    return output.split(" ")[2]

def dev_info(): # Device information
    a_file.write("\n\033[0;32;40mDevice Information\033[0;40m")
    a_file.write("\nHostname: \t\t" + hostname)
    domain = subprocess.check_output(["domainname"] # command domainname
        ,universal_newlines = True)
    a_file.write("Domain: \t\t" + domain)

def net_info(): # Network information
    a_file.write("\n\033[0;32;40mNetwork Information\033[0;40m");
    if_config = subprocess.check_output(["ifconfig"],
        universal_newlines = True) # command ifconfig
    ip = if_config.split()[5]    
    mask = if_config.split()[7]

    a_file.write("\nIP Address: \t\t" + ip)
    a_file.write("\nGateway: \t\t" + get_defaultgwy())
    a_file.write("\nNetwork Mask: \t\t" + mask)

    DNS_s = subprocess.check_output(["cat", "/etc/resolv.conf"],
        universal_newlines = True) # command cat /etc/resolv.conf
    DNS_1 = DNS_s.split()[7]
    DNS_2 = DNS_s.split()[9]

    a_file.write("\nDNS1: \t\t\t" + DNS_1)
    a_file.write("\nDNS2: \t\t\t" + DNS_2)

def os_info(): # OS information
    a_file.write("\n\n\033[0;32;40mOS Information\033[0;40m")
    
    o_info = subprocess.check_output(["cat", "/etc/os-release"],
        universal_newlines = True) # command cat /etc/os-release
    o_info = o_info.split()
    o_sys = o_info[0]

    a_file.write("\nOperating System: \t" + o_sys.split('="')[1] + " " 
            + o_info[1].split('"')[0])
    a_file.write("\nOperating Version: \t" + o_info[2].split('"')[1])
    a_file.write("\nKernal version: \t" + subprocess.check_output(["uname", "-r"],
        universal_newlines = True)) # command uname -r

def storage(): # Storage information
    a_file.write("\n\033[0;32;40mStorage Information\033[0;40m")
    df = subprocess.check_output(["df", "-h"],
        universal_newlines = True) # command df -h
    df = df.split()

    a_file.write("\nHard Drive Capacity: \t" + df[32]);
    a_file.write("\nAvailable Space: \t" + df[34]);

def processor(): # Processor information
    a_file.write("\n\n\033[0;32;40mProcessor Information\033[0;40m")
    # Calls cat_pro which does the command cat /proc/cpuinfo
    c_model = cat_pro("model name").split("model name\t: ")
    n_procesor = cat_pro("processor").split()
    n_cores = cat_pro("cores").split()

    a_file.write("\nCPU Model: \t\t" + c_model[1])
    a_file.write("Number of processors: \t" + n_procesor[5])
    a_file.write("\nNumber of cores: \t" + n_cores[3])

def memory():
    a_file.write("\n\n\033[0;32;40mMemory Information\033[0;40m")
    mem = subprocess.check_output(["free", "-h"],
        universal_newlines = True) # command free -h
    mem = mem.split()

    a_file.write("\nTotal Ram: \t\t" + mem[7]);
    a_file.write("\nAvailable Ram: \t\t"+ mem[9] + "\n");

def main():
    os.system("clear")
    create_file()
    date = subprocess.check_output(["date"],
        universal_newlines = True) # command date
    date = date.split()
    sp_date = date[0] + " " + date[1] + " " + date[2] + " " + date[5] + " " + date[3]
    a_file.write("\t\033[0;31;40mSystem Report: Current Date - " + sp_date + "\033[0;40m\n") # combine time and date

    dev_info()
    net_info()
    os_info()
    storage()
    processor()
    memory()
    
    a_file.close() # close the file
    
    # reopen the file to read it
    f = open(t_path, "r")
    os.system("clear")
    print(f.read())
    f.close()

if __name__ == "__main__":
    main()
