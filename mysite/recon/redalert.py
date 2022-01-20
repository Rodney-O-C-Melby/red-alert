import json

from .models import ReconTool

import subprocess
import socket
import re
import os
import nmap
import ares
#import vulners


def print_dict(dict):
    for value in dict:
        for key, text in value:
            print(key + ":" + text)


def cve_search(search):
    cve = ares.CVESearch()
    cve_list = cve.browse('linux')
    return cve_list

# def run_vulners_cpe(cpe_list):
#     vul_api = vulners.VulnersApi(api_key="")
#     cpe_results = vul_api.get_cpe_vulnerabilities(cpe_list[0])
#     cpe_exploit_list = cpe_results.get('exploit')
#     cpe_vulnerabilities_list = [cpe_results.get(key) for key in cpe_results if key not in ['info', 'blog', 'bugbounty']]
#     return cpe_exploit_list, cpe_vulnerabilities_list
#
#
# def run_vulners_software(name, version):
#     vul_api = vulners.VulnersApi(api_key="")
#     results = vul_api.get_software_vulnerabilities(name, version)
#     exploit_list = results.get('exploit')
#     vulnerabilities_list = [results.get(key) for key in results if key not in ['info', 'blog', 'bugbounty']]
#     # print(str(vulnerabilities_list) + "\n\n")
#     return exploit_list, vulnerabilities_list
#
#
# def run_vulners_query(query):
#     vul_api = vulners.VulnersApi(api_key="")
#     results = vul_api.find(query)
#     return results
#
#
# def run_vulners_apps(query):
#     vul_api = vulners.VulnersApi(api_key="")
#     results = vul_api.find(query)
#     return results
#
#
# def parse_vulners_os(operating_system):
#     new = ""
#     if operating_system == "Linux":
#         new = "unix"
#     elif operating_system == "Windows":
#         new = "msrc"
#     return new


def ipv4(s):
    try:
        return str(int(s)) == s and 0 <= int(s) <= 255
    except:
        return False


def ipv6(s):
    if len(s) > 4:
        return False
    try:
        return int(s, 16) >= 0 and s[0] != '-'
    except:
        return False


def valid_ip(address):
    """
    :type address: str
    :rtype: str
    """
    if address.count(".") == 3 and all(ipv4(i) for i in address.split(".")):
        return True
    if address.count(":") == 7 and all(ipv6(i) for i in address.split(":")):
        return True
    return False


def valid_host(hostname):
    """ Checks for at least 1 char to a max of 63 chars, only has allowed characters, no hyphen at start or end. """
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]  # strip exactly one dot from the right, if present
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))


def valid_net(network):
    """  """
    is_net_ip = valid_ip(network[:-3])
    if is_net_ip:
        return True
    is_net_host = valid_host(network[:-3])
    if is_net_host:
        return True
    if not is_net_ip and not is_net_host:  # no hostname or ip input error
        return False
    if "/" not in network:
        return False
    return False


def parse_searchsploit_json(filename):
    """ parses searchsploit json output, from a file, into a json object. """
    with open(filename) as f:
        data = f.read()
        # print(data)
        data = data.replace('\n', '')
        data = data.replace('\t', '')
        new_data = data.replace('}{', '},{')
        json_data = json.loads(f'[{new_data}]')
    return json_data


def make_executable(path):
    mode = os.stat(path).st_mode
    mode |= (mode & 0o444) >> 2    # copy R bits to X
    os.chmod(path, mode)


def get_ip(scan_mode, ip_or_host):
    """ Get ip from user input, or return empty string if no ping or route to host. """
    ip = ""
    if int(scan_mode) != 5:  # if auto scan
        try:
            ip = socket.gethostbyname(ip_or_host)
        except socket.gaierror:
            # likely list of hosts /24 or not exists (no ping or route to host)
            if "/" in ip_or_host:
                ip = ip_or_host  # set ip to network e.g. 10.0.0.1/24
            else:
                return ""
    if int(scan_mode) == 5:  # if manual scan
        words = ip_or_host.split()  # get ip from user input string
        ip = words[-1]  # get ip
    # print(ip)
    return ip


def get_hostname(scan_mode, ip_address, user_input):
    """ Get hostname from ip, or return empty string if no ping or route to host. """
    hostname = ""
    if int(scan_mode) != 5:
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
        except socket.herror:
            hostname = user_input
    if int(scan_mode) == 5:
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
        except socket.herror:
            words = user_input.split()  # get ip from user input string
            hostname = words[-1]  # get hostname
    print("Hostname " + hostname)
    return str(hostname)


def set_nmap_args(scan_mode, user_input):
    """ Set nmap arguments from mode. """
    string = None
    if int(scan_mode) == 1:
        string = "--privileged -sV -O"  # TCP scan
    if int(scan_mode) == 2:
        string = "--privileged -sU -O"  # UDP scan
    if int(scan_mode) == 3:
        string = "--privileged -Pn -sV -O"  # Silent scan
    if int(scan_mode) == 4:
        string = "--privileged -sV -O -A"  # Attack scan
    # TODO: CREATE PROXY SCAN USING LIVE PROXY LIST
    if int(scan_mode) == 5:  # if manual scan
        words = user_input.split()  # get ip from user input string
        words.pop()  # pop ip off so only args
        string = "--privileged " + ' '.join(words)  # set scan to string of nmap args list
    return string


def hostname_check(user_input, target_ip):
    hostname = ""
    try:
        hostname = socket.gethostbyaddr(user_input)[0]
    except socket.herror:
        try:
            hostname = socket.gethostbyaddr(target_ip)[0]
        except socket.herror:
            hostname = user_input
    return hostname


def nmap_scan(ip_address, arguments, filename):
    # nm.scan(hosts='192.168.1.0/24', arguments='-n -sP -PE -PA21,23,80,3389')
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_address, arguments=arguments)
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    xml = nm.get_nmap_last_output()

    # write nmap xml output to file
    f = open("mysite/recon/output/scans/" + filename + ".xml", "w")
    f.write(xml.decode("utf-8"))
    f.close()

    return hosts_list, nm


def parse_nmap_scan(scan_data):
    # parse nmap data
    host, system, kernel, protocol, vendor, mac, cpe, ports = "", "", "", "", "", "", "", ""
    if "addresses" in scan_data:
        if "mac" in scan_data["addresses"]:
            mac = scan_data["addresses"]["mac"]
    if "vendor" in scan_data:
        if len(scan_data["vendor"]) > 0:
            if scan_data["vendor"][mac] != '':
                vendor = scan_data["vendor"][mac]
    if "osmatch" in scan_data:  # set system and kernel if exists
        # print("osmatch length " + str(len(nm[ip_address]["osmatch"])))
        if len(scan_data["osmatch"]) > 0:  # check list not empty
            if "osclass" in scan_data["osmatch"][0]:
                if len(scan_data["osmatch"][0]["osclass"]) > 0:
                    #print(scan_data["osmatch"][0]["osclass"][0])
                    if "osfamily" in scan_data["osmatch"][0]["osclass"][0]:
                        if scan_data["osmatch"][0]["osclass"][0]["osfamily"] != '':
                            system = scan_data["osmatch"][0]["osclass"][0]["osfamily"]
                    if "osgen" in scan_data["osmatch"][0]["osclass"][0]:
                        if scan_data["osmatch"][0]["osclass"][0]["osgen"] != '':
                            kernel = scan_data["osmatch"][0]["osclass"][0]["osgen"]
                    if "cpe" in scan_data["osmatch"][0]["osclass"][0]:
                        if scan_data["osmatch"][0]["osclass"][0]["cpe"] != '':
                            cpe = scan_data["osmatch"][0]["osclass"][0]["cpe"]

    if scan_data.all_protocols():  # get protocol
        if scan_data.all_protocols()[0] != '':
            protocol = scan_data.all_protocols()[0]
    if protocol in scan_data and len(scan_data[protocol]) > 0:  # get ports with protocol
        ports = scan_data[protocol]
    if scan_data.hostname():  # get hostname
        if len(scan_data.hostname()) > 0 and scan_data.hostname()[0] != '':  # list has elements with values
            host = scan_data.hostname()
    return host, system, kernel, protocol, vendor, mac, cpe, ports


def grep_before(string, seperator):
    """ grep value before given separator. """
    space = re.search(seperator, string)
    first, last = space.span()
    value = string[:last]
    new_string = string[last:]
    return value, new_string


def os_execute(command):
    result = os.system(command)
    return result


def execute(input_list):
    process = subprocess.run(input_list, capture_output=True, text=True, stdin=subprocess.PIPE)
    return process


# def parse_nmap_output_ports(output):
#     port, service, state, protocol, program, version, extra_info = "", "", "", "", "", "", ""
#     # parse output for os and kernel
#     string = re.search("PORT", output)  # search for index of PORT
#     if string is not None:  # if found
#         discard, start = string.span()  # get index
#         title, rest = output[start:].split("\n", 1)  # split at new line
#         end = re.search("Device type:", rest)  # grep search
#         finish, discard = end.span()  # get index finish
#         ports = rest[:finish]  # port output
#
#         for line in ports.splitlines():  # for each port / line
#             print("line")
#             print(line)
#             slash = re.search("/", line)
#             port_number_index, leftover = slash.span()
#             port_number = line[:port_number_index]
#             line = line[leftover:]
#             #print(line)
#             # get ip layer protocol TCP/UDP
#
#             protocol, leftover = grep_before(line, " ")
#             state, leftover = grep_before(leftover, " ")
#             state, leftover = grep_before(leftover, " ")
#
#             print(port_number)
#             print(protocol)
#             print(state)
#             print(service)
#     #return scan_os, kernel


def get_tool_args(target_ip, tool_name):
    """ Takes ip and tool name as input and returns tool_id, tool args list. """
    tool_data = ReconTool.objects.filter(name=tool_name)  # get recon tool args
    tool_args_list = tool_args_to_list(tool_data, target_ip)  # create command and return list for subprocess execution
    tool_id = ReconTool.objects.filter(name=tool_name).latest('id').id  # get tool id
    return tool_id, tool_args_list


def parse_selected_tools(body_input):
    """ Takes request body as input and returns a list of selected tool names. (ignoring ip and csrf token) """
    program = ""
    program_list, checkbox_list = [], []
    body_list = body_input.decode('utf-8').split('&')[2:]  # get tools selected from request body, as list
    for i in range(0, len(body_list)):
        key, content = body_list[i].split('=')  # get key value pair
        if "name" in key:  # tool name
            program = content  # assign program name to variable for later use
        if "name" not in key:  # checkbox value
            if "on" in content:  # if tool selected
                checkbox_list.append(True)
                program_list.append(program)  # add tool name to list
    return program_list, checkbox_list


def parse_nmap_output_basic(output):
    scan_os, kernel = "Unknown", "Unknown"
    # parse output for os and kernel
    string = re.search("OS details: ", output)  # search for index of OS details
    if string is not None:  # if found
        discard, start = string.span()
        scan_os, rest = output[start:].split(" ", 1)
        kernel, leftover = rest.split("\n", 1)
    return scan_os, kernel


def tool_args_to_list(args_data, ip_address):
    """ takes arguments and ip as input, returns list for execution. """
    my_list = list()  # turn valid argument string into list
    my_list.append(args_data[0].name)  # add program to list
    args = [args_data[0].argv1, args_data[0].argv2, args_data[0].argv3, args_data[0].argv4, args_data[0].argv5,
            args_data[0].argv6, args_data[0].argv7, args_data[0].argv8, args_data[0].argv9]
    # add each arg to list
    for index in range(0, len(args)):
        if args[index] != "":
            my_list.append(args[index])
    # add ip to command
    my_list.append(ip_address)
    # print(my_list)
    return my_list


def create_command_list(name, argv1, argv2, argv3, argv4, argv5, argv6, argv7, argv8, argv9, ip_address):
    """ takes module data and ip as input, returns list for execution. """
    my_list = list()  # turn valid argument string into list
    my_list.append(name)  # add program to list
    args = [argv1, argv2, argv3, argv4, argv5, argv6, argv7, argv8, argv9]
    # add each arg to list - if not empty
    for index in range(0, len(args)):
        if args[index] != "":
            my_list.append(args[index])
    my_list.append(ip_address)  # add ip to command
    return my_list
