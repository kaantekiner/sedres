import configparser
import socket
import re
import binascii
from datetime import datetime
import threading
import time
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import sqlite3


#///////////////////// thread functions /////////////////////#

def load_blacklist_from_local_file(interval):
    interval = int(interval)
    global blacklist_file
    global blacklist
    try:
        while True:
            time.sleep(interval)
            with open(blacklist_file) as f:
                content = f.readlines()
            blacklist_lines = [x.strip() for x in content]
            write("<thread>implementing blacklist file to memory, entry count: " + str(len(blacklist_lines)))
            blacklist = list(dict.fromkeys(blacklist_lines))
            blacklist_lines.clear()
    except Exception as err:
        write("Error occurred: " + str(err))


def load_blacklist_from_web(interval):
    interval = int(interval)
    global blacklist_file
    global blacklist
    while True:
        time.sleep(interval)
        try:
            append_counter = 0
            write("<thread>requesting malicious domain names")
            x = requests.get("https://www.usom.gov.tr/url-list.txt", verify=False, timeout=40)
            if x.status_code == 200:
                write("<thread>malicious domain names fetched, applying regex")

                regex_results = re.findall('.*[a-z]', x.text)
                malic_dns_list = list(dict.fromkeys(regex_results))
                write("<thread>regex applied")
                write("<thread>appending malicious domain names into file, just not exist ones.")
                with open(blacklist_file) as x:
                    content = x.readlines()
                local_blacklist_file_list = [x.strip() for x in content]

                with open(blacklist_file, 'a') as f:
                    for dns_line in malic_dns_list:
                        if dns_line not in local_blacklist_file_list and '/' not in dns_line:
                            f.write((dns_line.replace("\x20", "").replace("\n", "")).strip() + "\n")
                            append_counter += 1
                write("<thread>append process complete with " + str(append_counter) + " new records, clearing RAM")
                write("<thread>RAM cleared, update process complete")
                append_counter = 0
                malic_dns_list.clear()
                content.clear()
                local_blacklist_file_list.clear()
            else:
                write("can not fetch the domain list from web.")
        except Exception as err:
            write("Error occurred: " + str(err))


def start_threads(interval_local, interval_web):
    t1 = threading.Thread(target=load_blacklist_from_local_file, args=(interval_local,), daemon=True)
    t2 = threading.Thread(target=load_blacklist_from_web, args=(interval_web,), daemon=True)
    t1.start()
    t2.start()


#///////////////////// utility function /////////////////////#

def write(text):
    global log_file
    try:
        text = str(datetime.now().strftime("%d/%m/%Y %H:%M:%S") + " - " + text)
        print(text)
        with open(log_file, 'a') as f:
            f.write(text + "\n")
    except Exception as err:
        print("Error occurred:", str(err))


def log_dns_query(is_secure, dns):
    global db
    global db_cursor
    db_cursor.execute("INSERT INTO dns_queries (date, is_secure, dns) VALUES (?, ?, ?)", (str(datetime.now().strftime("%d/%m/%Y %H:%M:%S")), str(is_secure), dns))
    db.commit()



def build_alert(addr, dns):
    global db
    global db_cursor
    db_cursor.execute("INSERT INTO alerts (date, addr, alert_data) VALUES (?, ?, ?)", (str(datetime.now().strftime("%d/%m/%Y %H:%M:%S")), addr, dns))
    db.commit()



#///////////////////// main functions /////////////////////#

def load_blacklist():
    global blacklist_file
    global blacklist
    try:
        with open(blacklist_file) as f:
            content = f.readlines()
        blacklist_lines = [x.strip() for x in content]
        write("entry in blacklist file: " + str(len(blacklist_lines)))
        write("implementing blacklist file to memory")
        blacklist = list(dict.fromkeys(blacklist_lines))
        blacklist_lines.clear()
    except Exception as err:
        print("Error occurred:", str(err))
        exit(0)


def start_socket(dns_service_address, dns_service_port):
    global glb_sock
    try:
        write("Starting DNS Server")
        glb_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        glb_sock.bind((dns_service_address, int(dns_service_port)))
        write("DNS Server started at: " + str(dns_service_address + ":" + str(dns_service_port)))
    except Exception as err:
        write("Error occurred: " + str(err))


def listen_socket():
    global glb_sock
    try:
        write("Listening socket....\n")
        while True:
            # get dns request data from client
            went_data, addr = glb_sock.recvfrom(512)
            # write("went data from client: " + str(went_data))

            # parse domain name
            domain_for_regex = bytes.fromhex(binascii.hexlify(bytearray(went_data)).decode("utf-8")).decode('utf-8', errors='ignore')
            domain_name_list = re.compile('\w{2,}').findall(domain_for_regex)
            if len(domain_name_list) > 4:
                del domain_name_list[0]
            for item in domain_name_list:
                if not item.islower():
                    domain_name_list.remove(item)
            dns = ""
            for item in domain_name_list:
                dns += item + "."
            dns = dns[:-1]
            write("client" + str(addr) + " requested: " + dns)


            # control domain name
            write("running security check")
            isSecure = control_domain_name(dns)

            # if dns not ok, do not answer, dns requester client will timeout
            if not isSecure:
                pass
                write("requested dns is not secure, alerting, no response will be given\n")
                log_dns_query(False, dns)
                build_alert(str(addr), dns)
            else:
                # if dns ok, send data to dns resolve service and give the response back to requester
                write("requested dns is secure, requesting from resolver")
                forward_addr = (dns_resolve_address, int(dns_resolve_port))  # dns and port
                client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                write("requesting to resolver server: " + dns)
                client.sendto(bytes(went_data), forward_addr)
                responsed_data, _ = client.recvfrom(1024)
                write("get response from resolver server, sending to client back")
                # write("redirected response data from server: " + str(responsed_data))
                glb_sock.sendto(responsed_data, addr)
                write("response redirected\n")
                log_dns_query(True, dns)
    except Exception as err:
        write("Error occurred:" + str(err))


def control_domain_name(dns):
    pass
    global blacklist
    if dns in blacklist:
        return False
    return True

print("(local)-------------------------------------")
print("(local)script started, loading configurations")
config_parser = configparser.ConfigParser()
config_parser.read('config.txt')

dns_service_address = config_parser['general_configuration']['dns_service_address']
dns_service_port = config_parser['general_configuration']['dns_service_port']
dns_resolve_address = config_parser['general_configuration']['dns_resolve_address']
dns_resolve_port = config_parser['general_configuration']['dns_resolve_port']

blacklist_interval_web = config_parser['general_configuration']['blacklist_interval_web']
blacklist_interval_local = config_parser['general_configuration']['blacklist_interval_local']
log_file = config_parser['general_configuration']['log_file']

write("-------------------------------------")
write("-------------------------------------")
write("script started, loading configurations")
write("DNS service IP Address is: " + dns_service_address)
write("DNS service Port is: " + dns_service_port)

write("DNS resolve IP Address is: " + dns_resolve_address)
write("DNS resolve Port is: " + dns_resolve_port)

write("Blacklist database remote update interval: " + blacklist_interval_web)
write("Blacklist memory update interval: " + blacklist_interval_local)

blacklist_file = config_parser['general_configuration']['dns_blacklist']
blacklist = []
glb_sock = None

write("configurations loaded.")
write("starting threads for blacklist operations")
start_threads(blacklist_interval_local, blacklist_interval_web)
write("loading blacklist from local file before start")
load_blacklist()
write("executing database operations")
db = sqlite3.connect(config_parser['general_configuration']['database_file'])
write("building database cursor")
db_cursor = db.cursor()
start_socket(dns_service_address, dns_service_port)
listen_socket()










