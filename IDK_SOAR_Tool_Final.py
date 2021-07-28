#!/usr/bin/env python3

import sys
import subprocess
import ipaddress
import requests
# install netdiscover with `pip3 install python-netdiscover`
from netdiscover import *

disc = Discover()

import json
import os
import time

my_ip = sys.argv[1]

api_key = " "

vt_report_file = "vt_report.json"

# external_database file is local to your VM. You need to make your own file with IP's in it to test against or 
# run the whole tool
external_database_file = "external_database"
# countries_file is local to your VM. You need to make your own file with countries in it to test against or 
# run the whole tool
countries_file = "countries_file"

ip_is_internal = False

print("\nStarting IDK SOAR Tool")
print("Scanning IP Address: " + str(my_ip))
print('-----------------------------------------------------------')

hosts = disc.scan(ip_range=my_ip)

if hosts:
    ip_is_internal = True
    print("IP " + str(my_ip) + " is internal\n")
    print("Returned Internal Hosts: ")
    for i in hosts:
        print("%s -> %s" % (i["ip"], i["mac"]))
else:
    ip_is_internal = False
    print("IP " + str(my_ip) + " is external\n")


if ip_is_internal == True:

#nmap

  print("\nRunning NMAP on " + str(my_ip))

  nmapO = "nmap -O -vv " + str(my_ip) + " | grep 'OS detail'|awk -F \: '{print $2}'"
  nmapOPS = subprocess.Popen(nmapO, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  nmapOOUT = nmapOPS.communicate()[0]
  print("This is the OS: " + nmapOOUT.decode('utf-8'))

  nmapvuln = "nmap --script nmap-vulners -sV -vv " + str(my_ip) + " | grep 'open'"
  nmapvulnPS = subprocess.Popen(nmapvuln, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  nmapvulnOut = nmapvulnPS.communicate()[0]
  print("Vulnerabilities are:\n" + nmapvulnOut.decode('utf-8'))



#whois

if ip_is_internal == False:
  print("Running WHOIS on " + str(my_ip))

  whois = "whois " + str(my_ip)
  whoisPS = subprocess.Popen(whois, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  whoisOut = whoisPS.communicate()[0]
  print(whoisOut.decode('utf-8'))


#Virustotal

def scan(url, api_key):
    url = 'https://www.virustotal.com/vtapi/v2/url/scan'
    scan_id_list = []
    # for URL in url_batch:
    try:
        params = {'apikey': api_key, 'url': url }
        response = requests.post(url, data=params)
        print("printing response!!")
        #print(response)
        scan_id_list.append(response.json()['scan_id'])
        print(scan_id_list)
    except ValueError as e:
        print("Rate limit detected: 4", e)
        # continue
    except Exception:
        print("Error detected: ")
        # continue
    return scan_id_list

def report(scan_id_list, api_key):
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    report_list = []
    for id in scan_id_list:
        try:
            params = {'apikey': api_key, 'resource': id }
            response = requests.get(url, params=params)
            report_list.append(response.json())
        except ValueError as e:
            print("Rate limit detected: 4", e)
            continue
        except Exception:
            print("Error detected:")
            continue
    return report_list

output_file = open(vt_report_file, 'w+')
response = scan(my_ip, api_key)
print("Virustotal Scan Response: ", response)

print('scan complete')

reportBatch = report(response, api_key)

for r in reportBatch:
    json.dump(r , output_file)
    output_file.write("\n")
    print(r)
output_file.close()


#freegeoip

if ip_is_internal == False:

  url = "https://freegeoip.app/xml/" + str(my_ip)

  headers = {
      'accept': "application/xml/",
      'content-type': "application/xml"
      }

  response = requests.request("GET", url, headers=headers)
  xml_text=response.text
  print(xml_text)

  from re import search
  country_name = search(r'<CountryName>(.*)</CountryName>', xml_text)
  print("Country Name: " + country_name.group(1))



  #IP Risk Scoring System

  #Database Function

  line_holder = []
  ip_risk = 0

  def risk_score(input):
      total = 0
      with open(external_database_file) as f:
          for line in f:
              line_holder.append(line.rstrip())
      for line in line_holder:
          if line == input:
              total += 1   
      return total  
  ip_risk = risk_score(my_ip)
  


  #Country File Function
  def country_origin(new_input):
      new_total = ip_risk
      with open(countries_file) as f:
          for line in f:
              if str(line).strip() == new_input.strip():
                  new_total += 1   
          return new_total  
  the_sum = country_origin(str(country_name.group(1)))
  print("Risk Score: " + str(the_sum) + '\n')



#ufw
if ip_is_internal == False:
  
  ufwenable = "ufw enable"
  ufwenPS = subprocess.Popen(ufwenable, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  ufwenOut = ufwenPS.communicate()[0]
  print(ufwenOut.decode('utf-8'))

  ufwstatus = "ufw status"
  ufwstatusPS = subprocess.Popen(ufwstatus, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  ufwstatusOut = ufwstatusPS.communicate()[0]
  print(ufwstatusOut.decode('utf-8'))

  ufwfrom = "ufw deny from " + str(my_ip)
  ufwfromPS = subprocess.Popen(ufwfrom, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  ufwfromOut = ufwfromPS.communicate()[0]
  print(ufwfromOut.decode('utf-8'))

  ufwto = "ufw deny to " + str(my_ip)
  ufwtoPS = subprocess.Popen(ufwto, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  ufwtoOut = ufwtoPS.communicate()[0]
  print(ufwtoOut.decode('utf-8'))


print('-----------------------------------------------------------')
print("Exiting IDK SOAR Tool\n")
