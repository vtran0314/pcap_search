import os
import re 
import pandas as pd
import virustotal_python
from pprint import pprint
from base64 import urlsafe_b64encode

#=============================DEFINITION SECTION==========================================

#Find URL within the file and output the URL string	
def Find(string):
  
    # findall() has been used 
    # with valid conditions for urls in string
    regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
    url = re.findall(regex,string)      
    return [x[0] for x in url]
    #return url will show 2D array

#Check if URL is malicious
def CheckUrl(url):

        with virustotal_python.Virustotal("<Your VirusTotal API Key>") as vtotal:       
            try:
                resp = vtotal.request("urls", data={"url": url}, method="POST")
                # Safe encode URL in base64 format
                # https://developers.virustotal.com/reference/url
                url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
                report = vtotal.request(f"urls/{url_id}")
                pprint(report.object_type)
                pprint(report.data)
            except virustotal_python.VirustotalError as err:
                print(f"Failed to send URL: {url} for analysis and get the report: {err}")

      

        
#=============================MAIN SECTION=================================================

#need user input for pcap filename and output csv filename
pcapfilename, output_filename = input("Please input filename and output filename: ").split()

cmd = 'tshark -r' + pcapfilename + " -e frame -e ip.src -e ip.dst -T fields -e http.response_for.uri -e http.content_type > " + output_filename


#cmd = "tshark -r" + "user input filename " + "-e frame -e ip.src -e ip.dst -T fields -e http.response_for.uri -e http.content_type > output.csv"
        #Search dir - if filename exist => alert!!!

os.system(cmd)


print("Analyzing output for suspicious behavior...")

#Output line contains the word "Download"
with open(output_filename) as f:
	for line in f.readlines():
		if 'download' in line:
                        url = Find(line)
                        #print(Find(line))
                        CheckUrl(url[0])
                        #print("URL: ", url) will always return all the urls found from Find(url) definition






#Reference:
#https://pypi.org/project/virustotal-python/

#https://bobbyhadz.com/blog/python-attributeerror-list-object-has-no-attribute-encode
