import os
import re 
import pandas as pd
import virustotal_python
import time
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

       #with virustotal_python.Virustotal("<VirusTotal API Key>") as vtotal:
        with virustotal_python.Virustotal("b24bfd3b0febf2f1eddcbb93122b50738e2fe92fbc4eff5720cd470ff532835c") as vtotal:       
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

#def isMalicious(filename)
#	for line in filename:
#		if line 

        
#=============================MAIN SECTION=================================================

#need user input for pcap filename and output csv filename
timestr = time.strftime("%Y%m%d-%H%M%S")

#pcapfilename, output_filename = input("Please input filename and output filename: ").split()

pcap_filename = input("Please input PCAP file: ")

output_filename = "output" + timestr + ".csv"

vt_result = "vtotal_result" + timestr + ".csv"

cmd = 'tshark -r' + pcap_filename + " -e frame -e ip.src -e ip.dst -T fields -e http.response_for.uri -e http.content_type > " + output_filename

#cmd = 'tshark -r' + pcapfilename + " -e frame -e ip.src -e ip.dst -T fields -e http.response_for.uri -e http.content_type > " + output_filename


os.system(cmd)




print("Analyzing" + output_filename + "for suspicious behavior...")

#Output line contains the word "Download"
with open(output_filename) as f:
	for line in f.readlines():
		if 'download' in line:
                        url = Find(line) 
                        #print(Find(line))
                        for x in url:
                        	str_url = x
                        	with open(vt_result, "w") as file:
                        		file.write(CheckUrl(str_url))
		continue
#with open(vt_result, "w") as file:
#	for x in url
                        #CheckUrl(url[0]) #print("URL: ", url) will always return all the urls found from Find(url) definition
		#else:
                	#print("No suspicious behavior found")
                	
                	
                	
                       






#Reference:
#https://pypi.org/project/virustotal-python/

#https://bobbyhadz.com/blog/python-attributeerror-list-object-has-no-attribute-encode
