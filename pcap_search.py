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
	cmd = "touch vtotal_result-" + timestr + ".txt"
	os.system(cmd)
   
	with virustotal_python.Virustotal("VirusTotal API Key") as vtotal:
            try:
                resp = vtotal.request("urls", data={"url": url}, method="POST")
                # Safe encode URL in base64 format
                # https://developers.virustotal.com/reference/url
                url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
                report = vtotal.request(f"urls/{url_id}")
                with open('vt_result.txt', 'a') as out:
                	pprint(report.object_type, stream=out )
                	pprint(report.data, stream=out)
                	#out.close()
            except virustotal_python.VirustotalError as err:
                print(f"Failed to send URL: {url} for analysis and get the report: {err}")

def isMalicious(file):
	for line in file:
		if ("'malicious': 1") in line:
			return true

#TO-DO 
#Alert() triggered but did not complete running. 
def alert():

	# modules
	import smtplib
	from email.message import EmailMessage

	print("Sending Email...")
	# content
	sender = "sender_email@example.com"
	receiver = "receiver_email@example.com"
	password = "Sender's password"
	msg_body = 'Hello! I found sth interesting'
		 
	# action
	msg = EmailMessage()
	msg['subject'] = 'Email sent using outlook.'   
	msg['from'] = sender
	msg['to'] = receiver
	msg.set_content(msg_body)

	with smtplib.SMTP_SSL('smtp-mail.outlook.com', 465) as smtp:
	    smtp.login(sender,password)
	    
	    smtp.send_message(msg)
	print("Email Sent!")

#=============================MAIN SECTION=================================================

#need user input for pcap filename and output csv filename
timestr = time.strftime("%Y%m%d")

#pcapfilename, output_filename = input("Please input filename and output filename: ").split()

pcap_filename = input("Please input PCAP file: ")

output_filename = "output" + timestr + ".csv"



cmd = 'tshark -r' + pcap_filename + " -e frame -e ip.src -e ip.dst -T fields -e http.response_for.uri -e http.content_type > " + output_filename

#cmd = 'tshark -r' + pcapfilename + " -e frame -e ip.src -e ip.dst -T fields -e http.response_for.uri -e http.content_type > " + output_filename


os.system(cmd)


print("Analyzing" + output_filename + "for suspicious behavior...")

#Output line contains the word "Download"
with open(output_filename) as f:
	for line in f.readlines():
		if 'download' in line:
                        url = Find(line)                        
                        for x in url:
                        	print("Checking: ",x)
                        	CheckUrl(x)                        	
                        	time.sleep(2)                   

with open("vtotal_result-" + timestr + ".txt") as file:
	if isMalicious(file) == 1:
		alert()
	else:
		print("All Good!....For now >:)")

#alert() - Working on it	


#Reference:
#https://pypi.org/project/virustotal-python/

#https://bobbyhadz.com/blog/python-attributeerror-list-object-has-no-attribute-encode
