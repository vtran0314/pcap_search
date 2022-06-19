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
   
	with virustotal_python.Virustotal("Virustotal API Key") as vtotal:
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

#TO-DO Password encryption method
#def encPasswd(pw):
from passlib.hash import bcrypt
from getpass import getpass


#FIX THIS CODE
#key = b'pRmgMa8T0INjEAfksaq2aafzoZXEuwKI7wDe4c1F8AY='
#cipher_suite = Fernet(key)
#ciphered_text = cipher_suite.encrypt(b'SuperSecretpassword')
#with open('c:\savedfiles\mssqltip_bytes.bin', 'wb') as file_object:  file_object.write(ciphered_text)

#with open('c:\savedfiles\mssqltip_bytes.bin', 'rb') as file_object:
#    for line in file_object:
#        encryptedpwd = line
#print(encryptedpwd)


#Password encryption
#https://towardsdatascience.com/secure-password-handling-in-python-6b9f5747eca5
#https://www.mssqltips.com/sqlservertip/5173/encrypting-passwords-for-use-with-python-and-sql-server/
#https://www.pdq.com/blog/secure-password-with-powershell-encrypting-credentials-part-1/
#https://quabr.com/44194860/how-can-i-use-encrypted-secure-password-in-smtp-credentials
#https://www.makeuseof.com/encrypt-password-in-python-bcrypt/
	



def alert():
#Transfer email over ssl - LOOK AT THE BELOW URL
#https://devrescue.com/python-send-email-with-smtp-over-ssl/

	import smtplib #importing the module
	
	sender_add='sender_email@example.com' #storing the sender's mail id
	receiver_add='receiver_email@example.com' #storing the receiver's mail id
	password='Password' #storing the password to log in
	
	#creating the SMTP server object by giving SMPT server address and port number
	smtp_server=smtplib.SMTP("smtp.office365.com",587)
	smtp_server.ehlo() #setting the ESMTP protocol
	smtp_server.starttls() #setting up to TLS connection
	smtp_server.ehlo() #calling the ehlo() again as encryption happens on calling startttls()
	
	print('Sending email...Please wait amoment')
	smtp_server.login(sender_add,password) #logging into outlook email id
	
	#Message content
	msg_to_be_sent ='''
	Alert, Cybersecurity team!		
	Malicious scanner have detected suspicious behavior, require immediate action!!!!
	'''
	#sending the mail by specifying the from and to address and the message 
	smtp_server.sendmail(sender_add,receiver_add,msg_to_be_sent)
	
	print('Successfully the mail is sent') #priting a message on sending the mail
	
	smtp_server.quit()#terminating the server

#=============================MAIN SECTION=================================================

#need user input for pcap filename and output csv filename

timestr = time.strftime("%Y%m%d")

pcap_filename = input("Please input PCAP file: ")

output_filename = "output" + timestr + ".csv"


cmd = 'tshark -r' + pcap_filename + " -e frame -e ip.src -e ip.dst -T fields -e http.response_for.uri -e http.content_type > " + output_filename


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
	if isMalicious(file) == 1: # Setting to true for testing alert(). Change it before use
		alert()
	else:
		print("All Good!....For now >:)")
	


#Reference:
#https://pypi.org/project/virustotal-python/
#https://bobbyhadz.com/blog/python-attributeerror-list-object-has-no-attribute-encode

#Setting up Email
	#https://pythongeeks.org/send-email-using-python/
#Transfer email over ssl - LOOK AT THE BELOW URL
	#https://devrescue.com/python-send-email-with-smtp-over-ssl/
