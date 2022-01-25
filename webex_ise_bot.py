import os
from webexteamsbot import TeamsBot
import requests
import xml.etree.ElementTree as ET
import urllib3
import json
import re
import xmltodict
import datetime
import base64
from netmiko import Netmiko



urllib3.disable_warnings()


# Retrieve required details from environment variables
bot_email = os.getenv("TEAMS_BOT_EMAIL")
teams_token = os.getenv("TEAMS_BOT_TOKEN")
bot_url = os.getenv("TEAMS_BOT_URL")
bot_app_name = os.getenv("TEAMS_BOT_APP_NAME")

# Create a Bot Object
bot = TeamsBot(
    bot_app_name,
    teams_bot_token=teams_token,
    teams_bot_url=bot_url,
    teams_bot_email=bot_email,
)

bot.remove_command('/echo')
bot.set_help_message('Hi! Mention me in this space followed by one of these commands to execute them.\n')


## pull the MAC address from the message to use in the functions
def extract_message(command, text):
    cmd_loc = text.find(command)
    message = text[1 + cmd_loc + len(command):]
    return message

def readme(command):
    return '* @ the bot and type the command with a single space.\n* Use anotherc single space and provide a MAC address and send the message with no trailing spaces. \n* MAC format should be AA:BB:CC:00:11:22 upper or lower case.'



mnt_headers = {'authorization': 'Basic (bas64 user/pass)'}
ers_xml_headers = {'authorization': 'Basic (base64 user/pass)', 'accept': 'application/xml', 'content-type': 'application/xml'}
ers_json_headers= {'authorization': 'Basic (base64 user/pass)', 'accept': 'application/json', 'content-type': 'application/json'}

reason_dict = {'1251': 'Failed SSL/TLS handshake - Check the icca and/or 512P certificate',
               '15039': 'Rejected per authorization profile - Check the user AD account and confirm the device is in the correct group',
               '12321': 'Client rejected the ISE local-certificate - Check the icca and/or 512P certificate',
               '22056': 'Subject not found in identity stores - Check to see if the device is in Mosyle or AD or if the username they\'re trying to authenticate with is valid.'}


def auth_status(mac_add):
    try:
        ## GET THE MAC ADDRESS FROM THE COMMAND
        mac = extract_message('/authcheck', mac_add.text)

        ## USE THE AUTHSTATUS API CALL TO GET THE USERNAME, AUTH STATUS, AND REASON FOR FAILURE IF APPLICABLE
        authcheck_url = 'https://(ISE MNT NODE)/admin/API/mnt/AuthStatus/MACAddress/' + mac + '/0/0/All'
        response = requests.request('GET', authcheck_url, headers=mnt_headers, verify=False)
        root = ET.fromstring(response.text)

        for user in root.iter('user_name'):
            usrname = (user.text)
        
        for passed in root.iter('passed'):
            if passed.text == 'true':
                auth_status = 'Authentication Passed'
                reason = 'N/A'

        for failed in root.iter('failed'):
            if failed.text == 'true':
                auth_status = 'AUTHENTICATION FAILED'
        
                for failure in root.iter('failure_reason'):
                    reason = failure.text
                
                rcode = re.search(r'(\d+)', reason).group(1)
                print(rcode)
                
        try:
            reason = reason_dict[rcode]
            print(reason)
        except Exception as e:
            print(e)
            pass

                           
        ## GET THE ENDPOINT GROUPID
        ers_endpoint_url = 'https://(ISE NODE):9060/ers/config/endpoint/name/' + mac
        response = requests.request('GET', ers_endpoint_url, headers=ers_xml_headers, verify=False)
        root = ET.fromstring(response.text)

        for groupid in root.iter('groupId'):
            group_id = (groupid.text)

        ## GET THE ENDPOINT GROUP NAME
        ers_endpointgroup_url = 'https://(ISE NODE):9060/ers/config/endpointgroup/' + group_id
        response = requests.request('GET', ers_endpointgroup_url, headers=ers_json_headers, verify=False)
        jdict = json.loads(response.text)
        mo_group = (jdict['EndPointGroup']['name'])

        ## BUILD RETURN MESSAGE
        message = f'* **_{auth_status}_** \n' + f'* **Provided username:** {usrname} \n' + f'* **Device group:** {mo_group} \n' + f'* **Reason for failure:** {reason}'

        

        return message

    except Exception as e:
       return f"""Sorry, either the command input was not in the correct format, an error occured in the program, or I could not find any information on the requested endpoint."""

def last_connection(mac_add):
    try:
        mac = extract_message('/last_connection', mac_add.text)
        url = 'https://(ISE MNT NODE)/admin/API/mnt/AuthStatus/MACAddress/' + mac + '/0/1/All'
        headers = {'authorization': 'Basic (base64 user/pass)'}
        response = requests.request('GET', url, headers=headers, verify=False)

        root = ET.fromstring(response.text)

        for timestamp in root.iter('acs_timestamp'):
            auth_time = (timestamp.text)
        
        ## PULL TIMESTAMP INFO FROM XML RESPONSE AND CONVERT IT TO EPOCH TIME IN MILLISECONDS
        a = re.search (r'(\d+)-(\d+)-(\d+)T(\d+):(\d+):(\d+).', auth_time)
        y = int(a.group(1))
        m = int(a.group(2))
        d = int(a.group(3))
        h = int(a.group(4))
        mi = int(a.group(5))
        s = int(a.group(6))
        time_stamp = datetime.datetime(y, m, d, h, mi, s)
        epoch = str(time_stamp.timestamp())[:-2] + '000'
        
        ##BUILD TIME INFO FOR RETURN MESSAGE
        sdate = time_stamp.strftime('%B %d %Y at %I:%M%P')

        ## GENERATE API TOKEN
        url = 'https://(DNAC NODE)/dna/system/api/v1/auth/token'
        headers = {'authorization': 'Basic (base64 user/pass)', 'accept': 'application/json', 'content-type': 'application/json'}
        t_response = requests.request('POST', url, headers=headers, verify=False)
        token_dict = json.loads(t_response.text)
        token = token_dict['Token']

        ## API CALL TO GET AP NAME
        url2 = 'https://(DNAC NODE)/dna/intent/api/v1/client-detail?timestamp=' + epoch + '&macAddress=' + mac
        headers2 = {'content-type': 'application/json', 'accept': 'application/json', 'X-Auth-Token': f'{token}'}
        response2 = json.loads(requests.request('GET', url2, headers=headers2, verify=False).text)

        try:
            ##GRAB AP INFO FROM JSON RESPONSE AND BUILD RETURN MESSAGE
            ap = (response2['detail']['clientConnection'])
            return('Device ' + mac + ' was last connected to the access point ' + '**' + ap + '**' + ' on ' + sdate)

        except:
            return('An error occured when locating the AP information. Please report to Trevor and provide the MAC Address used.')

    except Exception as e:
        return('I could not find any information for device ' + mac + ' within the last ten days. Check the MAC or reach out to find devices offline more than ten days.')

def locate_wired(mac_add):
    try:
        mac = extract_message('locate_wired', mac_add.text)
        url = 'https://(ISE MNT NODE)/admin/API/mnt/AuthStatus/MACAddress/' + mac + '/432000/1/All'
        headers = {'authorization': 'Basic (base64 user/pass'}
        response = requests.request('GET', url, headers=headers, verify=False)

        root = ET.fromstring(response.text)

        ##find which IDF device was connected to
        for x in root.iter('network_device_name'):
            switch = (x.text) + '.wan'

        ##find the switchport device was connected to
        for y in root.iter('nas_port_id'):
            port = (y.text)

        ##grab building name device was in
        for z in root.iter('location'):
            location = (z.text).replace('All Locations#', '').replace('_', ' ')


        basepass = '(base64 password)'
        password = str(base64.b64decode(basepass).decode('ascii'))
        print(type(password))

        ##ssh to switch 
        try:
            net_conn = Netmiko(host=switch, username='(USERNAME)',
                            password=password, device_type='cisco_ios')
            
            output = net_conn.send_command('show interface ' + port, use_textfsm=True)
            description = (output[0]['description'])
            
            
            
        except:
            return('I found a last connection, but I ran into an error while locating the port description. Please submit this error and MAC address to Trevor')
    
        return(f'Device {mac} was last seen connected to port {description} at {location}')
    except:
        return(f'I could not find any information for {mac} in the past ten days. Please check that the MAC address is correct or submit a ticket to NIS for historical information prior to ten days.')


# Add new commands to the box.
bot.add_command("/authcheck", "Check authorization status of an endpoint by MAC.", auth_status)
bot.add_command("/last_connection", "See which AP a device was last connected to (up to ten days ago)", last_connection)
bot.add_command("/readme", "simple instructions on how to use the bot", readme)
bot.add_command("/locate_wired", "See which port a wired device was last connected to (up to ten days ago", locate_wired)

if __name__ == "__main__":
    # Run Bot
    bot.run(host="0.0.0.0", port=5000)