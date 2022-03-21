import time
import socket
import requests
import json

import logging.handlers

SPLUNKINDEX = "csp"
logger = logging.getLogger('csp-listener')

def log_to_hec(content, AUTH_TOKEN, SOURCETYPE, policyversion):

    logger.info(f"Logging {SOURCETYPE} events to splunk")
    eventtime = time.time()
    dict = json.loads(content)
    dict['policyVersion'] = policyversion
    send_to_splunk(AUTH_TOKEN, dict, eventtime, SOURCETYPE)

def send_to_splunk(AUTH_TOKEN, dict, eventtime, SOURCETYPE):
    response_json = ''
    splunk_session = requests.Session()
    try:
        hostname = socket.gethostname()
        post_data = {"host": hostname}

        post_data["time"] = eventtime
        post_data["sourcetype"] = SOURCETYPE
        post_data["index"] = SPLUNKINDEX
        post_data["event"] = dict

        request_url = "https://<yourinstance>/services/collector"

        # Encode data in JSON utf-8 format
        post_data_json = json.dumps(post_data).encode('utf8')

        # Create auth header
        auth_header = "Splunk %s" % AUTH_TOKEN
        headers = {'Authorization': auth_header}

        splunk_session.headers.update(headers)

        response = splunk_session.post(request_url, data=post_data_json)

        try:
            response_json = json.loads (response.content.decode ('utf-8'))
            if "text" in response_json:
                if response_json["text"] == "Success":
                    post_success = True
                else:
                    post_success = False
        except:
            post_success = False

        if post_success == True:
            # Event was recieved successfully
            pass
        else:
            # Event returned an error
            logger.exception()

    except Exception:
        # Network or connection error
        post_success = False
        logger.exception()
