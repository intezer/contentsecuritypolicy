from flask import Flask, request,jsonify
from flask_restful import Api
from flask_httpauth import HTTPBasicAuth
import logging.config
from postToSplunk import log_to_hec
from getTokens import get_secret
import json

logger = logging.getLogger('csp-listener')
logFileName = '/var/log/csp-listener.log'
logging.config.dictConfig({
    'version': 1,'disable_existing_loggers': False,
    'formatters': {'default': {'format': '%(asctime)s %(levelname)s %(name)s %(message)s'},},
    'handlers': {'file':{'class':'logging.handlers.RotatingFileHandler',
            'maxBytes':50000,
            'backupCount':5,
            'level':'INFO',
            'formatter': 'default',
            'filename': logFileName,
            'mode':'a'},},
    'root': {
        'handlers': ['file'],
        'level': 'INFO',
    },
})

app = Flask(__name__)
api = Api(app)
auth = HTTPBasicAuth()

def validate_policy_version(policy_version):
    if policy_version.isnumeric():
        logger.info("Policy version validated")
        return True
    else:
        logger.info(f"Policy version validation failed. returned {policy_version}. Expected int")
        return False


@app.route("/cspgate/<token>/<policyversion>", methods = ['POST','GET'])
def csp_gate(policyversion):

    # Validate policy_version:
    isvalidate = validate_policy_version(policyversion)
    if isvalidate:

        data = request.data.decode('utf-8')
        if data:
            logger.info(data)
            splunk_hec_response = get_secret('secret_name')
            splunk_hec = json.loads(splunk_hec_response)['keyname']
            if splunk_hec:
                log_to_hec(data,splunk_hec,"_json",policyversion)
                return f"Identified CSP violation {data}. Policy version: {policyversion}"
            else:
                logger.error('Could not retrieve hec token from secret manager')
                return jsonify(message='Could not complete task'), 400
        else:
            return jsonify(message='Nothing to process'), 200
    else:
        return jsonify(message='Could not complete task'), 400

if __name__ == '__main__':
    app.run()
