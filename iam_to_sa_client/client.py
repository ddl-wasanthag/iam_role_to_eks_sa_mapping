import requests
import os
import time
from jproperties import Properties
import logging
import traceback

logger = logging.getLogger("iamroletosamapping-client")
lvl: str = logging.getLevelName(os.environ.get("LOG_LEVEL", "DEBUG"))
logging.basicConfig(
    level=lvl,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
print(lvl)
if __name__ == "__main__":
    #os.environ['ROOT_PATH'] = os.path.join(os.environ['PYTHONPATH'], 'root')
    #os.environ['AWS_CONFIG_FILE'] = '/var/run/.aws/config'
    #os.environ['AWS_WEB_IDENTITY_TOKEN_FILE'] =  '/var/run/secrets/eks.amazonaws.com/serviceaccount/token'
    #os.environ['IAM_SA_MAPPING_ENDPOINT'] = 'http://iam-sa-mapping-svc.domino-platform/map_iam_role_to_pod_sa'
    #os.environ['POD_INFO_PATH'] = '/var/run/podinfo/labels'

    root = os.environ.get('ROOT_PATH','')
    aws_config_file = root + os.environ['AWS_CONFIG_FILE']
    domino_token_file = root + os.environ['DOMINO_TOKEN_FILE']
    aws_web_identity_token_file = root + os.environ['AWS_WEB_IDENTITY_TOKEN_FILE']
    service_endpoint = os.environ['IAM_SA_MAPPING_ENDPOINT']
    pod_info = root + os.environ['POD_INFO_PATH']

    configs = Properties()

    logger.debug(aws_config_file)
    logger.debug(aws_web_identity_token_file)
    logger.debug(service_endpoint)


    success = False
    while not success:
        try:
            with open(pod_info, "rb") as f:
                # Writing data to a file
                configs.load(f)
            logger.debug(domino_token_file)
            logger.debug('Read domino token file')
            with open(domino_token_file, "r") as f:
                # Writing data to a file
                token = f.read()

            data = {
                "run_id": configs.get('app.kubernetes.io/name')
            }
            headers = {"Content-Type": "application/json",
                       "Authorization": "Bearer " + token
                       }

            resp = requests.post(service_endpoint, headers=headers, json=data)
            # Writing to file
            logger.debug(resp.status_code)
            if(resp.status_code==200):
                with open(os.environ['AWS_CONFIG_FILE'], "w") as f:
                    # Writing data to a file
                    f.write(resp.content.decode())

                    if(resp.status_code==200):
                        success = True
        except:
            # printing stack trace
            traceback.print_exc()
        logger.debug('Sleeping for 15 seconds')
        time.sleep(15)
        #If fails, retry every 30 seconds
    while(True):
        logger.debug('Wait forever by waking up every 5 mins and then going back to sleep')
        time.sleep(300)
