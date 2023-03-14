"""
Esse script analisa a saída do Open Policy Agent e decide se aprova o MR ou solicita aprovação manual
via Microsoft Teams. 
"""
import requests
import os
import json
import pymsteams
from enum import Enum

gl_token = os.environ.get('ATLANTIS_GITLAB_TOKEN')                                             
gl_pull_num = os.environ.get('PULL_NUM')
gl_pull_author = os.environ.get('PULL_AUTHOR')                                                                    
gl_repo_owner = os.environ.get('BASE_REPO_OWNER')
gl_url_encoded = os.environ.get('BASE_REPO_OWNER').replace('/', '%2F')                                                 
gl_repo_name = os.environ.get('BASE_REPO_NAME') 
gl_pull_url = f'https://gitlab.com/api/v4/projects/{gl_url_encoded}%2F{gl_repo_name}/merge_requests/{gl_pull_num}'
dir = f'/atlantis-data/repos/{gl_repo_owner}/{gl_repo_name}/{gl_pull_num}/conftest'                                                         
#dir = '/tmp/status_json2'
teams_webhook =  os.environ.get('TEAMS_WEBHOOK') 
myTeamsMessage = pymsteams.connectorcard(teams_webhook)

class Approval_flow(Enum):
    AUTOMATIC_APPROVAL = 1
    MANUAL_APPROVAL = 0
    NO_INFORMATIOM = -1


def get_status():
    res = requests.get(gl_pull_url + '/approval_state', headers={'PRIVATE-TOKEN': gl_token})
    if res.status_code > 399:
        raise ValueError('Error checking MR status!')
    res = res.json()
    approval = next((True for rule in res['rules'] if rule['approved_by']), False)
    if not approval:
        security_faults = Approval_flow.NO_INFORMATIOM
        cloud_faults = Approval_flow.NO_INFORMATIOM
        for filename in os.listdir(dir):
            with open(os.path.join(dir,filename), 'r') as file:
                data = json.load(file)
                for i in data:
                    if i.get('failures'):
                        return('There is a failed policy!')
                    if i.get('warnings') and i.get('namespace') == 'iam':
                        security_faults = Approval_flow.MANUAL_APPROVAL
                    elif i.get('successes') and i.get('namespace') == 'iam' and security_faults == Approval_flow.NO_INFORMATIOM:
                        security_faults = Approval_flow.AUTOMATIC_APPROVAL
                    elif i.get('warnings') and i.get('namespace') == 'terraform2_0':
                        cloud_faults = Approval_flow.MANUAL_APPROVAL
                    elif i.get('successes') and i.get('namespace') == 'terraform2_0' and cloud_faults == Approval_flow.NO_INFORMATIOM:
                        cloud_faults = Approval_flow.AUTOMATIC_APPROVAL

        if security_faults != Approval_flow.NO_INFORMATIOM or cloud_faults != Approval_flow.NO_INFORMATIOM:
            if security_faults == Approval_flow.AUTOMATIC_APPROVAL or cloud_faults == Approval_flow.AUTOMATIC_APPROVAL:
                response = requests.post(gl_pull_url + '/approve', headers={'PRIVATE-TOKEN': gl_token})
                if not response.ok:
                    requests.post(gl_pull_url + '/notes', headers={'PRIVATE-TOKEN': gl_token}, data={'body': f"Automatic approval error. Request manual approval! {response.json()}"})
                else:
                    requests.post(gl_pull_url + '/notes', headers={'PRIVATE-TOKEN': gl_token}, data={'body': 'Automatically approved!'})
            elif security_faults == Approval_flow.MANUAL_APPROVAL:
                requests.post(gl_pull_url + '/notes', headers={'PRIVATE-TOKEN': gl_token}, data={'body': 'Request manual approval!'})
                myTeamsMessage.title(f'{gl_repo_owner} / {gl_repo_name}')
                myTeamsMessage.text(f'<h1> User {gl_pull_author} awaiting approval on Merge Request !{gl_pull_num} </h1>')
                myTeamsMessage.addLinkButton("Click here to access", f'https://gitlab.com/{gl_repo_owner}/{gl_repo_name}/-/merge_requests/{gl_pull_num}')
                myTeamsMessage.send()
            elif cloud_faults == Approval_flow.MANUAL_APPROVAL:
                requests.post(gl_pull_url + '/notes', headers={'PRIVATE-TOKEN': gl_token}, data={'body': 'Request manual approval!'})
        else:
            return(f'Something went wrong!')

    else:
        return('MR has already been approved!')

       
if __name__ == '__main__':
    print(get_status())
