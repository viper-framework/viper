import ast
import datetime
import json
import os

from viper.core.session import __sessions__
from .fe_auth import fe_auth_logout, fe_auth_login
from .fe_malware_objects import fe_submit_single_file_malware_objects_request, fe_submission_queue_size_request, \
    fe_submission_status_request, fe_submission_results_request


def calculate_threat_level(resp_id: str):
    """
    simple and naive approach to threat level calculation on a per alert basis
    :param resp_id: string containing valid json from a xml converted API response
    :return:
    """
    res_json = json.loads(resp_id[0])["alerts"]["ns2:alert"]
    threat_level = 3
    if str(res_json["@malicious"]) == 'yes':
        threat_level = 2
        if str(res_json["@severity"]) == 'majr':
            threat_level = 0
        else:
            threat_level = 1
    return threat_level


def generate_std_ioc(self, res_json: dict, threat_level: int):
    """
    returns a "standard" ioc object containing basic info, as well as hashes
    :param self:
    :param res_json: json dict containing the parsed API response
    :param threat_level: calculated threat level to add to misp event
    :return: dict
    """
    return {
        'info': str(self.args.misp_info) + '_' + str(res_json["ns2:explanation"]["ns2:malware-detected"]
        ["ns2:malware"]["@name"]),
        'date': str(datetime.datetime.now().date()),
        'threat_level': threat_level,
        'distribution': 0,
        'analysis': self.args.analysis,
        'sha256': str(res_json["ns2:explanation"]["ns2:malware-detected"]["ns2:malware"]["ns2:sha256"]),
        'md5': str(res_json["ns2:explanation"]["ns2:malware-detected"]["ns2:malware"]["ns2:md5sum"])
    }


def print_ioc_info(self, ioc: dict):
    """
    prints commands that add attributes to a MISP related event file
    :param self:
    :param ioc: object containing information about an ioc
    :return:
    """
    print('misp add sha1 ' + str(__sessions__.current.file.sha1) + ";")
    print('misp add sha256 ' + str(ioc.get("sha256")) + ";")
    print('misp add sha512 ' + str(__sessions__.current.file.sha512) + ";")
    print('misp add md5 ' + str(ioc.get("md5")) + ";")
    print('misp add mime-type ' + str(__sessions__.current.file.mime) + ";")
    print('misp add ssdeep ' + str(__sessions__.current.file.ssdeep) + ";")


def fe_upload(self):
    """
    Wrapper method which handles file upload to FireEye
    :param self:
    :return:
    """
    fe_auth_login(self)
    if self.api_tokens is not None:
        queue_size = fe_submission_queue_size_request(self)
        self.log('info', "Current Queue Size: " + str(queue_size))
        if queue_size < 5:
            json_response = fe_submit_single_file_malware_objects_request(self)
            if json_response is not None:
                for submission in json_response:
                    self.id_list.append(str(submission["ID"]))
        else:
            self.log('info', "Queue Size too long")
    else:
        self.log('error', "No API Tokens were supplied")
    fe_auth_logout(self)


def fe_fetch_results(self):
    """
    Wrapper method which handles the fetching of results gathered by FireEye
    :param self:
    :return:
    """
    fe_auth_login(self)
    if self.api_tokens is not None:
        all_done = fe_submission_status_request(self)
        if not all_done:
            self.log('info', 'Not all submissions are processed yet. Come back later')
        else:
            self.response = fe_submission_results_request(self)
            self.log('success', "You may now continue with one of the following commands: ")
            __sessions__.current.fireeye_response.extend(self.response)
            print("fireeye misp -create -analysis 0 -mi '<Some Misp Info>'")
            print("fireeye misp -update -analysis 1 -mi '<Some Misp Info>'")
    fe_auth_logout(self)


def update_misp_event(self):
    """
    Prints the basic commands one can use to update a related misp event
    :param self:
    :return:
    """
    ioc_list = []
    self.response = __sessions__.current.fireeye_response
    if self.response is not None:
        max_threat_lvl = 3
        for resp_id in self.response:
            res_json = json.loads(resp_id[0])["alerts"]["ns2:alert"]
            threat_level = calculate_threat_level(resp_id)
            if threat_level < max_threat_lvl:
                max_threat_lvl = threat_level
            ioc = generate_std_ioc(self, res_json, threat_level)
            ioc_list.append(ioc)
        self.log('success', 'You might want to continue with the following commands: ')
        for ioc in ioc_list:
            print_ioc_info(self, ioc)
        print('open -f ' + os.getcwd() + "/out.xml;")
        print('misp upload -e ' + str(__sessions__.current.misp_event.event.id) +
              ' -d 0 -c 3 -i FireEye_AX_Analysis_Report -a ' + str(ioc.get("analysis")) + ' -t ' +
              str(ioc.get("threat_level")) + ";")
        print('misp check_hashes;')


def create_misp_event_from_fe_results(self):
    """
    Prints the basic commands one can use to create a related misp event
    :param self:
    :return:
    """
    ioc_list = []
    self.response = __sessions__.current.fireeye_response
    if self.response is not None:
        max_threat_lvl = 3
        for resp_id in self.response:
            res_json = json.loads(resp_id[0])["alerts"]["ns2:alert"]
            threat_level = calculate_threat_level(resp_id)
            if threat_level < max_threat_lvl:
                max_threat_lvl = threat_level
            ioc = generate_std_ioc(self, res_json, threat_level)
            ioc_list.append(ioc)
        self.log('success', 'You might want to continue with the following commands: ')
        print('misp create_event -d 0 -t ' + str(max_threat_lvl) + ' -a 0 -i <MEANINGFUL_INFO>')
        for ioc in ioc_list:
            print_ioc_info(self, ioc)
        print('open -f ' + os.getcwd() + "/out.xml;")
        print('misp upload -d 0 -c 3 -i FireEye_AX_Analysis_Report -a 0 -t ' + str(ioc.get("threat_level")) + ";")
        print('misp check_hashes;')
