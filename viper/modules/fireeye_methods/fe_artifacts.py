import json
import traceback
import requests
import urllib3
from viper.core.config import __config__

cfg = __config__

fe_user = cfg.fireeye.username
fe_passwd = cfg.fireeye.password


def do_fe_artifact_request(obj: dict):
    """
    Wrapper function to asynchronize the GET Request associated with the Alert Request API Functionality
    :param obj: Dictionary consisting of (str:str) mappings for Appliance + Endpoint URL, API Token & Content-Type Information
    :return: the crafted requests.get method
    """
    return requests.get(obj.get("appliance_and_endpoint"),
                        headers={"X-FeApi-Token": obj.get("appliance_api_token"),
                                 "Content-Type": obj.get("content-type")},
                        proxies=cfg.fireeye.proxies,
                        verify=cfg.fireeye.verify,
                        cert=cfg.fireeye.cert)


def fe_artifacts_data_by_uuid(self, alert_uuid: str):
    """
    Logic to send, receive and evaluate FireEye Artifacts data by uuid
    :param self:
    :param alert_uuid: UUID associated with the desired alert
    :return:
    """
    current_method = "[Artifacts|DataByUuid] "
    for index, appliance in enumerate(self.active_appliances, start=1):
        current_appliance = " | [" + str(index) + "/" + str(len(self.active_appliances)) + "]"
        try:
            self.log('debug',
                     current_method + "Current API Token: " + self.api_tokens.get(str(appliance)) + current_appliance)
            r = do_fe_artifact_request({"appliance_and_endpoint": str(appliance) + "/artifacts/" + str(alert_uuid),
                                        "appliance_api_token": self.api_tokens.get(str(appliance)),
                                        "content-type": "application/xml"
                                        })
            self.log('debug',
                     current_method + "Request URL: " + str(appliance) + "/artifacts/" + str(
                         alert_uuid) + current_appliance)
            if r.status_code == 200:
                self.log('info', current_method + "Requesting artifacts data successful" + current_appliance)
                # TODO what should happen with the zip?
            elif r.status_code == 500:
                self.log('error', current_method + "Encountered a server error" + current_appliance)
                self.log('error', r.content.decode())
            elif r.status_code == 404:
                self.log('error', current_method + "Resource not found" + current_appliance)
            elif r.status_code == 405:
                self.log('error', current_method + "Method not allowed" + current_appliance)
            else:
                self.log('error', current_method + "Something unforeseen has happened: " + str(r.status_code) + "\n" +
                         str(r.text) + current_appliance)
        except urllib3.exceptions.MaxRetryError:
            self.log('error', "Maximum amount of retries has been used. Connection abort...")
            traceback.print_exc()
            return
        except requests.exceptions.ProxyError:
            self.log('error', "Issues with Proxy. Connection abort...")
            traceback.print_exc()
            return
        except Exception:
            self.log('error', "Unexpected error")
            traceback.print_exc()
            return


def fe_artifacts_data_by_id(self, alert_id: str, alert_type="malwareobject"):
    """
    Logic to send, receive and evaluate FireEye Artifacts data by id
    :param self:
    :param alert_id: ID associated with the desired alert
    :param alert_type: defaults to "malwareobjects" | no other option available so far
    :return:
    """
    current_method = "[Artifacts|DataById] "
    for index, appliance in enumerate(self.active_appliances, start=1):
        current_appliance = " | [" + str(index) + "/" + str(len(self.active_appliances)) + "]"
        try:
            self.log('debug', current_method + "Current API Token: " + self.api_tokens.get(str(appliance)) +
                     current_appliance)
            r = do_fe_artifact_request({"appliance_and_endpoint": str(appliance) + "/artifacts/" + alert_type +
                                                                  "/" + str(alert_id),
                                        "appliance_api_token": self.api_tokens.get(str(appliance)),
                                        "content-type": "application/xml"
                                        })
            if r.status_code == 200:
                self.log('info', current_method + "Requesting artifacts data successful" + current_appliance)
                # TODO what should happen with the zip?
            elif r.status_code == 500:
                self.log('error', current_method + "Encountered a server error" + current_appliance)
                self.log('error', r.content.decode())
            elif r.status_code == 404:
                self.log('error', current_method + "Resource not found" + current_appliance)
            elif r.status_code == 405:
                self.log('error', current_method + "Method not allowed" + current_appliance)
            else:
                self.log('error', current_method + "Something unforeseen has happened: " + str(r.status_code) + "\n" +
                         str(r.text) + current_appliance)
        except urllib3.exceptions.MaxRetryError:
            self.log('error', "Maximum amount of retries has been used. Connection abort...")
            traceback.print_exc()
            return
        except requests.exceptions.ProxyError:
            self.log('error', "Issues with Proxy. Connection abort...")
            traceback.print_exc()
            return
        except Exception:
            self.log('error', "Unexpected error")
            traceback.print_exc()
            return


def fe_artifacts_metadata_by_id(self, alert_id: str, alert_type="malwareobject"):
    """
    Logic to send, receive and evaluate FireEye Artifacts Metadata by id
    :param self:
    :param alert_id: ID associated with the desired alert
    :param alert_type: defaults to "malwareobjects" | no other option available so far
    :return:
    """
    current_method = "[Artifacts|MetadataById] "
    for index, appliance in enumerate(self.active_appliances, start=1):
        current_appliance = " | [" + str(index) + "/" + str(len(self.active_appliances)) + "]"
        try:
            self.log('debug', "Current API Token: " + self.api_tokens.get(str(appliance)))
            r = do_fe_artifact_request({"appliance_and_endpoint": str(appliance) + "/artifacts/" + alert_type + "/" +
                                                                  str(alert_id) + "/meta",
                                        "appliance_api_token": self.api_tokens.get(str(appliance)),
                                        "content-type": "application/json"
                                        })
            if r.status_code == 200:
                self.log('success', current_method + "Requesting artifacts data successful" + current_appliance)
                json_response = json.loads(r.text)
                header = ["Artifact Name", "Artifact Size", "Artifact Type"]
                rows = []
                for artifact in json_response["artifactsInfoList"]:
                    rows.append(
                        [
                            str(artifact["artifactName"]), str(artifact["artifactSize"]), str(artifact["artifactType"]),
                        ]
                    )
                self.log('table', dict(header=header, rows=rows))
            elif r.status_code == 500:
                self.log('error', current_method + "Encountered a server error" + current_appliance)
                self.log('error', r.content.decode())
            elif r.status_code == 404:
                self.log('error', current_method + "Resource not found" + current_appliance)
            elif r.status_code == 405:
                self.log('error', current_method + "Method not allowed" + current_appliance)
            else:
                self.log('error', current_method + "Something unforeseen has happened: " + str(r.status_code) + "\n" +
                         str(r.text) + current_appliance)
        except urllib3.exceptions.MaxRetryError:
            self.log('error', "Maximum amount of retries has been used. Connection abort...")
            traceback.print_exc()
            return
        except requests.exceptions.ProxyError:
            self.log('error', "Issues with Proxy. Connection abort...")
            traceback.print_exc()
            return
        except Exception:
            self.log('error', "Unexpected error")
            traceback.print_exc()
            return


def fe_artifacts_metadata_by_uuid(self, alert_uuid: str):
    """
    Logic to send, receive and evaluate FireEye Artifacts Metadata by uuid
    :param self:
    :param alert_uuid: UUID associated with the desired alert
    :return:
    """
    current_method = "[Artifacts|MetadataByUuid] "
    for index, appliance in enumerate(self.active_appliances, start=1):
        current_appliance = " | [" + str(index) + "/" + str(len(self.active_appliances)) + "]"
        try:
            self.log('debug', "Current API Token: " + self.api_tokens.get(str(appliance)))
            r = do_fe_artifact_request({"appliance_and_endpoint": str(appliance) + "/artifacts/" + str(alert_uuid) +
                                                                  "/meta",
                                        "appliance_api_token": self.api_tokens.get(str(appliance)),
                                        "content-type": "application/json"
                                        })
            if r.status_code == 200:
                self.log('success', current_method + "Requesting artifacts data successful" + current_appliance)
                json_response = json.loads(r.text)
                header = ["Artifact Name", "Artifact Size", "Artifact Type"]
                rows = []
                for artifact in json_response["artifactsInfoList"]:
                    rows.append(
                        [
                            str(artifact["artifactName"]), str(artifact["artifactSize"]), str(artifact["artifactType"]),
                        ]
                    )
                self.log('table', dict(header=header, rows=rows))
            elif r.status_code == 500:
                self.log('error', current_method + "Encountered a server error" + current_appliance)
                self.log('error', r.content.decode())
            elif r.status_code == 404:
                self.log('error', current_method + "Resource not found" + current_appliance)
            elif r.status_code == 405:
                self.log('error', current_method + "Method not allowed" + current_appliance)
            else:
                self.log('error', current_method + "Something unforeseen has happened: " + str(r.status_code) + "\n" +
                         str(r.text) + current_appliance)
        except urllib3.exceptions.MaxRetryError:
            self.log('error', "Maximum amount of retries has been used. Connection abort...")
            traceback.print_exc()
            return
        except requests.exceptions.ProxyError:
            self.log('error', "Issues with Proxy. Connection abort...")
            traceback.print_exc()
            return
        except Exception:
            self.log('error', "Unexpected error")
            traceback.print_exc()
            return
