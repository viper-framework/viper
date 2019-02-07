import json
import traceback
import requests
import urllib3
from viper.core.config import __config__

cfg = __config__
cfg.parse_http_client(cfg.fireeye)

fe_user = cfg.fireeye.username
fe_passwd = cfg.fireeye.password


def do_fe_alert_request(obj: dict):
    """
    Wrapper function to asynchronize the GET Request associated with the Alert Request API Functionality
    :param obj: Dictionary consisting of (str:str) mappings for Appliance + Endpoint URL & API Token Information
    :return: the crafted requests.get method
    """
    return requests.get(obj.get("appliance_and_endpoint"),
                        headers={"X-FeApi-Token": obj.get("appliance_api_token"),
                                 # "X-FeClient-Token": client_token,
                                 "Accept": "application/json"},
                        proxies=cfg.fireeye.proxies,
                        verify=cfg.fireeye.verify,
                        cert=cfg.fireeye.cert)


# **kwargs according to documentation
def fe_alerts_request(self, **kwargs: str):
    """
    Logic to send, receive and evaluate FireEye Alert Requests and parse the received JSON and visualize it in a table
    :param self:
    :param kwargs: According to documentation: additional parameters in string format
    :return:
    """
    current_method = "[Alerts|Request] "
    for index, appliance in enumerate(self.active_appliances, start=1):
        current_appliance = " | [" + str(index) + "/" + str(len(self.active_appliances)) + "]"
        try:
            self.log('debug', current_method + "Current API Token: " + self.api_tokens.get(str(appliance)) +
                     current_appliance)
            if len(kwargs) == 0:
                r = do_fe_alert_request({"appliance_and_endpoint": str(appliance) + "/alerts?",
                                         "appliance_api_token": self.api_tokens.get(str(appliance))})
            else:
                parameterstring = ""
                for key, value in kwargs.iteritems():
                    parameterstring += "%s=%s" % (key, value)
                r = do_fe_alert_request({"appliance_and_endpoint": str(appliance) + "/alerts?" + parameterstring,
                                         "appliance_api_token": self.api_tokens.get(str(appliance))})
            if r.status_code == 200:
                self.log('info', current_method + "Requesting alerts successful" + current_appliance)
                json_response = json.loads(r.text)
                self.log('success', "General Response Info:" +
                         "\nAppliance: " + str(json_response["appliance"]) +
                         "\nVersion: " + str(json_response["version"]) +
                         "\nMessage: " + str(json_response["msg"]) +
                         "\nAlert Count: " + str(json_response["alertsCount"]))
                header = ["Malware Name", "SHA256", "MD5", "Source", "Alert URL", "Action", "Occurred",
                          "Destination - MAC", "Appliance ID", "ID", "Name", "Severity", "UUID", "Product",
                          "VLAN", "Malicious"]
                rows = []
                for alert in json_response["alert"]:
                    rows.append(
                        [
                            str(json.loads(
                                str(alert["explanation"]["malwareDetected"]["malware"][0]).replace("\'", "\"")
                            )["name"]),
                            str(json.loads(
                                str(alert["explanation"]["malwareDetected"]["malware"][0]).replace("\'", "\"")
                            )["sha256"]),
                            str(json.loads(
                                str(alert["explanation"]["malwareDetected"]["malware"][0]).replace("\'", "\"")
                            )["md5Sum"]),
                            str(alert["src"]), str(alert["alertUrl"]),
                            str(alert["action"]), str(alert["occurred"]),
                            str(json.loads(str(alert["dst"]).replace("\'", "\""))["mac"]),
                            str(alert["applianceId"]), str(alert["id"]), str(alert["name"]),
                            str(alert["severity"]), str(alert["uuid"]), str(alert["product"]),
                            str(alert["vlan"]), str(alert["malicious"])
                        ]
                    )
                    # TODO maybe further or more generalized JSON parsing
                self.log('table', dict(header=header, rows=rows))
            elif r.status_code == 400:
                self.log('error', current_method +
                         "Filter values for alert request were invalid" + current_appliance)
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
