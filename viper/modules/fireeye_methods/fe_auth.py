import traceback
import requests
import urllib3
from viper.core.config import __config__

cfg = __config__

client_token = cfg.fireeye.client_token
fe_user = cfg.fireeye.username
fe_passwd = cfg.fireeye.password


def fe_auth_login(self):
    """
    Login / Authenticate yourself with the FireEye API and obtain your API Session Tokens for all queried appliances
    :param self:
    :return: list of strings containing associated API Tokens or None if Auth is tried in offline mode
    """
    current_method = "[Auth|Login] "
    for index, appliance in enumerate(self.active_appliances, start=1):
        current_appliance = " | [" + str(index) + "/" + str(len(self.active_appliances)) + "]"
        try:
            r = do_fe_auth_login(appliance)
            if r.status_code == 200:
                self.log('info', "Authentication against FireEye API was successful | [" +
                         str(index) + "/" + str(len(self.active_appliances)) + "]")
                api_token = r.headers.get("X-FeApi-Token")
                self.api_tokens.update({str(appliance): str(api_token)})
                self.log('debug', current_method + "API Token: " + str(
                    self.api_tokens or "") + current_appliance)
                self.log('debug', current_method + "Client Token: " + str(r.headers.get("X-FeClient-Token") or "") +
                         current_appliance)
            elif r.status_code == 401:
                self.log('error',
                         current_method +
                         "Authentication against FireEye API was not successful due to bad credentials" +
                         current_appliance)
                self.log('debug', r.text)
            elif r.status_code == 503:
                self.log('error', current_method + "API is turned off. Authentication therefore failed" +
                         current_appliance)
                self.log('debug', r.text)
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


def do_fe_auth_login(appliance: str):
    """
    Auth login wrapper method for requests.post
    :param appliance: appliance URL which shall be used to authenticate against
    :return: crafted requests.post
    """
    return requests.post(appliance + "/auth/login",
                         auth=(fe_user, fe_passwd),
                         headers={"X-FeClient-Token": client_token},
                         proxies=cfg.fireeye.proxies,
                         verify=cfg.fireeye.verify,
                         cert=cfg.fireeye.cert)


def do_fe_auth_logout(obj: dict):
    """
    Auth Logout Wrapper Method for requests.post
    :param obj: dict with (str:str) mappings for appliances and API Tokens
    :return: crafted requests.post
    """
    return requests.post(str(obj.get("appliance")) + "/auth/logout",
                         headers={"X-FeApi-Token": obj.get("api_token"),
                                  "X-FeClient-Token": client_token},
                         proxies=cfg.fireeye.proxies,
                         verify=cfg.fireeye.verify,
                         cert=cfg.fireeye.cert)


def fe_auth_logout(self):
    """
    Logout at the FireEye Appliances and end your session
    :param self:
    :return:
    """
    current_method = "[Auth|Logout] "
    for index, appliance in enumerate(self.active_appliances, start=1):
        current_appliance = " | [" + str(index) + "/" + str(len(self.active_appliances)) + "]"
        try:
            r = do_fe_auth_logout({"appliance": appliance,
                                   "api_token": self.api_tokens.get(str(appliance))})
            if r.status_code == 204:
                self.log('info', current_method + "Logout successful" + current_appliance)
                self.log('debug',
                         current_method + "API Token: " + self.api_tokens.get(str(appliance)) + current_appliance)
                self.log('debug', current_method + "Client Token: " + str(r.headers.get("X-FeClient-Token") or "") +
                         current_appliance)
            elif r.status_code == 304:
                self.log('error', current_method + "Session token missing" + current_appliance)
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
