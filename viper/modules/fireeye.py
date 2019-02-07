import argparse
import logging
import textwrap

from viper.core.config import __config__
from viper.common.abstracts import Module
from viper.core.session import __sessions__

log = logging.getLogger('viper')
cfg = __config__

client_token = cfg.fireeye.client_token
fe_user = cfg.fireeye.username
fe_passwd = cfg.fireeye.password
feAxIp = cfg.fireeye.ax
feHxIp = cfg.fireeye.hx
feNxIp = cfg.fireeye.nx
feExIp = cfg.fireeye.ex


class FireEye(Module):
    from .fireeye_methods import fe_upload, fe_fetch_results
    from .fireeye_methods import create_misp_event_from_fe_results, update_misp_event

    cmd = 'fireeye'
    description = 'The FireEye module adds an API Wrapper to Viper Berus'
    authors = ['frennkie <mail@rhab.de>']

    def __init__(self):
        super(FireEye, self).__init__()
        subparsers = self.parser.add_subparsers(dest='subname')
        self.parser.add_argument('-ax',
                                 action='store_true',
                                 help='Request FireEye AX')
        self.parser.add_argument('-ex',
                                 action='store_true',
                                 help='Request FireEye EX')
        self.parser.add_argument('-hx',
                                 action='store_true',
                                 help='Request FireEye HX')
        self.parser.add_argument('-nx',
                                 action='store_true',
                                 help='Request FireEye NX')
        self.parser.add_argument('-all',
                                 action='store_true',
                                 help='Request all possible FireEye Instances')
        parser_samples = subparsers.add_parser('sample', help='Upload or Fetch Samples from FireEye',
                                               formatter_class=argparse.RawDescriptionHelpFormatter,
                                               description=textwrap.dedent('''
                                                              upload: Send sample to FireEye
                                                              fetch: Fetch sample from FireEye
                                                            '''))
        parser_samples.add_argument('-upload',
                                    '-u',
                                    dest='upload',
                                    action='store_true',
                                    help='Send sample to FireEye')
        parser_samples.add_argument('-fetch',
                                    '-f',
                                    metavar='fetch',
                                    type=int,
                                    nargs='+',
                                    help='Fetch sample results from FireEye')
        parser_misp = subparsers.add_parser('misp', help='FireEye & MISP Link',
                                            formatter_class=argparse.RawDescriptionHelpFormatter,
                                            description=textwrap.dedent('''
                                                      -a : Analysis levels:
                                                        * 0: Initial
                                                        * 1: Ongoing
                                                        * 2: Completed
                                                      -mi : Misp Info: Add meaningful MISP Info to your Event

                                                    '''))
        parser_misp.add_argument('-analysis',
                                 '-a',
                                 metavar='analysis',
                                 type=int,
                                 nargs=1,
                                 help='Setting the analysis level of a MISP item')
        parser_misp.add_argument('-misp_info',
                                 '-mi',
                                 metavar='misp_info',
                                 type=str,
                                 nargs='+',
                                 help='Setting the MISP Info of a MISP item')
        parser_misp.add_argument('-create',
                                 '-c',
                                 dest='create',
                                 action='store_true',
                                 help='Create MISP Event from FireEye Result')
        parser_misp.add_argument('-update',
                                 '-u',
                                 dest='update',
                                 action='store_true',
                                 help='Update current MISP Event from FireEye Result')
        self.active_appliances = []
        self.api_tokens = {}
        self.id_list = []
        self.response = []

    def run(self):
        super(FireEye, self).run()
        if self.args is None:
            self.log('error', "Additional Arguments required")
            return
        if self.args.subname not in ["misp", "sample"] and self.args is None:
            self.log('error', "No valid arguments detected")
            return
        else:
            if hasattr(self.args, "subname") and self.args.subname in ["misp", "sample"]:
                if not hasattr(__sessions__.current, 'file'):
                    self.log('error', "No File open")
                    return
                if self.id_list is []:
                    self.log('error', "No IDs pending")
                    return
        if self.args.all:
            # TODO Ping for online appliances || filter out placeholder appliances
            self.active_appliances.append("https://" + str(feAxIp) + "/wsapis/v2.0.0")
            self.active_appliances.append("https://" + str(feNxIp) + "/wsapis/v2.0.0")
            self.active_appliances.append("https://" + str(feHxIp) + "/wsapis/v2.0.0")
            self.active_appliances.append("https://" + str(feExIp) + "/wsapis/v2.0.0")
        else:
            if self.args.ax:
                self.active_appliances.append("https://" + str(feAxIp) + "/wsapis/v2.0.0")
            if self.args.ex:
                self.active_appliances.append("https://" + str(feExIp) + "/wsapis/v2.0.0")
            if self.args.hx:
                self.active_appliances.append("https://" + str(feHxIp) + "/wsapis/v2.0.0")
            if self.args.nx:
                self.active_appliances.append("https://" + str(feNxIp) + "/wsapis/v2.0.0")
        if self.args.subname in ["sample"]:
            if len(self.active_appliances) < 1:
                self.log('error', "At least one FireEye Appliance has to be queried")
                return
            for index, appliance in enumerate(self.active_appliances, start=1):
                self.log('info', "Active Appliance: " + appliance +
                         " | [" + str(index) + "/" + str(len(self.active_appliances)) + "]")
            if len(self.active_appliances) > 0:
                if self.args.upload:
                    self.fe_upload()
                elif self.args.fetch:
                    self.id_list.extend(self.args.fetch)
                    if len(self.id_list) > 0:
                        self.fe_fetch_results()
                    else:
                        self.log('error', "Local List of Sample IDs is empty")
                else:
                    self.log('error', "No valid argument recognized: " + str(self.args))
                    return
            else:
                self.log('error', "At least one FireEye Appliance has to be queried")
                return
        if self.args.subname in ["misp"]:
            if not self.args.analysis and not self.args.misp_info:
                self.log('error', "Analysis Level & MISP Info required")
                return
            if self.args.create:
                self.create_misp_event_from_fe_results()
            if self.args.update:
                if __sessions__.is_attached_misp():
                    self.update_misp_event()
                else:
                    self.log('error', "Open MISP Session required")
                    return
