# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.


def version(self):
    if self.offline_mode:
        self.log('error', 'Offline mode, unable to check versions')
        return
    api_ok = True

    api_version = self.misp.get_api_version()
    self.log('info', 'The version of your MISP API is: {}'.format(api_version['version']))
    api_version_master = self.misp.get_api_version_master()
    if self._has_error_message(api_version_master):
        api_ok = False
    else:
        self.log('info', 'The version of MISP API master branch is: {}'.format(api_version_master['version']))

    if api_ok:
        if api_version['version'] == api_version_master['version']:
            self.log('success', 'Congratulation, the MISP API installed is up-to-date')
        else:
            self.log('warning', 'The MISP API installed is outdated, you should update to avoid issues.')

    pymisp_recommended = self.misp.get_recommended_api_version()
    if self._has_error_message(pymisp_recommended):
        self.log('warning', "The MISP instance you're using doesn't have a recomended PyMISP version, update recommended.")
    else:
        self.log('info', 'The recommended version of PyMISP: {}'.format(pymisp_recommended['version']))
        for a, b in zip(pymisp_recommended['version'].split('.'), api_version['version'].split('.')):
            if a != b:
                self.log('warning', "You're not using the recommended PyMISP version for this instance.")
                break

    instance_ok = True

    misp_version = self.misp.get_version()
    if self._has_error_message(misp_version):
        instance_ok = False
    else:
        self.log('info', 'The version of your MISP instance is: {}'.format(misp_version['version']))

    misp_version_master = self.misp.get_version_master()
    if self._has_error_message(misp_version_master):
        instance_ok = False
    else:
        self.log('info', 'The version of MISP master branch is: {}'.format(misp_version_master['version']))

    if instance_ok:
        if misp_version['version'] == misp_version_master['version']:
            self.log('success', 'Congratulation, your MISP instance is up-to-date')
        else:
            master_major, master_minor, master_hotfix = misp_version_master['version'].split('.')
            major, minor, hotfix = misp_version['version'].split('.')
            if master_major < major or master_minor < minor or master_hotfix < hotfix:
                self.log('warning', 'Your MISP instance is more recent than master, you must be using a beta version and probably know what you are doing. Enjoy!')
            else:
                self.log('warning', 'Your MISP instance is outdated, you should update to avoid issues with the API.')
