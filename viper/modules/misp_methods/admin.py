# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os


def admin(self):
    if self.args.admin == 'org':
        def display_orgs_table(typeorg='local', name=None):
            header = ['ID', 'Name', 'Local', 'Users', 'Created', 'UUID']
            rows = []
            for org in self.misp.get_organisations_list(typeorg):
                org = org['Organisation']
                if not name or name.lower() in org['name'].lower():
                    rows.append([org['id'], org['name'], org['local'], org.get('user_count'), org['date_created'], org['uuid']])
            self.log('table', dict(header=header, rows=sorted(rows, key=lambda x: int(x[0]))))

        def display_org(org):
            if not org.get('Organisation'):
                self.log('error', 'Invalid organisation.')
                return False
            org = org['Organisation']
            self.log('success', org['name'])
            for k, v in org.items():
                if k != 'name' and v:
                    self.log('item', '{}: {}'.format(k, v))
            return True

        if self.args.org == 'display':
            if self.args.id in ['all', 'local', 'external']:
                display_orgs_table(self.args.id)
            else:
                org = self.misp.get_organisation(self.args.id)
                display_org(org)
        elif self.args.org == 'search':
            display_orgs_table(name=self.args.name, typeorg=self.args.type)
        elif self.args.org == 'add':
            response = self.misp.add_organisation(
                name=self.args.name, description=' '.join(self.args.description),
                type=' '.join(self.args.type), nationality=self.args.nationality,
                sector=' '.join(self.args.sector), uuid=self.args.uuid,
                contact=' '.join(self.args.contacts), local=self.args.not_local)
            if response.get('Organisation'):
                self.log('success', 'New organisation created.')
                display_org(response)
            else:
                # Error
                self.log('error', response['message'])
                if response.get('errors'):
                    self.log('error', response['errors'][-1])
        elif self.args.org == 'delete':
            org = self.misp.get_organisation(self.args.id)
            self.log('warning', "You're about to delete the following organisation:")
            if not display_org(org):
                return
            i = input('Are you sure you want to delete it? (Please write "I am sure.")\n')
            if i != 'I am sure.':
                self.log('warning', "Organisation not deleted.")
                return
            response = self.misp.delete_organisation(self.args.id)
            self.log('success', response['message'])
        elif self.args.org == 'edit':
            response = self.misp.edit_organisation(
                self.args.id,
                name=self.args.name, description=' '.join(self.args.description),
                type=' '.join(self.args.type), nationality=self.args.nationality,
                sector=' '.join(self.args.sector), uuid=self.args.uuid,
                contacts=' '.join(self.args.contacts), local=self.args.not_local)
            if response.get('Organisation'):
                self.log('success', 'Organisation updated.')
                display_org(response)
            else:
                # Error
                self.log('error', response['message'])
                if response.get('errors'):
                    self.log('error', response['errors'][-1])
    elif self.args.admin == 'user':
        def display_users_table(name=None):
            header = ['ID', 'E-Mail', 'Organisation', 'authkey']
            rows = []
            for user in self.misp.get_users_list():
                user = user['User']
                if not name or name.lower() in user['email'].lower():
                    rows.append([user['id'], user['email'], user['org_ci'], user['authkey']])
            self.log('table', dict(header=header, rows=sorted(rows, key=lambda x: int(x[0]))))

        def display_user(user):
            if not user.get('User'):
                self.log('error', 'Invalid user.')
                return False
            user = user['User']
            self.log('success', user['email'])
            for k, v in user.items():
                if k not in ['email', 'certif_public', 'gpgkey'] and v:
                    self.log('item', '{}: {}'.format(k, v))
            return True

        if self.args.user == 'display':
            if self.args.id == 'all':
                display_users_table()
            else:
                user = self.misp.get_user(self.args.id)
                display_user(user)
        elif self.args.user == 'search':
            display_users_table(name=self.args.name)
        elif self.args.user == 'add':
            gpgkey = ''
            if self.args.gpgkey:
                if os.path.isfile(self.args.gpgkey):
                    with open(self.args.gpgkey, 'r') as f:
                        gpgkey = f.read()
                else:
                    self.log('error', 'gpgkey should be a path to the armored dump of the public key')
            response = self.misp.add_user(
                email=self.args.email, org_id=self.args.org_id, role_id=self.args.role_id,
                gpgkey=gpgkey, change_pw=self.args.change_pw, termsaccepted=self.args.termsaccepted,
                password=self.args.password, disabled=self.args.disabled)
            if response.get('User'):
                self.log('success', 'New user created.')
                display_user(response)
            else:
                # Error
                self.log('error', response['message'])
                if response.get('errors'):
                    self.log('error', response['errors'][-1])
        elif self.args.user == 'delete':
            user = self.misp.get_user(self.args.id)
            self.log('warning', "You're about to delete the following user:")
            if not display_user(user):
                return
            i = input('Are you sure you want to delete it? (Please write "I am sure.")\n')
            if i != 'I am sure.':
                self.log('warning', "User not deleted.")
                return
            response = self.misp.delete_user(self.args.id)
            self.log('success', response['message'])
        elif self.args.user == 'edit':
            gpgkey = ''
            if self.args.gpgkey:
                if os.path.isfile(self.args.gpgkey):
                    with open(self.args.gpgkey, 'r') as f:
                        gpgkey = f.read()
                else:
                    self.log('error', 'gpgkey should be a path to the armored dump of the public key')
            response = self.misp.edit_user(
                self.args.id,
                email=self.args.email, org_id=self.args.org_id, role_id=self.args.role_id,
                gpgkey=gpgkey, change_pw=self.args.change_pw, termsaccepted=self.args.termsaccepted,
                password=self.args.password, disabled=self.args.disabled)
            if response.get('User'):
                self.log('success', 'User updated.')
                display_user(response)
            else:
                # Error
                self.log('error', response['message'])
                if response.get('errors'):
                    self.log('error', response['errors'][-1])
    elif self.args.admin == 'role':
        def display_roles_table(name=None):
            header = ['ID', 'Name', 'Adm', 'Site Adm', 'Sync', 'Audit',
                      'Authkey', 'Regex', 'Tagger', 'Tag edit', 'Template',
                      'Sharing grp', 'Deleg', 'Sighting', 'Default', 'ID - Permission']
            rows = []
            for role in self.misp.get_roles_list():
                role = role['Role']
                if not name or name.lower() in role['name'].lower():
                    row = [role['id'], role['name'], role['perm_admin'],
                           role['perm_site_admin'], role['perm_sync'],
                           role['perm_audit'], role['perm_auth'], role['perm_regexp_access'],
                           role['perm_tagger'], role['perm_tag_editor'], role['perm_template'],
                           role['perm_sharing_group'], role['perm_delegate'], role['perm_sighting'],
                           role['default_role'], '{} - {}'.format(role['permission'], role['permission_description'])]
                    rows.append([entry if entry else '' for entry in row])
            self.log('table', dict(header=header, rows=sorted(rows, key=lambda x: int(x[0]))))

        if self.args.role == 'display':
            display_roles_table()
        elif self.args.role == 'search':
            display_roles_table(name=self.args.name)
    elif self.args.admin == 'tag':
        def display_tags_table(name=None):
            header = ['ID', 'Name', 'Usage', 'Favourite', 'Exportable', 'Hidden', 'Colour', 'Org ID']
            rows = []
            for tag in self.misp.get_tags_list():
                if not name or name.lower() in tag['name'].lower():
                    rows.append([tag['id'], tag['name'], tag['attribute_count'],
                                tag['favourite'], tag['exportable'], tag['hide_tag'], tag['colour'], tag['org_id']])
            self.log('table', dict(header=header, rows=sorted(rows, key=lambda x: int(x[0]))))

        if self.args.tag == 'display':
            display_tags_table()
        elif self.args.tag == 'search':
            display_tags_table(name=self.args.name)
