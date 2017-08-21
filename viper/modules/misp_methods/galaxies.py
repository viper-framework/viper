# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

try:
    from pymispgalaxies import Clusters
    HAVE_PYGALAXIES = True
except:
    HAVE_PYGALAXIES = True


def galaxies(self):
    if not HAVE_PYGALAXIES:
        self.log('error', "Missing dependency, install PyMISPGalaxies (`pip install git+https://github.com/MISP/PyMISPGalaxies.git`)")
        return

    clusters = Clusters()

    if self.args.list:
        self.log('table', dict(header=['Name', 'Description'], rows=[(name, cluster.description)
                                                                     for name, cluster in clusters.items()]))
    elif self.args.search:
        matches = clusters.search(self.args.search)
        if not matches:
            self.log('error', 'No tags matching "{}".'.format(self.args.search))
            return
        self.log('success', 'Tags matching "{}":'.format(self.args.search))
        for cluster, values in matches:
            self.log('info', cluster.name)
            for val in values:
                for k, v in val._json().items():
                    self.log('item', '{}: {}'.format(k, v))
    elif self.args.details:
        cluster = clusters.get(self.args.details)
        if not cluster:
            self.log('error', 'No cluster called "{}".'.format(self.args.details))
            return
        if not self.args.cluster_value:
            # Show all values
            self.log('info', cluster.description)
            self.log('info', 'Type: ' + cluster.type)
            self.log('info', 'Source: ' + cluster.source)
            self.log('info', 'Authors: ' + ', '.join(cluster.authors))
            self.log('info', 'UUID: ' + cluster.uuid)
            self.log('info', 'Version: {}'.format(cluster.version))
            self.log('info', 'Values:')
            header = ['ID', 'Name', 'Description']
            rows = []
            i = 1
            for name, value in cluster.items():
                row = (i, value.value, value.description)
                rows.append(row)
                i += 1
            self.log('table', dict(header=header, rows=rows))
        else:
            cluster_value = ' '.join(self.args.cluster_value)
            # Show meta of a value
            c_val = cluster.get(cluster_value)
            if not c_val:
                self.log('error', 'No cluster value called "{}".'.format(cluster_value))
                return
            self.log('info', 'Name: {}'.format(c_val.value))
            self.log('info', 'Description: {}'.format(c_val.description))
            for key, value in c_val.meta._json().items():
                if isinstance(value, list):
                    self.log('info', '{}:'.format(key))
                    for e in value:
                        self.log('item', '{}'.format(e))
                else:
                    self.log('info', '{}: {}'.format(key, value))
