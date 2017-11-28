# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

try:
    from pytaxonomies import Taxonomies
    HAVE_PYTAX = True
except ImportError:
    HAVE_PYTAX = True


from viper.core.session import __sessions__


def tag(self):
    if not HAVE_PYTAX:
        self.log('error', "Missing dependency, install PyTaxonomies (`pip install git+https://github.com/MISP/PyTaxonomies.git`)")
        return

    taxonomies = Taxonomies()

    if self.args.list:
        self.log('table', dict(header=['Name', 'Description'], rows=[(title, tax.description)
                                                                     for title, tax in taxonomies.items()]))
    elif self.args.search:
        matches = taxonomies.search(self.args.search)
        if not matches:
            self.log('error', 'No tags matching "{}".'.format(self.args.search))
            return
        self.log('success', 'Tags matching "{}":'.format(self.args.search))
        for t in taxonomies.search(self.args.search):
            self.log('item', t)
    elif self.args.details:
        taxonomy = taxonomies.get(self.args.details)
        if not taxonomy:
            self.log('error', 'No taxonomy called "{}".'.format(self.args.details))
            return
        if taxonomy.description:
            self.log('info', taxonomy.description)
        elif taxonomy.expanded:
            self.log('info', taxonomy.expanded)
        if taxonomy.refs:
            self.log('info', 'References:')
            for r in taxonomy.refs:
                self.log('item', r)
        if not taxonomy.has_entries():
            header = ['Description', 'Predicate', 'Machinetag']
            rows = []
            for p in taxonomy.predicates.values():
                rows.append([p.description, p.predicate, taxonomy.make_machinetag(p)])
            self.log('table', dict(header=header, rows=rows))
        else:
            for p in taxonomy.predicates.values():
                if p.description:
                    self.log('info', p.description)
                elif p.expanded:
                    self.log('info', p.expanded)
                else:
                    self.log('info', p.predicate)

                if not p.entries:
                    self.log('item', taxonomy.make_machinetag(p))
                else:
                    header = ['Description', 'Predicate', 'Machinetag']
                    rows = []
                    for e in p.entries.values():
                        if e.description:
                            descr = e.description
                        else:
                            descr = e.expanded
                        rows.append([descr, e.value, taxonomy.make_machinetag(p, e)])
                    self.log('table', dict(header=header, rows=rows))
    elif self.args.event:
        if not __sessions__.is_attached_misp():
            return
        try:
            taxonomies.revert_machinetag(self.args.event)
        except Exception:
            self.log('error', 'Not a valid machine tag available in misp-taxonomies: "{}".'.format(self.args.event))
            return
        __sessions__.current.misp_event.event.add_tag(self.args.event)
        self._change_event()
    elif self.args.attribute:
        if not __sessions__.is_attached_misp():
            return
        identifier, tag = self.args.attribute
        try:
            taxonomies.revert_machinetag(tag)
        except Exception:
            self.log('error', 'Not a valid machine tag available in misp-taxonomies: "{}".'.format(tag))
            return
        __sessions__.current.misp_event.event.add_attribute_tag(tag, identifier)
        self._change_event()
