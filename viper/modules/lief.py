from viper.common.abstracts import Module

class Lief(Module):
    cmd         = "lief"
    description = "Parse and extract information from ELF, PE, MachO, DEX, OAT, ART and VDEX formats"
    authors     = ["Jordan Samhi"]

    def __init__(self):
        super(Lief, self).__init__()
        subparsers = self.parser.add_subparsers(dest="subname")
        subparsers.add_parser("elf", help="ELF parser")
        subparsers.add_parser("pe", help="PE parser")

    def run(self):
        super(Lief, self).run()
        if self.args is None:
            return

        if self.args.subname == "elf":
            print("elf")
        elif self.args.subname == "pe":
            print("pe")
        else:
            self.log("error", "At least one of the paramteres is required")
            self.usage()
