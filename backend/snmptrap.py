import re
import json
from pysnmp import debug
from pysnmp.hlapi import *


class Parsing:

    debug.setLogger(debug.Debug('msgproc'))

    def parser_json(self, myfile):
        data = []
        order = ["Timestamp", "Entity", "Message"]
        for line in myfile:
            details = re.sub("[][]|-|#|}|{", "", line.rstrip())
            structure = {key: value for key, value in zip(order, details.split(" ", 2))}
            data.append(structure)

        for entry in data:
            if entry:
                if entry["Timestamp"] == "":
                    entry["Timestamp"] = "Error"
                    entry["Entity"] = "Error"
            next(
                sendNotification(
                    SnmpEngine(),
                    CommunityData('public'),
                    UdpTransportTarget(('localhost', 162)),
                    ContextData(),
                    'trap',
                    # OID-value
                    [ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'),
                                OctetString(json.dumps(entry, indent=4)), )]))

    def reader(self):
        try:
            with open("enb0.log", encoding="utf-8") as file:
                return self.parser_json(file)
        except Exception:
                raise('File not found!')


if __name__ == "__main__":
    result = Parsing()
    result.reader()


