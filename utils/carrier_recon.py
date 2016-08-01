#!/usr/bin/env python3

import csv
import argparse
from collections import OrderedDict

from core.base import Service


class CarrierRecon:
    """Wrapper to work with carrier CSV"""

    carrier_recon_layout = OrderedDict([
        ('ip', 'IP Address'),
        ('services', 'Port/Protocol'),
        ('hostnames', 'Domains'),
        ('os', 'Operating System'),
        ('os_version', 'OS Version'),
        ('notes', 'Notes')
    ])

    def __init__(self, csv_file_path: str):
        self._recon_entries = CarrierRecon.parse_csv(csv_file_path)

    @staticmethod
    def to_csv(csv_file_path: str, csv_report: list):
        with open(csv_file_path, 'w') as outfile:
            csv_out = csv.writer(outfile)
            for entry in csv_report:
                csv_out.writerow(entry)


    def get_updated_carrier_recon(self, keep_blank: bool=False):
        """
        :param keep_blank: remove entries with no open ports
        :return: None
        """
        if not keep_blank:
            self._remove_blanks()

        return self._produce_carrier_report_csv_rows()

    def _remove_blanks(self):
        self._recon_entries = {k: v for k, v in self._recon_entries.items()
                               if len(v['services'])}

    def _produce_carrier_report_csv_rows(self):
        carrier_report = []
        for ip, entry in self._recon_entries.items():
            carrier_ports = CarrierRecon.services_to_carrier_ports(entry['services'])
            domains = ', '.join(entry['hostnames'])
            os = entry['os']
            os_version = entry['os_version']
            notes = entry['notes']
            carrier_report += [[ip, carrier_ports, domains, os, os_version, notes]]

        # Sort results by IP
        carrier_report.sort(key=lambda x: list(map(int, x[0].split('.'))))
        carrier_report.insert(0, CarrierRecon.get_carrier_header())
        return carrier_report

    @staticmethod
    def get_carrier_header():
        header = []
        for k, v in CarrierRecon.carrier_recon_layout.items():
            header += [v]
        return header

    @staticmethod
    def parse_hostnames(carrier_hostnames_string: str):
        return [x.strip() for x in carrier_hostnames_string.split(',') if x.strip()]

    @staticmethod
    def parse_service(carrier_ports_string: str):
        # I should not have to add the if x.strip(), but otherwise it adds blank entries.
        carrier_ports = [x.strip() for x in carrier_ports_string.split(',') if x.strip()]
        services = []
        for carrier_port in carrier_ports:
            port = carrier_port.split('/')[0]
            protocol = carrier_port.split('/')[1]
            state = 'open'
            services += [Service(protocol=protocol, port=port, state=state)]

        return services

    @staticmethod
    def services_to_carrier_ports(services: list):
        ports = []
        for service in services:
            ports += [service.port + '/' + service.protocol]

        return ', '.join(ports)


    @staticmethod
    def parse_csv(csv_file_path: str):
        recon_entries = {}
        layout = CarrierRecon.carrier_recon_layout
        with open(csv_file_path, 'r') as csv_file:
            carrier_csv = csv.DictReader(csv_file)

            for row in carrier_csv:
                recon_entries.update({
                    row[layout['ip']]:
                    {
                        'hostnames': CarrierRecon.parse_hostnames(row[layout['hostnames']]),
                        'services': CarrierRecon.parse_service(row[layout['services']]),
                        'os': row[layout['os']],
                        'os_version': row[layout['os_version']],
                        'notes': row[layout['notes']]
                    }
                })

        return recon_entries


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description='Sanitize and update carrier_recon for a painless import in MST')
    parser.add_argument('csv_file', metavar='<csv file>', type=str,
                        help='Exported carrier recon (after the initial carrier scan from MST)')
    parser.add_argument('--keep_blank', '-b', action='store_true',
                        help="Don't remove IP with no open ports")
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='verbose flag')
    parser.add_argument('--outfile', '-o',
                        default='updated_carrier_recon.csv',
                        help='Report output')

    args = parser.parse_args()

    cr = CarrierRecon(args.csv_file)
    CarrierRecon.to_csv(args.outfile, cr.get_updated_carrier_recon())
