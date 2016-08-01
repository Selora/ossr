#!/usr/bin/python2

import re
import socket
import csv
from netaddr import IPNetwork


class Scope:
    """Util class to manipulate recon scope.
    Supports:
    IP
    Netblocks (192.168.2.1/24)
    Netrange (192.168.2.1-25)
        -> Somewhat limited compared to Nmap funky range selectors
    FQDN
    """

    def __init__(self, ip_list=[], hostname_list=[], netblock_list=[], netrange_list=[]):
        not_ip = [x for x in ip_list if not Scope.is_ip(x)]
        if not_ip:
            raise ValueError('Value(s) ' + str(not_ip) + ' are provided as IP but cannot be casted as such')
        self.ip_list = ip_list

        not_hostname = [x for x in hostname_list if not Scope.is_hostname(x)]
        if not_hostname:
            raise ValueError('Value(s) ' + str(not_hostname) + ' are provided as hostnames but cannot be casted as such')
        self.hostname_list = hostname_list

        not_netblock = [x for x in netblock_list if not Scope.is_netblock(x)]
        if not_netblock:
            raise ValueError('Value(s) ' + str(not_netblock) + ' are provided as netblocks but cannot be casted as such')
        self.netblock_list = netblock_list

        not_netrange = [x for x in netrange_list if not Scope.is_netrange(x)]
        if not_netrange:
            raise ValueError('Value(s) ' + str(not_netrange) + ' are provided as netranges but cannot be casted as such')
        self.netrange_list = netrange_list

    def get_expanded_ip_list(self):
        ip_list = [x for x in self.ip_list]
        ip_netblocks = [ip for nb in self.netblock_list for ip in Scope.expend_netblock(nb)]
        ip_netrange = [ip for nr in self.netrange_list for ip in Scope.expend_netrange(nr)]

        ip_list = list(set(ip_list + ip_netrange + ip_netblocks))
        ip_list.sort(key=lambda s: list(map(int, s.split('.'))))

        return ip_list

    @staticmethod
    def read_scope_from_file(filename):
        """Read the scope from a file containing what's supported (see class description)"""
        ip_list = []
        hostname_list = []
        netblock_list = []
        netrange_list = []
        unknown_list = []

        # Read the scope file, extract the scope
        with open(filename, 'r') as scope_file:
            for line in scope_file:
                line = line.strip()
                if Scope.is_ip(line):
                    ip_list += [line]
                elif Scope.is_netblock(line):
                    netblock_list += [line]
                elif Scope.is_netrange(line):
                    netrange_list += [line]
                elif Scope.is_hostname(line):
                    hostname_list += [line]
                else:
                    unknown_list += [line]

        return Scope(ip_list=ip_list,
                     hostname_list=hostname_list,
                     netblock_list=netblock_list,
                     netrange_list=netrange_list)

    @staticmethod
    def is_ip(ip):
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False

    @staticmethod
    def is_hostname(hostname):
        """Will validate if its ip OR fqdn OR domain"""
        if len(hostname) > 255:
            return False

        if hostname[-1] == ".":
            # strip exactly one dot from the right, if present
            hostname = hostname[:-1]
        allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
        return all(allowed.match(x) for x in hostname.split("."))

    @staticmethod
    def is_netblock(hostname):
        if '/' in hostname:
            (ip_addr, cidr) = hostname.split('/')
            if Scope.is_int(cidr) and Scope.is_ip(ip_addr):
                return True

        return False

    @staticmethod
    def is_netrange(hostname):
        if '-' in hostname:
            (ip_addr, ip_range) = hostname.split('-')
            if Scope.is_int(ip_range) and Scope.is_ip(ip_addr):
                return True
        return False

    @staticmethod
    def is_int(s):
        try:
            int(s)
            return True
        except ValueError:
            return False

    @staticmethod
    def expend_netblock(netblock):
        return [str(ip) for ip in IPNetwork(netblock)]

    @staticmethod
    def expend_netrange(ip_range):
        if '-' not in ip_range:
            raise ValueError(
                        str(ip_range) + ' is not an ip range (ex: 1.1.1.1-255)')
        (ip_addr, ip_range_end) = ip_range.split('-')
        if not Scope.is_int(ip_range_end):
            raise ValueError(
                        str(ip_range) + ' is not an ip range (ex: 1.1.1.1-255)')

        ip_bytes = ip_addr.split('.')
        ip_list = [ip_addr]
        ip_start = int(ip_bytes[-1])
        ip_end = int(ip_range_end)
        for ip_suffix in range(ip_start+1, ip_end+1):
            ip = str(ip_bytes[0] +
                     '.' + ip_bytes[1] +
                     '.' + ip_bytes[2] +
                     '.' + str(ip_suffix))
            ip_list += [ip]
        return ip_list


class ScopeValidator:
    """Validate {hostname,IP} against a scope"""

    def __init__(self, original_scope: Scope):
        self.scope = original_scope

    def validate_ip(self, ip):
        ip_found = [x for x in self.scope.get_expanded_ip_list() if x == ip]
        return True if ip_found else False

    def validate_hostname(self, hostname):
        return True if hostname in self.scope.hostname_list else False

    def validate_host_csv(self, host_csv_file_path, idx_hn=0, idx_ip=1):
        with open(host_csv_file_path, 'r') as host_file:
            host_csv = csv.reader(host_file)

            for row in host_csv:
                hostname = row[idx_hn]
                ip = row[idx_ip]

                yield ((hostname, self.validate_hostname(hostname)), (ip, self.validate_ip(ip)))

    @staticmethod
    def validated_scope_writer(validated_scope, validated_scope_outfile):
        with open(validated_scope_outfile, 'w') as outfile:
            out_csv = csv.writer(outfile)
            for validated_entry in validated_scope:
                (hostname, hn_in_scope) = validated_entry[0]
                (ip, ip_in_scope) = validated_entry[1]

                status = 'Not in scope'
                if ip_in_scope and hn_in_scope:
                    status = 'Original scope'
                elif not hostname and ip_in_scope:
                    # If hostname is blank but IP is in original scope
                    status = 'Original scope'
                elif ip_in_scope:
                    status = 'Extended scope (new hostname)'
                elif hn_in_scope:
                    status = 'Extended scope (new ip)'

                out_csv.writerow([hostname, ip, status])
