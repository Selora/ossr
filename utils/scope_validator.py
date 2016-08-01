#!/usr/bin/python3

import argparse
import csv

from core.scope import Scope, ScopeValidator



if __name__ == "__main__":

    parser = argparse.ArgumentParser(
                            description='validate hosts exported with recon-ng')
    parser.add_argument('scope_file', metavar='<scope file>', type=str,
                        help='copy/paste the scope in that file')
    parser.add_argument('hosts_csv', metavar='<hosts csv>', type=str,
                        help='exported hosts')
    parser.add_argument('--out_csv', '-o', metavar='<out csv>',
                        default='validated_scope.csv',
                        help='hosts validated against scope\n\
                        the last column is true if it is in scope, false otherwise')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='verbose flag')

    args = parser.parse_args()
    scope = Scope.read_scope_from_file(filename=args.scope_file)

    scope_validator = ScopeValidator(scope)
    validated_scope = scope_validator.validate_host_csv(args.hosts_csv)

    if args.verbose:
        print('Original scope:')
        print(scope.ip_list)
        print(scope.netblock_list)
        print(scope.netrange_list)
        print(scope.hostname_list)

        print()
        print('Expended IP list:')
        print(scope.get_expanded_ip_list())

        print()
        print('Scope check:')
        print(validated_scope)


    ScopeValidator.validated_scope_writer(validated_scope, args.out_csv)

