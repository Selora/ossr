#usr/bin/env python3

from os import path

from core.recon_ng import Launcher, ScriptWriter
from core.scope import Scope, ScopeValidator

import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run recon-ng')

    parser.add_argument('recon_ng_path',
                        type=str,
                        help='Path to recon-ng latest git pull. MUST already be working (get those dep!)')
    parser.add_argument('--python2_path', '-p',
                        type=str,
                        default='/usr/bin/python2',
                        help='Path to python2 install')
    parser.add_argument('--outdir', '-o',
                        default='recon_out',
                        help='Where recon-ng will dump the db in csv')

    parser.add_argument('--recon_ng_script', type=argparse.FileType('r'),
                            help='The recon-ng command file; you can record your own.'\
                                 'If no file is provided, will just load info in workspace.'
                        )

    parser.add_argument('--workspace', '-w', type=str,
              required=True,
              help='The recon-ng workspace name. \
              Works best with no spaces.')
    parser.add_argument('--scope_file', '-s', type=str,
                        help='File containing FQDN,IP,netblocks,netranges,etc' \
                        'See scope.py for what is supported')
    parser.add_argument('--companies', '-c', type=str,
                        help='Company name in dbl.quotes, comma separated: "NiceCorp Inc.,SuperNiceCorp LLC."')
    parser.add_argument('--emails', '-e', type=str,
                        help='Emails separated by commas ("asdf@test.com,test@corp.com")')

    args = parser.parse_args()

    reconscript_path = 'reconscript.txt'
    scope = Scope.read_scope_from_file(args.scope_file)

    # Build the final recon-ng script which imports the scope and run commands in
    # --recon_ng_script
    if args.recon_ng_script:
        recon_ng_script = args.recon_ng_script.read().splitlines()
    else:
        recon_ng_script = ''

    sw = ScriptWriter(workspace=args.workspace,
                      companies=args.companies,
                      recon_ng_template_script=recon_ng_script,
                      contact_emails=args.emails,
                      scope=scope)

    reconscript = sw.get_recon_script()
    reconscript += sw.get_report_script(out_dir=args.outdir)

    with open(reconscript_path, 'w') as scriptfile:
        scriptfile.write(reconscript)

    script_file_path = reconscript_path

    launcher = Launcher(args.recon_ng_path, args.python2_path)
    launcher.run_script(script_file_path)

    if args.scope_file:
        scope = Scope.read_scope_from_file(filename=args.scope_file)
        sv = ScopeValidator(scope)
        validated_scope = sv.validate_host_csv(path.join(args.outdir, 'hosts.csv'))
        ScopeValidator.validated_scope_writer(validated_scope, path.join(args.outdir, 'validated_scope.csv'))
