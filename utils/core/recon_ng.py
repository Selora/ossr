import sh
from os import path, makedirs


class Launcher:
    """Useful to launch recon-ng and get results from it...dang you python2!"""

    def __init__(self, recon_ng_path, python2_path):
        """path to recon-ng"""
        self.python2 = sh.Command(python2_path)

        cli_path = path.join(recon_ng_path, 'recon-cli')
        self.recon_cli = self.python2.bake(cli_path)

        ng_path = path.join(recon_ng_path, 'recon-ng')
        self.recon_ng = self.python2.bake(ng_path)

    def get_whois(self, company):
        whois = self.cmd.bake(['-x', '-m', 'recon/companies-multi/whois_miner', '-o'])
        print('Launching whois, please wait...(max 30 sec?)')
        return whois('SOURCE=' + company, _out_bufsize=0)

    def run_script(self, script_path):
        for line in self.recon_ng(['-r', script_path], _out_bufsize=1, _iter=True):
            print(line.rstrip('\n'))


class ScriptWriter:
    """Creates a recon-ng script file based on a master script"""

    def __init__(self, workspace, companies=None, recon_ng_template_script=None, contact_emails=None, scope=None):
        if ' ' in workspace:
            raise ValueError('"workspace" parameter contains spaces, its not supported by recon-ng!')
        self.workspace = workspace
        self.companies = companies.split(',')
        self.recon_ng_template_script = recon_ng_template_script
        self.scope = scope
        self.contacts_email = contact_emails.split(',')

    def get_recon_script(self):
        script = []
        script += ['workspaces add ' + self.workspace]

        for company in self.companies:
            script += ['query INSERT INTO companies (company, module) VALUES (' +
                  "'" + company.strip() + "'," + "'initial_scope')"]

        for netblock in self.scope.netblock_list:
            script += ['query INSERT INTO netblocks (netblock, module) VALUES (' +
                "'" + netblock + "'," + "'initial_scope')"]

        for ip in self.scope.get_expanded_ip_list():
            script += ['query INSERT INTO hosts (ip_address, module) VALUES (' +
                "'" + ip + "'," + "'initial_scope')"]

        for hostname in self.scope.hostname_list:
            script += ['query INSERT INTO hosts (host, module) VALUES (' +
                "'" + hostname + "'," + "'initial_scope')"]

        for email in self.contacts_email:
            script += ['query INSERT INTO contacts (email, module) VALUES (' +
                       "'" + email + "'," + "'initial_scope')"]

        script += self.recon_ng_template_script
        script += []
        return '\n'.join(script)

    def get_report_script(self, out_dir='recon_out'):
        tables_to_dump = [
            'companies',
            'contacts',
            'credentials',
            'netblocks',
            'ports',
            'domains',
            'hosts'
        ]
        report_script = []
        report_script += ['\nmkdir -p ' + out_dir]
        for table in tables_to_dump:
            report_script += ['use reporting/csv']
            report_script += ['set TABLE ' + table]
            report_script += ['set FILENAME ' + path.join(out_dir, table + '.csv')]
            report_script += ['run']

        report_script += ['exit']

        return '\n'.join(report_script)
