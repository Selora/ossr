#!/usr/bin/env python


class Finding:
    """Finding class:
        Agregate object abstracting a finding from various tools, could be a
        vulnerability as well as a scan results.

        Note: When creating a finding, it should be atomic.
        Ex: Portscanning
            For each port <status?> on a single host there should be a finding.

        Finding.host : The host IP
        Finding.vulnerability : Special wrapper for vulnerability
        Finding.service : Used to identify a port/protocol
        Finding.title : A generic title for the finding (ex. HTTP service)
        Finding.category : A set with keywords to identify the finding
        Finding.evidence : This is a buffer variable..may be anything
        Finding.command"""

    def __init__(self,
                 host,
                 vulnerability=None,
                 service=None,
                 evidence='',
                 title='',
                 category='',
                 command=''):
        self.host = host
        self.vulnerability = vulnerability
        self.service = service
        self.__title = title
        self.category = list(category)
        self.evidence = evidence
        self.command = command

    @property
    def title(self):
        """If its a vulnerability finding, return the vulnerabilty name \
            instead"""
        if self.vulnerability:
            return self.vulnerability.name
        else:
            return self.__title

    @title.setter
    def title(self, val):
        self.__title = val

    def is_scan(self):
        return True if not self.vulnerability else False

    def is_vulnerability(self):
        return True if self.vulnerability else False

    def get_printable(self):
        return str(self.title) + '\t' + str(self.category)


class Service:

    def __init__(
            self,
            protocol=None,
            port=None,
            service=None,
            state=None):
        self.protocol = protocol
        self.port = port
        self.service = service
        self.state = state

    def __str__(self):
        return str(self.__dict__)

    def __bool__(self):
        return any(attr for (key, attr) in self.__dict__.items())


class VulnerabilityMeta:

    def __init__(self,
                 severity=None,
                 category=None,
                 notes=None,
                 description=None,
                 evidence_cmd=None,
                 recommendation=None):
        self.severity = severity
        self.category = category
        self.notes = notes
        self.description = description
        self.evidence_cmd = evidence_cmd
        self.recommendation = recommendation

    def __bool__(self):
        return any(attr for (key, attr) in self.__dict__)


class Vulnerability:

    def __init__(self,
                 name,
                 meta=VulnerabilityMeta()):
        self.name = name
        self.meta = meta

    def __str__(self):
        return str(self.__dict__)

    def __bool__(self):
        return bool(self.name)
