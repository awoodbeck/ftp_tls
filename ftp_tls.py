"""A FTP_TLS client subclass with additional functionality
to handle misconfigured FTP servers.
"""

from ftplib import FTP_TLS as stdFTP_TLS

class FTP_TLS(stdFTP_TLS):
    """
    A FTP_TLS subclass which adds support to force the use of
    the host address for passive (PASV) connections.

    This solves the problem of connecting to an misconfigured
    FTP server behind a firewall that reports its private IP
    instead of its public IP when issuing a PASV response.

    Usage example:
    >>> from ftp_tls import FTP_TLS
    >>> ftps = FTP_TLS('ftp.python.org')
    >>> ftps.login()  # login anonymously previously securing control channel
    '230 Guest login ok, access restrictions apply.'
    >>> ftps.prot_p()  # switch to secure data connection
    '200 Protection level set to P'
    >>> ftps.use_host_address()  # force the use of the host address
    >>> ftps.dir()  # list directory content securely
    total 2
    drwxr-xr-x   8 root     wheel        1024 Jan  3  1994 .
    drwxr-xr-x   8 root     wheel        1024 Jan  3  1994 ..
    '226 Transfer complete.'
    >>> ftps.quit()
    '221 Goodbye.'
    >>>
    """

    force_host_address = False

    def use_host_address(self, val=True):
        self.force_host_address = bool(val)

    def makepasv(self):
        host, port = stdFTP_TLS.makepasv(self)
        if self.force_host_address:
            host = self.sock.getpeername()[0]
        return host, port