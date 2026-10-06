"""
The `~certbot_dns_muumuu._internal.dns_muumuu` plugin automates the process of
completing a ``dns-01`` challenge (`~acme.challenges.DNS01`) by creating, and
subsequently removing, TXT records using the Muumuu Domain API v2.

Named Arguments
---------------

========================================  =====================================
``--dns-muumuu-credentials``              Muumuu Domain credentials_ INI file.
                                          (Required)
``--dns-muumuu-propagation-seconds``      The number of seconds to wait for DNS
                                          to propagate before asking the ACME
                                          server to verify the DNS record.
                                          (Default: 30)
========================================  =====================================


Credentials
-----------

Use of this plugin requires a Muumuu Domain Personal Access Token with the
``domains:read``, ``dns:read`` and ``dns:write`` scopes.

.. code-block:: ini
   :name: credentials.ini
   :caption: Example credentials file:

   # Muumuu Domain Personal Access Token used by Certbot
   dns_muumuu_token = muu_pat_0123456789abcdef

   # Optional: API endpoint (defaults to production)
   # dns_muumuu_endpoint = https://api-sandbox.muumuu-domain.com/api/v2

The path to this file can be provided interactively or using the
``--dns-muumuu-credentials`` command-line argument. Certbot records the path
to this file for use during renewal, but does not store the file's contents.

.. caution::
   You should protect this token as you would the password to your Muumuu
   Domain account. Users who can read this file can use the token to modify
   any DNS record of every domain in the account.

   Certbot will emit a warning if it detects that the credentials file can be
   accessed by other users on your system (``chmod 600`` it).


Examples
--------

.. code-block:: bash
   :caption: To acquire a certificate for ``example.com`` and ``*.example.com``

   certbot certonly \\
     --authenticator dns-muumuu \\
     --dns-muumuu-credentials ~/.secrets/certbot/muumuu.ini \\
     -d example.com \\
     -d '*.example.com'
"""
