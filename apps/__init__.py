"""SASEGuard — a SASE-inspired Zero Trust access and data protection lab.

Four separately runnable services:

* ``apps.identity``   — demo identity issuer; sole holder of the RSA private key.
* ``apps.policy``     — policy decision point; owns device posture + revocation.
* ``apps.mock_apps``  — synthetic private applications, web fixtures, storage.
* ``apps.gateway``    — the only publicly bound service; policy enforcement point.

Everything here is synthetic. See README.md for the honest scope statement.
"""

__version__ = "1.0.0"
