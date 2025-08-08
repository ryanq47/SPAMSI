# SPAMSI - PostEx AMSI Patching

SPAMSI is a security bypass tool designed to automatically patch the Antimalware Scan Interface (AMSI) in all currently running PowerShell processes. Its primary purpose is to neutralize AMSI-based scanning and detection mechanisms used by antivirus and endpoint protection software.

The tool operates by identifying active PowerShell instances and applying an in-memory patch that disables AMSI functionality, effectively preventing script content from being scanned. Future development aims to extend this capability to all other processes where AMSI is loaded, including both existing processes and any newly spawned ones.