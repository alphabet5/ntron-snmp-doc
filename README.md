# ntron-snmp-doc
 Script to collect snmp information from n-tron switches.

This is no longer maintained, but is still useful.

## Requirements

- python3 (3.9)
- pysnmp

# Usage

- Update the community string in community.txt
- Update switch_list.txt with list of switch ip addresses.
- Run `python3.9 ./SNMP_Doc.py`, this will output port devices and statuses similar to alphabet5/cisco_documentation.