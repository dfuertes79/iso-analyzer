# iso-analyzer

Simple script that:

- Looks for the contents inside ISO files: identifies files, types and SHA256 hash for each.
- If provided, checks files that can be executed (.py, .pl, EXE, DLL, etc.) with Virus Total API.
- Dumps the previous files to disk if desired.

Usage
-----

Provide an input ISO filename
Usage: iso-analyzer.py [options]

Options:
  -h, --help            show this help message and exit
  -f ISOFILE, --file=ISOFILE
                        ISO file to analyze
  -v VTAPI, --virustotal=VTAPI
                        Enable and provide Virust Total API to check coverage
                        for hashes
  -d, --dump            Automatically dump files that can be executed
  -t REQUESTDELAY, --delay=REQUESTDELAY
                        Delay between VT queries when -v option has been
                        expecified. When not specified, it defaulst to 16s to
                        respect VT public API rate limits
