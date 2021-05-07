# HTTP Security Header security evaluator

A tool to fetch and evaluate the security of HTTP Security Headers of websites. Weighting is used to tweak the algorithm without changing the code.

## Requirements

At least Python version 3.6 (not tested with anything below).

Packages:

    beautifulsoup4==4.8.2
    Flask==1.1.2
    html5lib==1.0.1
    httplib2==0.14.0
    Jinja2==2.11.3
    PyYAML==5.3.1
    requests==2.22.0
    requests-unixsocket==0.2.0
    simplejson==3.16.0
    urllib3==1.25.8
    validators==0.18.2

## scanner.py

scanner.py is used to scan all websites found in `ListAgencies.csv`. Run it from the repo-root dir using `python3 webapp/lib/scanner.py`.

## evaluategrade.py

evaluategrade.py is used in the GUI to evaluate the grade using the scanned results and the user-assigned weights. It can also be imported using `from lib.evaluategrade import *` to use it in your own code. How to use it is deferred to the `webapp/app.py` file for examples.

## stat.py

stat.py is used to get statistics about the scanned websites.

## Web GUI

### WARNING, DO NOT PUBLISH TO THE WEB

The tool is not meant to be published to the web as a finished web application. The tool is just a proof of concept and is not deemed secure for untrusted users to use.

To run the GUI, change directory to the root of the repository, then run `python3 webapp/app.py`

## Developers

Tool developed by Ludwig Johnson and Lukas Mårtensson at Blekinge Institute of Technology.
