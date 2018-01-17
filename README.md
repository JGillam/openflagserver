# Open Flag Server

## Overview
This application is designed to be a lightweight customizable scoring server for the use of CTF (Capture The Flag)
exercises typical in security/hacking competitions.  It consists of a single python script (flags.py), a sqlite db,
some static html, css, etc... and a configuration file that specifies which flags are available.

This project was thrown together for a specific need and seemed useful enough to warrant sharing.  If you have ideas to improve
on it please submit feedback or even fork, implement and submit a pull request.  Thanks!

## Dependencies
The Open Flag Server has been tested on Python 3 and requires the following Python modules:
   * cherrypy
   * argparse
   * db-sqlite3
   * hashlib (requires Python developer libs)
   * json
   * datetime
   
## Other Included Stuff
Open Flag Server uses JQuery and Bootstrap, both of which are included to simplify setup.
   
## More Details

### The Database
The sqlite database (participants.db) is created automatically upon startup.  If you want to start a fresh server,
simply delete this database.  The main purpose of the database is to persist the state in the event of an outage.

### The Configuration
The configuration file is in JSON format and consists of a list of the following value sets:
   * id: The id of the flag.  This will be what is displayed to the user upon successful submission of a flag.
   * hash: The key, typically as a md5 hash.
   * value: The value assigned to the key.  This should be an int value.
   
An example configuration can be found in the example.flags file.  The configuration file is specified on the command
line during startup, making it easy to manage different scoring configurations without having to customize many files.

In addition to the flag list, the configuration also includes the following:
   * help: Point to a specific file to display in the help link.  This should be an html fragment that will be inserted
   into the appropriate div on the page (i.e. do not include html, head, body tags).  The "example-help.html" file is
   the default.

### Security
The Open Flag Server is designed to minimize the likelihood of many common web vulnerabilities.  For example all db
queries are parameterized and any values submitted are strictly validated before use.  This does not guarantee that
the system has no vulnerabilities, only that an effort was made to mitigate them.
