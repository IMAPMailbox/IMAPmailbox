# IMAP Mailbox app

This app will download email messages from an IMAP account/mailbox and index it into Splunk.  Each email message will be treated as a separate splunk event.

This is an update to the "Splunk for IMAP" v1.20 app. It appears the Splunk employee who created the original app is not able to maintain it. Its last update was in 2009. So I decided (with permission of Splunk) to write an update! It cannot be named the same due to Splunk development naming rules, but this app can be considered the new version going forward; and thus started it at version 2.0.  The original app will still work fine for Splunk v5 users and below.

You can help make IMAP Mailbox better by contributing: https://github.com/IMAPMailbox/IMAPmailbox.git

# Getting Started

## Default settings note:

Before enabiling the IMAP settings, be aware of the default settings used in imap.conf file.
One of the default settings is to delete all email once read and indexed from your mailbox. This is default to speed up indexing. If all mail is left in the mailbox, the script has to read the mail headers over and over each time it connects to index and can greatly slow down the process.

## New Install

This section is to install on a centralized splunk setup. Look further down for distributed splunk design instructions.

1. Copy the IMAPmailbox app directory into $SPLUNK_HOME/etc/apps/ location.  Or install via Splunk UI (recommended).
2. Copy default/imap.conf to local/imap.conf and provide the required settings for connecting to your IMAP server (server, user, password, port, etc...).  See the comments in the default/imap.conf file for more details about all required and optional settings. Or you can run the setup page via the Splunk UI under Apps.
3. For Windows users please disable the unix script and enable the windows one in file default/inputs.conf
4. Restart the Splunk server.

By default, the IMAP app will create a new Splunk index named "mail". This is controlled by:  default/indexes.conf. If you want the IMAP output to go to the default Splunk index:

1. Remove "index = mail" reference in default/inputs.conf
2. Delete the default/index.conf file.
3. Comment out the "definition = index=mail" in default/macros.conf file.
4. Restart the Splunk server.


## Upgrading this app

1. Run the upgrade via the Splunk App management UI.


## Upgrading from the original "Splunk for Imap" app

Instructions if you are currently using Splunk for IMAP v1.20 and want to upgrade to this new app. 

Install this app as instructions above, it will install in a new location than the original app.

1. Copy imap/local/* files/directories over to IMAPmailbox/local/
2. Copy imap/metadata/local.meta over to IMAPmailbox/metadata/
3. Disable the original app via the Splunk Apps UI.
4. Restart Splunk.

Note: If you have any users with private saved searches, dashboards, alerts, then you will need to change their user app directory name so it appears for this app.

- Example: (do this for all users)
    - cd /opt/splunk/etc/users/pbalsley/
    - mv imap/ IMAPmailbox/

This app uses the same index "mail" as the original app, so all past indexed data will still exist.


## Install for Distributed Splunk designs

For those who are running a distributed Splunk set: forwarders, search heads, indexers, etc... You may want to use the IMAPmailbox-TA located under appserver/addons/ directory.

See the TA README.md file for more instructions.


## Generating encrypted passwords

It is recommeneded that your store your IMAP user password and splunk admin password encrypted in your local/imap.conf file.

1. To do so, make sure your password= and splunkpassword= are not used or blank.
2. Run the genpass.sh script to generate your encrypted text.
3. Put the encrypted password with the values xpassword= and splunkxpassword= in your local/imap.conf file.


### Run the password generator

1. Import the splunk ENV: `source $SPLUNK_HOME/bin/setSplunkEnv`
2. Run: `bin/genpass.sh`


# Notes

Message headers are indexed as key-value pairs, for example:

`From = "User Name <user@emailcom>"`

`Subject = "This is sooo cool"`

This makes it easy to generate reports from the email indexed in Splunk.
For example:

`index=mail | top From`

Also, note the quotes around the field values.  This makes it easy to perform searches 'where' or regexes.  For example, if you want to find all your email that was sent by any Will, do the following:

`index=mail From="Will*"`

Instead of searching with the "index=mail" tag as examples show above. I recommend using the macro ``imap_index`` instead. If you change your index or even don't use one, this macro will still keep your searches working correctly.
   
If you have bugs or suggestions please contact pj@dysan.net.


# Exchange MAPI

What if your Exchange Admin does not want to enable imap?  I suggest using the davmail server proxy, <http://davmail.sourceforge.net/>.  It will convert IMAP requests to MAPI for exchange.  You can load davmail on your local splunk server, or on any other server. Just point your imap.conf to the correct server and port. It will pass through the imap credentials to Exchange.


# Troubleshooting

Some hints on troubleshooting:

Run the get imap script manually to look for mail issues.

1. Login and become the user that runs splunk.
    `sudo su - splunk`
2. Import the splunk ENV.
    `source $SPLUNK_HOME/bin/setSplunkEnv`
3. Run python script with debug
    `$SPLUNK_HOME/bin/splunk cmd python bin/get_imap_email.py --debug`

Check that the email message is plain text. Rich Text and HTML emails will not index by default inless you update imap.conf.

Google your error messages. :)

Duplicate Emails: If using a service like Gmail and you are getting a two copies or more of an email, this is normally because the email is being found twice on the server; once in the INBOX and the second in All Mail. Solution is to limit what folders you are checking.  I suggest using:

- folders = INBOX

This will download just your new email in your inbox and not the archived messages, which is why this is happening.


# What is it good for?

In my case I forward all unix root system messages to one mailbox that I index from. Then I can watch for errors and create alerts, such as cron failures.

I've signed up for mailing lists to my indexed email address and create reports and alerts based on only certain content I'm interested in looking for.


# What's new in 2.0.4!

- Added multi field support for email addresses, such as To, From, and Cc.
- Fixed format bug in the get_imap_email.py script.


# What's new in 2.0.3!

- Fixed a handler error in the setup.
- Verified works with Splunk v6.2


# What's new in 2.0.2!

Just minor updates.

- Added a TA for distributed Splunk designs.


# What's new in 2.0.1!

Just minor updates.

- Added ui-prefs.conf to set default search times to 1 day instead of all time.
- Added a few more searches.
- Renamed the searches to be more helpful.


# What's New in 2.0!

App completely updated for Splunk 6.0

- Updated nav bar
- New searches
- New dashboards
- Updated setup.xml
- Added Pivot Data Models
- Added app Icons
- Fixed some python bugs
- Fixed some genpass.sh bugs
- imap.conf changes to default settings:
    - imapSearch 
    - deleteWhenDone
    - useSSL
    - port

