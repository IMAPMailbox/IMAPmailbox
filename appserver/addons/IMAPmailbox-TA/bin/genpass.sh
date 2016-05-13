#!/bin/bash

#Jimmy J - 07/15/2008
#Modified this script to use the /bin/bash shell as opposed to the /bin/sh shell. The /bin/sh does not interpret the -n flag
#correctly on mac i.e. the trailing newline is added to the password

#No need of a key file to save the key used for encrypting/decrypting the passwords.
#We now use the splunk.secret key that comes with every installation of splunk

echo -n "Enter the password you want to encrypt:"
stty -echo
read pass
stty echo

echo ""
echo -n "Enter it one more time to make sure you typed it in correctly:"
stty -echo
read pass2
stty echo

if [ $pass = $pass2 ]; then

    echo ""
    echo ""
    echo -n $pass | openssl bf -e -a -pass file:$SPLUNK_HOME/etc/auth/splunk.secret
    
    echo ""
    echo "Copy the string on the line above and paste it into"
    echo "local/imap.conf as the value for xpassword."
else
    echo ""
    echo ""
    echo "Exiting"
    echo "Sorry, your passwords did not match."
fi
