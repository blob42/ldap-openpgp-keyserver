#!/usr/bin/env python

import ldap
import subprocess
import re


# LDAP SERVER INFORMATIONS
###########

HOST = '192.168.0.138'
BINDDN = 'cn=admin,dc=company,dc=lan'
CREDENTIALS = 'toto'
USERSDN = 'ou=users,dc=company,dc=lan'
DEFAULT_SCOPE = ldap.SCOPE_SUBTREE



# LDAP KEYSERVER SPECEFIC INFORMATIONS
###########

# PGP KEY SCHEMA
##

PGP_KEY_SCHEMA = {
    'pgpCertID': '',
    'pgpKey': '',
    'pgpDisabled': '',
    'pgpKeyID': '',
    'pgpKeyType': '',
    'pgpUserID': '',
    'pgpKeyCreateTime': '',
    'pgpSignerID': '',
    'pgpRevoked': '',
    'pgpSubKeyID': '',
    'pgpKeySize': '',
    'pgpKeyExpireTime': '',
}

# KEY SERVER INFO DN
###
PGP_SERVER_INFO = 'cn=pgpServerInfo,dc=company,dc=lan'

# BASE KEY SPACE DN
##
BASE_KEY_SPACE = 'ou=pgpKeys,dc=company,dc=lan'

############
# GPG SPECEFIC OPTIONS
############

# GPG COMMAND ARGUMETNS
##

GPG_HOME_DIR = "/home/spike/ldap/keys/"
GPG_IMPORT_STDIN = [
    'gpg',
    '--batch',
    '--no-tty',
    '--homedir',
    GPG_HOME_DIR,
    '--import',
    '-',
    ]

GPG_GET_FINGERPRINT = [
    'gpg',
    '--batch',
    '--no-tty',
    '--with-colons',
    '--homedir',
    GPG_HOME_DIR,
    '--fingerprint',
    ]


class LdapServer(object):
    """
    LdapServer : Handle connection to ldap server.
    Provides a simple interface to get and search pgp keys
    stored by users

    Attributes :

    host : the ip or lookup name to the Ldap server
    binddn : binddn
    cred : your credentials associated to your binddn
    usersdn : base dn to start looking for users in

    Methods:
    - test_search
    - get_user_key


    """
    host = HOST
    binddn = BINDDN
    cred = CREDENTIALS
    usersdn = USERSDN
    scope = DEFAULT_SCOPE
    attrs = ['gpgkey']
    userKeys = {}

    def __init__(self):
        try:
            self.ldapHandle = ldap.init(self.host)
            self.ldapHandle.bind(self.binddn, self.cred)
        except ldap.SERVER_DOWN as error:
            print 'init failed -> %s -> at %s' % (error, self.host)

    def test_search(self):
        """
        Perform a test search on the ldap server
        returns ldap.result() return type
        """
        self.test = self.ldapHandle.search_s(self.usersdn,ldap.SCOPE_SUBTREE,
        '(cn=cbenzian)', ['mail','phone'])
        return (self.test)

    def get_user_key(self, user):
        """
        This method lookup for the pgp key stored by the user,
        user must be in form 'cbenzian'

        Return a list in the form {userdn : gpgkey, }
        """
        print 'Searching for user %s gpgkey in ldap ou=users database ...' \
        % user
        try:
            msgid = self.ldapHandle.search(self.usersdn, self.scope, 'cn=%s' % \
                                           user, self.attrs)

            result = self.ldapHandle.result(msgid)[1]
            if result == []:
                raise ldap.NO_RESULTS_RETURNED('user %s not found' % user)
        except Exception, error:
            raise ValueError(error)
        return self._fetch_result(result)

    def updateKeyEntry(self, ldapKey):
        """
        Updates or creates a new ldap key entry
        If key exists it gets overwritten
        ldapKey must be a dict in the form PGP_KEY_SCHEMA
        """
        # NOTE: first we just want to add a key. We'll look to
        # update late
        key_dn = ''.join(['pgpCertID=%s,' % ldapKey['pgpCertID'],BASE_KEY_SPACE])
        key_record = [
            ('objectClass', ['pgpKeyInfo']),
            ('pgpCertID', [ldapKey['pgpCertID']]),
            ('pgpKey', [ldapKey['pgpKey']]),
            ('pgpKeyID', [ldapKey['pgpKeyID']])
            ]
        try:
            msgid = self.ldapHandle.add(key_dn,key_record)
            result = self.ldapHandle.result(msgid)
        except Exception, e:
            raise e

    def _fetch_result(self, ldap_result):
        """
        Fetches a result from an ldap result tupple and returns
        a dict of form {userdn: gpgkey,}
        """
        print 'Fetching results...'
        #print ldap_result
        tmp = ldap_result.pop(0)
        key_name = tmp[0].split(',')[0].split('=')[1]
        self.userKeys[key_name] = tmp[1]['gpgKey'].pop()
        return self.userKeys

class gpgKeyHandler(object):
    """Interface to manipulate gpgKeys, store on local keyring,
    send, update, or any key managment in the `ldap keys server`.

    The object initialization takes a dict in the form {'user' : key } .
    The following methods are available to manipulate keys:

    - saveKeyMsg: generates a file containing the public key armor

    - importUserKey: given a username imports it's public key message
    in the local defined keyring using gpg command line tools

    - getLdapReadyKey
    - getUserkeys
    - updateLdapKey : prepare specified key to be updated in ldap key server

    """

    user_keys = {}
    ldapReadyKeys = {}

    def __init__(self, keys={}):
        """
        Populate keys, takes a dict or raises an exception
        """
        if type(keys).__name__ != 'dict':
            raise TypeError ('%s takes a dict argument, %s given' %
                                (gpgKeyHandler, type(keys).__name__))
        self.user_keys = keys
        self.ldapHandle = LdapServer()

    def getLdapReadyKeys(self):
        """returns the keys prepared to be updated to ldap"""
        return self.ldapReadyKeys

    def getUserkeys(self):
        """returns public keys loaded from ldap users entries"""
        return user_keys

    def saveKeyMsg(self, user):
        """Save given key message in a file"""
        key = self.user_keys[user]
        filename = '%s.asc' % user
        try:
            file = open(filename, 'w')
            file.write(key)
            file.close()
        except IOError, error:
            print 'Read Write error %s' % error
    def importUserKey(self, user):
        """imports key block message of the user in form 'cbenzian'
        to the defined local keyring
        """
        self.user_keys.update(self.ldapHandle.get_user_key(user))
        key = self.user_keys[user]
        gpg_proc = subprocess.Popen(GPG_IMPORT_STDIN,
                                    stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
        output = gpg_proc.communicate(key)

    def ParseLdapKey(self, user):
        """Parse user public key in a structure that fits
        in the ldap keyserver entries see PGP_KEY_SCHEMA
        """
        self.importUserKey(user)
        keyInfo = PGP_KEY_SCHEMA
        keyInfo['pgpKey'] = self.user_keys[user]
        keyInfo['pgpCertID'] = self.fetchCertId(user)
        keyInfo['pgpKeyID'] = keyInfo['pgpCertID'][8:]
        keyInfo['pgpKeyType'] = self.fetchKeyType(user)
        self.ldapReadyKeys[user] = keyInfo


    def updateLdapKey(self, user):
        """
        Sends user's parsed key to ldap keys server
        We user ldapHandler's method updateKeyEntry()
        to do this.
        """
        self.ldapHandle.updateKeyEntry(self.ldapReadyKeys[user])

    def fetchCertId(self, user):
        """
        Returns CertID of user's public key by taking the
        last 8 bytes of the key's fingerprint
        """
        find_pattern = re.compile(r"(([0-9a-fA-F]{4,4}){4,4}):")
        args = GPG_GET_FINGERPRINT
        args.append(user)
        gpg_proc = subprocess.Popen(args,
                                    stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
        output = gpg_proc.communicate()
        # get gpg process output
        # and grep the CertID in the key's fingerprint
        fingerprint = output[0].split('\n')
        fingerprint = find_pattern.search(fingerprint[1])
        fingerprint = fingerprint.group(0).rstrip(':')
        certID = fingerprint.replace(' ','')
        return certID

    def fetchKeyType(self, user):
        """ Returns user's key type """





if __name__ == "__main__":
        keyHandler = gpgKeyHandler()
        keyHandler.ParseLdapKey('tvincent')
        #keyHandler.updateLdapKey('tvincent')
        keyHandler.saveKeyMsg('tvincent')





