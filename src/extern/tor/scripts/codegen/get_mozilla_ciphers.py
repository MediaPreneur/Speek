#!/usr/bin/env python
# coding=utf-8
# Copyright 2011-2019, The Tor Project, Inc
# original version by Arturo Filastò
# See LICENSE for licensing information

# This script parses Firefox and OpenSSL sources, and uses this information
# to generate a ciphers.inc file.
#
# It takes two arguments: the location of a firefox source directory, and the
# location of an openssl source directory.

# Future imports for Python 2.7, mandatory in 3.0
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import os
import re
import sys

if len(sys.argv) != 3:
    print("Syntax: get_mozilla_ciphers.py <firefox-source-dir> <openssl-source-dir>", file=sys.stderr)
    sys.exit(1)

ff_root = sys.argv[1]
ossl_root = sys.argv[2]

def ff(s):
    return os.path.join(ff_root, s)
def ossl(s):
    return os.path.join(ossl_root, s)

#####
# Read the cpp file to understand what Ciphers map to what name :
# Make "ciphers" a map from name used in the javascript to a cipher macro name
with open(ff('security/manager/ssl/nsNSSComponent.cpp'),'r') as fileA:
    # The input format is a file containing exactly one section of the form:
    # static CipherPref CipherPrefs[] = {
    #  {"name", MACRO_NAME}, // comment
    #  ...
    #  {NULL, 0}
    # }

    inCipherSection = False
    cipherLines = []
    for line in fileA:
        if line.startswith('static const CipherPref sCipherPrefs[]'):
            # Get the starting boundary of the Cipher Preferences
            inCipherSection = True
        elif inCipherSection:
            line = line.strip()
            if line.startswith('{ nullptr, 0}'):
                # At the ending boundary of the Cipher Prefs
                break
            else:
                cipherLines.append(line)
# Parse the lines and put them into a dict
ciphers = {}
cipher_pref = {}
key_pending = None
for line in cipherLines:
    if m := re.search(
        r'^{\s*\"([^\"]+)\",\s*(\S+)\s*(?:,\s*(true|false))?\s*}', line
    ):
        assert not key_pending
        key,value,enabled = m.groups()
        if enabled == 'true':
            ciphers[key] = value
            cipher_pref[value] = key
        continue
    if m := re.search(r'^{\s*\"([^\"]+)\",', line):
        assert not key_pending
        key_pending = m[1]
        continue
    if m := re.search(r'^\s*(\S+)(?:,\s*(true|false))+\s*}', line):
        assert key_pending
        key = key_pending
        value,enabled = m.groups()
        key_pending = None
        if enabled == 'true':
            ciphers[key] = value
            cipher_pref[value] = key

with open(ff('security/nss/lib/ssl/ssl3con.c'), 'r') as fileC:
    firefox_ciphers = []
    inEnum=False
    for line in fileC:
        if not inEnum:
            if "ssl3CipherSuiteCfg cipherSuites[" in line:
                inEnum = True
            continue

        if line.startswith("};"):
            break

        if m := re.match(r'^\s*\{\s*([A-Z_0-9]+),', line):
            firefox_ciphers.append(m[1])

with open(ff('netwerk/base/security-prefs.js'), 'r') as fileB:
    enabled_ciphers = {}
    for line in fileB:
        m = re.match(r'pref\(\"([^\"]+)\"\s*,\s*(\S*)\s*\)', line)
        if not m:
            continue
        key, val = m.groups()
        if key.startswith("security.ssl3"):
            enabled_ciphers[key] = val
used_ciphers = [ciphers[k] for k, v in enabled_ciphers.items() if v == "true"]
#oSSLinclude = ('/usr/include/openssl/ssl3.h', '/usr/include/openssl/ssl.h',
#               '/usr/include/openssl/ssl2.h', '/usr/include/openssl/ssl23.h',
#               '/usr/include/openssl/tls1.h')
oSSLinclude = ['ssl3.h', 'ssl.h'
               'ssl2.h', 'ssl23.h',
               'tls1.h']

with open(ff('security/nss/lib/ssl/sslproto.h'), 'r') as sslProto:
    sslProtoD = {}

    for line in sslProto:
        if m := re.match('#define\s+(\S+)\s+(\S+)', line):
            key, value = m.groups()
            sslProtoD[key] = value
cipher_codes = [sslProtoD[x].lower() for x in used_ciphers]
####
# Now read through all the openssl include files, and try to find the openssl
# macro names for those files.
openssl_macro_by_hex = {}
all_openssl_macros = {}
for fl in oSSLinclude:
    fname = ossl(f"include/openssl/{fl}")
    if not os.path.exists(fname):
        continue
    with open(fname, 'r') as fp:
        for line in fp.readlines():
            if m := re.match('# *define\s+(\S+)\s+(\S+)', line):
                value,key = m.groups()
                if key.startswith('0x') and "_CK_" in value:
                    key = key.replace('0x0300','0x').lower()
                    #print "%s %s" % (key, value)
                    openssl_macro_by_hex[key] = value
                all_openssl_macros[value]=key
# Now generate the output.
print("""\
/* This is an include file used to define the list of ciphers clients should
 * advertise.  Before including it, you should define the CIPHER and XCIPHER
 * macros.
 *
 * This file was automatically generated by get_mozilla_ciphers.py.
 */""")
# Go in order by the order in CipherPrefs
for firefox_macro in firefox_ciphers:

    try:
        js_cipher_name = cipher_pref[firefox_macro]
    except KeyError:
        # This one has no javascript preference.
        continue

    # The cipher needs to be enabled in security-prefs.js
    if enabled_ciphers.get(js_cipher_name, 'false') != 'true':
        continue

    hexval = sslProtoD[firefox_macro].lower()

    try:
        openssl_macro = openssl_macro_by_hex[hexval.lower()]
        openssl_macro = openssl_macro.replace("_CK_", "_TXT_")
        if openssl_macro not in all_openssl_macros:
            raise KeyError()
        format = {'hex':hexval, 'macro':openssl_macro, 'note':""}
    except KeyError:
        # openssl doesn't have a macro for this.
        format = {
            'hex': hexval,
            'macro': firefox_macro,
            'note': f"/* No openssl macro found for {hexval}" + " */\n",
        }


    res = """\
%(note)s#ifdef %(macro)s
    CIPHER(%(hex)s, %(macro)s)
#else
   XCIPHER(%(hex)s, %(macro)s)
#endif""" % format
    print(res)
