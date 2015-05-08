import re
import smtplib
import logging
import socket
import json
from os.path import isfile

# Validate Email Function (https://pypi.python.org/pypi/validate_email)--------------------------------

# Constants below used to verify valid email address formats
WSP = r'[ \t]'  # see 2.2.2. Structured Header Field Bodies
CRLF = r'(?:\r\n)'  # see 2.2.3. Long Header Fields
NO_WS_CTL = r'\x01-\x08\x0b\x0c\x0f-\x1f\x7f'  # see 3.2.1. Primitive Tokens
QUOTED_PAIR = r'(?:\\.)'  # see 3.2.2. Quoted characters
FWS = r'(?:(?:' + WSP + r'*' + CRLF + r')?' + WSP + r'+)'  # see 3.2.3. Folding white space and comments
CTEXT = r'[' + NO_WS_CTL + r'\x21-\x27\x2a-\x5b\x5d-\x7e]'  # see 3.2.3
CCONTENT = r'(?:' + CTEXT + r'|' + QUOTED_PAIR + r')'  # see 3.2.3
COMMENT = r'\((?:' + FWS + r'?' + CCONTENT + r')*' + FWS + r'?\)'  # see 3.2.3
CFWS = r'(?:' + FWS + r'?' + COMMENT + ')*(?:' + FWS + '?' + COMMENT + '|' + FWS + ')'  # see 3.2.3
ATEXT = r'[\w!#$%&\'\*\+\-/=\?\^`\{\|\}~]'  # see 3.2.4. Atom
ATOM = CFWS + r'?' + ATEXT + r'+' + CFWS + r'?'  # see 3.2.4
DOT_ATOM_TEXT = ATEXT + r'+(?:\.' + ATEXT + r'+)*'  # see 3.2.4
DOT_ATOM = CFWS + r'?' + DOT_ATOM_TEXT + CFWS + r'?'  # see 3.2.4
QTEXT = r'[' + NO_WS_CTL + r'\x21\x23-\x5b\x5d-\x7e]'  # see 3.2.5. Quoted strings
QCONTENT = r'(?:' + QTEXT + r'|' + QUOTED_PAIR + r')'  # see 3.2.5
QUOTED_STRING = CFWS + r'?' + r'"(?:' + FWS + r'?' + QCONTENT + r')*' + FWS + r'?' + r'"' + CFWS + r'?'
LOCAL_PART = r'(?:' + DOT_ATOM + r'|' + QUOTED_STRING + r')'  # see 3.4.1. Addr-spec specification
DTEXT = r'[' + NO_WS_CTL + r'\x21-\x5a\x5e-\x7e]'  # see 3.4.1
DCONTENT = r'(?:' + DTEXT + r'|' + QUOTED_PAIR + r')'  # see 3.4.1
DOMAIN_LITERAL = CFWS + r'?' + r'\[' + r'(?:' + FWS + r'?' + DCONTENT + r')*' + FWS + r'?\]' + CFWS + r'?'  # see 3.4.1
DOMAIN = r'(?:' + DOT_ATOM + r'|' + DOMAIN_LITERAL + r')'  # see 3.4.1
ADDR_SPEC = LOCAL_PART + r'@' + DOMAIN  # see 3.4.1

# A valid address will match exactly the 3.4.1 addr-spec.
VALID_ADDRESS_REGEXP = '^' + ADDR_SPEC + '$'

MX_DNS_CACHE = {}
MX_CHECK_CACHE = {}

try:
    import DNS

    ServerError = DNS.ServerError
    DNS.DiscoverNameServers()
except (ImportError, AttributeError):
    DNS = None

    class ServerError(Exception):
        pass


def get_mx_ip(hostname):
    if hostname not in MX_DNS_CACHE:
        try:
            MX_DNS_CACHE[hostname] = DNS.mxlookup(hostname)
        except ServerError as e:
            if e.rcode == 3:  # NXDOMAIN (Non-Existent Domain)
                MX_DNS_CACHE[hostname] = None
            else:
                raise

    return MX_DNS_CACHE[hostname]


def validate_email(email, check_mx=False, verify=False, debug=False, smtp_timeout=5):
    """Indicate whether the given string is a valid email address
    according to the 'addr-spec' portion of RFC 2822 (see section
    3.4.1).  Parts of the spec that are marked obsolete are *not*
    included in this test, and certain arcane constructions that
    depend on circular definitions in the spec may not pass, but in
    general this should correctly identify any email address likely
    to be in use as of 2011."""
    if debug:
        logger = logging.getLogger('validate_email')
        logger.setLevel(logging.DEBUG)
    else:
        logger = None

    try:
        assert re.match(VALID_ADDRESS_REGEXP, email) is not None
        check_mx |= verify
        if check_mx:
            if not DNS:
                raise Exception('For check the mx records or check if the email exists you must '
                                'have installed pyDNS python package')
            hostname = email[email.find('@') + 1:]
            mx_hosts = get_mx_ip(hostname)
            if not mx_hosts:
                return False
            for mx in mx_hosts:
                try:
                    if not verify and mx[1] in MX_CHECK_CACHE:
                        return MX_CHECK_CACHE[mx[1]]

                    # Port can be specified here
                    smtp1 = smtplib.SMTP(timeout=smtp_timeout, port=None)
                    smtp1.connect(mx[1])
                    MX_CHECK_CACHE[mx[1]] = True
                    if not verify:
                        try:
                            smtp1.quit()
                        except smtplib.SMTPServerDisconnected:
                            pass
                        return True
                    status, x = smtp1.helo()
                    if status != 250:
                        smtp1.quit()
                        continue
                    smtp1.mail('')
                    status, x = smtp1.rcpt(email)
                    if status == 250:
                        smtp1.quit()
                        return True
                    smtp1.quit()
                except smtplib.SMTPServerDisconnected:  # Server does not permit verify user
                    return "Verification Not Permitted"
                    if debug:
                        logger.debug(u'%s disconnected.', mx[1])
                except smtplib.SMTPConnectError:
                    if debug:
                        logger.debug(u'Unable to connect to %s.', mx[1])
            return status
    except AssertionError:
        return False
    except (ServerError, socket.error) as e:
        print e
        return None
    return True


# Begin Email Searcher--------------------------------------------------------------------------------------------------

# Basic email address formats are inputte below
if not isfile("addressFormats.json"):
    addressFormats = ["\"%s%s@%s\" % (firstName, lastName, domain)", "\"%s.%s@%s\" % (firstName, lastName, domain)",
                      "\"%s.%s@%s\" % (lastName, firstName, domain)", "\"%s.%s@%s\" % (firstName[0], lastName, domain)",
                      "\"%s_%s@%s\" % (firstName, lastName, domain)", "\"%s_%s@%s\" % (firstName[0], lastName, domain)",
                      "\"%s-%s@%s\" % (firstName, lastName, domain)", "\"%s-%s@%s\" % (firstName[0], lastName, domain)",
                      "\"%s%s@%s\" % (firstName[0], lastName, domain)", "\"%s@%s\" % (lastName, domain)",
                      "\"%s@%s\" % (firstName, domain)", "\"%s%s@%s\" % (firstName[0], lastName[0], domain)"]
    otherFormats = []
else:
    addressFormats = json.load(open("addressFormats.json", "rb"))
    otherFormats = json.load(open("otherFormats.json", "rb"))
quitting = False

# Basic program menu functions begin below.
while not quitting:
    print "Email Searcher\n"
    choice = input("(1) Start\n(2) Search Options\n(3) Quit\n")

    if choice == 1:
        restart = True
        while restart:
            firstName = raw_input("First Name:").lower()
            lastName = raw_input("Last Name:").lower()
            domain = raw_input("Domain:").lower()

            for addressFormat in addressFormats:
                try:
                    # Verify email function is called here:
                    is_valid = validate_email(eval(addressFormat), verify=True, smtp_timeout=3)
                except Exception, err:
                    print "Error: ", err
                    continue
                if is_valid == "Verification Not Permitted":
                    print "Verification not permitted by domain"
                    continue
                if is_valid is True:
                    print "*", eval(addressFormat), "= True"
                elif is_valid == 550:
                    print eval(addressFormat), "= Does Not Exist"
                elif type(is_valid) == int:
                    print eval(addressFormat), "= I'm not sure", ", SMTP Response Status = ", is_valid
                else:
                    print eval(addressFormat), "= None"

            print "------------------------------------------------"
            choice = raw_input("Continue?\n(1) Y\n(2) N\n")
            if choice.lower() == "y" or choice == 1:
                restart = True
            elif choice.lower() == "n" or choice == 2:
                restart = False
            else:
                continue
    elif choice == 2:
        firstName = "john"
        lastName = "doe"
        domain = "gmail.com"
        i = 0
        options = True
        while options:
            print "Email Address Formats\n(ex: First Name: {0:s}   Last Name: {1:s}   Domain: {2:s})".format(firstName,
                                                                                                             lastName,
                                                                                                             domain)
            i = 0
            for addressFormat in addressFormats:
                i += 1
                print "(%2d)" % i, eval(addressFormat)
            print "-----------------------------------------------------------------------------------"
            choice = input("Would you like to add or remove address formats:\n(1) Add\n(2) Remove\n(3) Exit\n")
            if choice == 1:
                if len(otherFormats) != 0:
                    i = 0
                    print "Additional email address formats"
                    for addressFormat in otherFormats:
                        i += 1
                        print "(%2d)" % i, eval(addressFormat)
                    print "----------------------------------------------------------------------------"
                    choice = input("Which format would you like to add?\n")
                    addressFormats.append(otherFormats[choice - 1])
                    del otherFormats[choice - 1]
                else:
                    print "No email address formats to add"
                    raw_input()
            elif choice == 2:
                choice = input("Which format would you like to remove? (1-%d)\n" % len(addressFormats))
                otherFormats.append(addressFormats[choice - 1])
                del addressFormats[choice - 1]
            elif choice == 3:
                options = False
    elif choice == 3:
        quitting = True

json.dump(addressFormats, open("addressFormats.json", "wb"))
json.dump(otherFormats, open("otherFormats.json", "wb"))