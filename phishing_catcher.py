#!/usr/bin/env python
# Copyright (c) 2017 @x0rz
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
import certstream
import tqdm
import entropy
import smtplib
import string
import dns.resolver

log_suspicious = 'suspicious_domains.log'

suspicious_keywords = [
    'login',
    'log-in',
    'account',
    'verification',
    'verify',
    'support',
    'activity',
    'authorize',
    'security',
    'update',
    'authentication',
    'authenticate',
    'wallet',
    'alert',
    'purchase',
    'transaction',
    'recover',
    'live',
    'office',
    'federal',
    'benefit',
    'wordpress',
    'sprint',
    'apple',
    'phishing',
    'target',
    'income'
    ]

highly_suspicious = [
    'paypal',
    'paypol',
    'poypal',
    'twitter',
    'appleid',
    'gmail',
    'outlook',
    'protonmail',
    'amazon',
    'facebook',
    'microsoft',
    'windows',
    'cgi-bin',
    'localbitcoin',
    'icloud',
    'iforgot',
    'isupport',
    'kraken',
    'bitstamp',
    'bittrex',
    'blockchain',
    '.com-',
    '-com.',
    '.net-',
    '.org-',
    '.gov-',
    '.gouv-',
    '-gouv-',
    'hack',
    'password',
    'bank',
    'chase',
    'wells-fargo',
    'citigroup',
    'equifax',
    'goldman',
    'morganstanley',
    'wellsfargo',
    'morgan-stanley',
    'bancorp',
    'capitalone',
    'capital-one',
    'tdbank',
    'td-bank',
    't-d-bank',
    'financial',
    'hsbc',
    'trump',
    'google',
    'slack',
    'itunes',
    'linkedin',
    'yahoo',
    'reddit',
    'tmall',
    'yandex',
    'netflix',
    'pornhub',
    'ebay',
    'alipay',
    'etsy',
    'microsoft',
    'tmobile',
    't-mobile',
    'metropcs',
    'walmart',
    'wal-mart',
    'bestbuy',
    'best-buy',
    'support',
    'download'
    ]

suspicious_tld = [
    '.top',
    '.bank',
    '.stream',
    '.loan',
    '.download',
    '.online',
    '.win'
    ]

pbar = tqdm.tqdm(desc='certificate_update', unit='cert')


def sendmail(domain, toaddr):
    """Python SMTP"""
    fromaddr = ""
    frompass = ""
    host = "localhost"
    subject = "Possible malicious site: " + domain
    text = "The domain " + domain + " was detected on your network as possibly malicious.\n\nThis is a python script using certstream to detect suspicious domains.  While not foolproof, this domain was detected as possibly fraudulent."
    body = string.join((
        "From: %s" % fromaddr,
        "To: %s" % toaddr,
        "Subject: %s" % subject ,
        "",
        text
        ), "\r\n")
    server = smtplib.SMTP('localhost')
    server.login(fromaddr, frompass)
    server.set_debuglevel(1)
    server.sendmail(fromaddr, toaddr, body)
    server.quit()


def checkcf(domain):
    """Check if cloudflare and write to logs or email abuse@ for certain nameservers"""
    domain = domain.rstrip()
    if domain[:2] == '*.':
        domain = domain[2:]
    if domain[:4] == 'www.':
        domain = domain[4:]
    answers = dns.resolver.query(domain, 'NS')
    nserver = []
    for rdata in answers:
        nserver.append(rdata.target.to_text())

    if answers:
        if any("ns.cloudflare.com" in s.lower() for s in nserver):
            with open('cloudflare.txt', 'a') as f:
                f.write(domain + '\n' + ', '.join(nserver) + "\n\n")
        elif any("inmotionhosting.com" in s.lower() for s in nserver):
            #sendmail(domain, "abuse@inmotionhosting.com")
            print "email abuse"
        elif any("webhostinghub.com" in s.lower() for s in nserver):
            #sendmail
            print "email abuse"
        elif any("servconfig.com" in s.lower() for s in nserver):
            #sendmail(domain, "abuse@inmotionhosting.com")
            print "email abuse"
        else:
            with open('notcloudflare.txt', 'a') as f:
                f.write(domain + '\n' + ', '.join(nserver) + "\n\n")


def score_domain(domain):
    """Score `domain`.
    The highest score, the most probable `domain` is a phishing site.
    Args:
        domain (str): the domain to check.
    Returns:
        int: the score of `domain`.
    """
    score = 0
    mult = 1
    for tld in suspicious_tld:
        if domain.endswith(tld):
            score += 20
            mult += 1
    for keyword in suspicious_keywords:
        if keyword in domain:
            score += 25
            mult += 1
    for keyword in highly_suspicious:
        if keyword in domain:
            score += 60
            mult += 1
    score += (int(round(entropy.shannon_entropy(domain)*50))) * mult

    # Lots of '-' (ie. www.paypal-datacenter.com-acccount-alert.com)
    if 'xn--' not in domain and domain.count('-') >= 4:
        score += 20
    return score


def callback(message, context):
    """Callback handler for certstream events."""
    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']

        for domain in all_domains:
            pbar.update(1)
            score = score_domain(domain)
            if score > 100:
                tqdm.tqdm.write(
                    "\033[91mSuspicious: "
                    "\033[4m{}\033[0m\033[91m (score={})\033[0m".format(domain,
                                                                        score))
                with open(log_suspicious, 'a') as f:
                    f.write("{}\n".format(domain))
                    checkcf(domain)
            elif score > 200:
                tqdm.tqdm.write(
                    "Potential: "
                    "\033[4m{}\033[0m\033[0m (score={})".format(domain, score))


certstream.listen_for_events(callback)
