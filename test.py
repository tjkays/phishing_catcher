import dns.resolver

answers = dns.resolver.query('google.com', 'NS')
for rdata in answers:
    print rdata
