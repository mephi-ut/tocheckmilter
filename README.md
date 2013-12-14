tocheckmilter
===============

Disallows mail with too many domains in "To" field.

Any questions?
 - IRC: ircs://irc.campus.mephi.ru/#mephi,xai,xaionaro
 - email: <dyokunev@ut.mephi.ru> 0x8E30679C


options
-------

 - -p /path/to/unix/socket - path to unix socket to communicate with MTA.
 - -t timeout - timeout in seconds of communicating with MTA.
 - -l limit - limit of domains in "To" field
 - -H - check only HTML-like letters (with "\nContent-Type: text/html" in body)
 - -N - check mail only from new senders (in "MAIL FROM")
 - -d - dry run (don't reject mail)
 - -B - check mail from blacklisted senders only (blacklisting status is
detected by "X-DNSBL-MILTER" header value left by [dnsbl-milter](https://github.com/hloeung/dnsbl-milter "dnsbl-milter"))
 - -h - help

