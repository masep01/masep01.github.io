---
layout: post
title: What is DMARC, DKIM and SPF?
date: 2024-03-01 +0100
categories: [Notes, Spoofing]
tags: [spoofing, cloud, notes, wiki, mail]
---

**DMARC, DKIM and SPF** are three different authenticacion methods for electronic mail. They all try to prevent from spammers, phishing and spoofing techniques.


## SPF
**Sender Policy Framework (SPF)** is an email authentication method which defines which SMTP servers are authorized to send mail from the email sender's domain.  

SPF uses **DNS** records to ensure that. Recievers can verify SPF information in **TXT** records and therefore reject messages from unauthorized sources **before recieving the body of the message**.  

### SPF Mechanisms

|  Name  |    Description    |
|--------|-------------------|
|ALL     |Matches always.    |
|A		 |Match if the domain name has an address record that can be resolved to the sender's address.|
|IP4     |Match if the sender is in a given IPv4 address range.|
|IP6	 |Match if the sender is in a given IPv6 address range.|
|MX	     |Match if the domain name has an MX record resolving to the sender's address.|
|PTR	 |Match if the domain name for the client's address is in given domain and that domain name resolves to the client's address (forward-confirmed reverse DNS). **Not recommended!**|
|EXISTS |Match if the given domain name resolves to any address.|
|INCLUDE|References the policy of another domain.|
|REDIRECT|This is a pointer to other domain name that hosts an SPF policy.|

### Qualifiers
Each mechanism may be prefixed by one of the following prefixes to define the wanted result:
* `+` Means **PASS** result. Assumed **by default**.  
* `?` Represents **NEUTRAL** result. (Similar to **NONE**).  
* `~` Denotes **SOFTAIL**, middle ground between **NEUTRAL** and **FAIL**. Emails recieved with this qualifier are tipically accepted but marked as it.  
* `-` Indicates **FAIL**. Suggesting that the email should be rejected.

There is an example of the **SPF policy of** `google.com`:
```
dig txt google.com | grep spf
google.com.             235     IN      TXT     "v=spf1 include:_spf.google.com ~all"

dig txt _spf.google.com | grep spf
; <<>> DiG 9.11.3-1ubuntu1.7-Ubuntu <<>> txt _spf.google.com
;_spf.google.com.               IN      TXT
_spf.google.com.        235     IN      TXT     "v=spf1 include:_netblocks.google.com include:_netblocks2.google.com include:_netblocks3.google.com ~all"

dig txt _netblocks.google.com | grep spf
_netblocks.google.com.  1606    IN      TXT     "v=spf1 ip4:35.190.247.0/24 ip4:64.233.160.0/19 ip4:66.102.0.0/20 ip4:66.249.80.0/20 ip4:72.14.192.0/18 ip4:74.125.0.0/16 ip4:108.177.8.0/21 ip4:173.194.0.0/16 ip4:209.85.128.0/17 ip4:216.58.192.0/19 ip4:216.239.32.0/19 ~all"

dig txt _netblocks2.google.com | grep spf
_netblocks2.google.com. 1908    IN      TXT     "v=spf1 ip6:2001:4860:4000::/36 ip6:2404:6800:4000::/36 ip6:2607:f8b0:4000::/36 ip6:2800:3f0:4000::/36 ip6:2a00:1450:4000::/36 ip6:2c0f:fb50:4000::/36 ~all"

dig txt _netblocks3.google.com | grep spf
_netblocks3.google.com. 1903    IN      TXT     "v=spf1 ip4:172.217.0.0/19 ip4:172.217.32.0/20 ip4:172.217.128.0/19 ip4:172.217.160.0/20 ip4:172.217.192.0/19 ip4:172.253.56.0/21 ip4:172.253.112.0/20 ip4:108.177.96.0/19 ip4:35.191.0.0/16 ip4:130.211.0.0/22 ~all"
```

For example, in `v=spf1 mx ptr ~all` 
* `v=spf1` Indicates the version.
* `mx` Authorizes IPs given in the MX record. 
* `ptr` Authorizes all domain's IP. 
* `~all` Deny all the unmatched mails with the previous. 

## DKIM
**DomainKeys Identified Mail (DKIM)** allow domain owners to sign automatically emails. DKIM uses public key cryptography. The validation is done by retrieving domain's public key from DNS. The PK is located in the domain's TXT record.

To request the key, the **domain name** and **selector** are essential. This can be found in the mail header `DKIM-Signature`, e.g., `d=gmail.com;s=123456`.

## DMARC
**Domain-based Message Authentication, Reporting & Conformance (DMARC)** tells a receiving email server what to do given the results after checking SPF and DKIM. It can instruct mail servers to quarantine emails that fail **SPF** or **DKIM** (or both), to reject such emails, or to deliver them.

**DMARC policies** are stored in **DMARC records**. A DMARC record can also contain instructions to send reports to domain administrators about which emails are passing and failing these checks.

### DMARC Policies
As explained above, a **DMARC policy** determines what happens to an email after it is checked against SPF and DKIM records.

Example.com's domain policy could be:

`If an email fails the DKIM and SPF tests, mark it as spam.`

That DMARC policy would actually look like:

`v=DMARC1; p=quarantine; adkim=s; aspf=s;`

### DMARC Tags

| Tag Name | Purpose                                       | Sample                         |  
|---------|-----------------------------------------------|---------------------------------|  
|v        | Protocol version                              | v=DMARC1                        |  
|pct      | Percentage of messages subjected to filtering | pct=20                          |  
|ruf      | Reporting URI for forensic reports            | ruf=mailto:authfail@example.com |  
|rua      | Reporting URI of aggregate reports            | rua=mailto:aggrep@example.com   |  
|p        | Policy for organizational domain              | p=quarantine                    |  
|sp       | Policy for subdomains of the OD               | sp=reject                       |  
|adkim    | Alignment mode for DKIM                       | adkim=s                         |  
|aspf     | Alignment mode for SPF                        | aspf=r                          |  

To obtain the DMARC record, you need to query the `subdomain _dmarc`.
```
# Reject
dig _dmarc.facebook.com txt | grep DMARC
_dmarc.facebook.com.	3600	IN	TXT	"v=DMARC1; p=reject; rua=mailto:a@dmarc.facebookmail.com; ruf=mailto:fb-dmarc@datafeeds.phishlabs.com; pct=100"

# Quarantine
dig _dmarc.google.com txt | grep DMARC
_dmarc.google.com.	300	IN	TXT	"v=DMARC1; p=quarantine; rua=mailto:mailauth-reports@google.com"

# None
dig _dmarc.bing.com txt | grep DMARC
_dmarc.bing.com.	3600	IN	TXT	"v=DMARC1; p=none; pct=100; rua=mailto:BingEmailDMARC@microsoft.com;"
```


## References
[Cloudflare](https://www.cloudflare.com/learning/email-security/dmarc-dkim-spf)  
[Wikipedia](https://en.wikipedia.org/wiki/Sender_Policy_Framework)  
[HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smtp)

