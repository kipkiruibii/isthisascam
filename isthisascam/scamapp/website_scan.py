# website scan
from datetime import datetime
import ssl
import socket
import OpenSSL
import tldextract
import re
import whois
import requests


def is_url_shortened(url):
    shortener_domains = ["bit.ly", "tinyurl.com", "goo.gl", "t.co"]
    return any(shortener in url for shortener in shortener_domains)


def unshorten_url(short_url):
    try:
        response = requests.head(short_url, allow_redirects=True, timeout=10)
        return response.url
    except requests.RequestException as e:
        return False


def get_domain_info(domain):
    url_shortened = False
    if is_url_shortened(domain):
        url_shortened = True
        if unshorten_url(domain):
            domain_info = whois.whois(unshorten_url(domain))
            print(domain_info)
        else:
            domain_info = 'Could not get the original url'
    else:
        domain_info = whois.whois(domain)
        print(domain_info)
    try:
        cd = domain_info.get('creation_date')[0]
    except:
        cd = domain_info.get('creation_date')
    try:
        ed = domain_info.get('expiration_date')[0]
    except:
        ed = domain_info.get('expiration_date')
    try:
        return {
            'isUrlShortened': url_shortened,
            'success': True,
            'domain_name': domain_info.get('domain_name'),
            'registrar': domain_info.get('registrar'),
            'whois_server': domain_info.get('whois_server'),
            'creation_date': cd.strftime('%Y-%m-%d'),
            'expiration_date': ed.strftime('%Y-%m-%d'),
            'nameservers': domain_info.get('name_servers'),
            'emails': domain_info.get('emails'),
            'name': domain_info.get('name'),
            'org': domain_info.get('org'),
            'address': domain_info.get('address'),
            'city': domain_info.get('city'),
            'state': domain_info.get('state'),
            'registrant_postal_code': domain_info.get('registrant_postal_code'),
            'country': domain_info.get('country'),
            'registered_recently': True if ((datetime.now() - cd).days <= 366) else False,
            'time_since_reg': (datetime.now() - cd).days,
            'registered_for_short ': True if ((ed - cd).days <= 366) else False,
            'registered_for_period ': (ed - cd).days,

        }
    except:
        return {
            'isUrlShortened': url_shortened,
            'success': False,
        }


# # # Usage
# domain = "https://instagram.com"
# domain_info = get_domain_info(domain)
# print(domain_info)
def check_ssl_cert(domain):
    try:
        cert = ssl.get_server_certificate((domain, 443))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)

        def check_ssl_expiry():
            expiry_date = datetime.strptime(x509.get_notAfter().decode('ascii'), "%Y%m%d%H%M%SZ")
            return expiry_date

        expiry = check_ssl_expiry()
        expired = ''
        if expiry < datetime.now():
            expired = f"Warning: SSL certificate has expired on {expiry}"

        def check_ssl_issuer():
            issuer = x509.get_issuer().organizationName
            return issuer

        issuer = check_ssl_issuer()
        trusted_cas = ['DigiCert', 'GlobalSign', 'Comodo', "Let's Encrypt"]
        less_trusted = ''
        if issuer not in trusted_cas:
            less_trusted = f"Warning: Certificate issued by less-known CA: {issuer}"

        def check_ocsp_revocation(ocsp_url):
            if ocsp_url:
                # Query the OCSP server
                ocsp_response = requests.get(ocsp_url)
                print(ocsp_response.status_code)
                return ocsp_response.status_code == 200  # 200 OK status means no revocation
            else:
                return False  # No OCSP URL found or unable to verify

        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.connect((domain, 443))
        certificate = conn.getpeercert()
        ocsp_url = certificate['OCSP'][0]
        is_valid = check_ocsp_revocation(ocsp_url)
        subject_alt_names = [dns[1] for dns in certificate['subjectAltName'] if dns[0] == 'DNS']

        def check_domain_mismatch():
            subject = dict(x509.get_subject().get_components())
            domain_in_cert = subject[b'CN'].decode('utf-8')
            return domain_in_cert

        domain_in_cert = check_domain_mismatch()
        domain_mismatch = ''
        if domain_in_cert != domain and domain not in subject_alt_names:
            domain_mismatch = f"Warning: Domain mismatch! SSL certificate is for {domain_in_cert}, but you are visiting {domain}"

        is_valid_report = ''
        if not is_valid:
            is_valid_report = f"Warning: The SSL certificate for {domain} might be revoked or OCSP check failed."

        return {'domain_in_cert': domain_in_cert,
                'success': True,
                'domain_mismatch': domain_mismatch,
                'subject_alt_names': subject_alt_names,
                'expiry': expiry.strftime('%Y-%m-%d '),
                'expired': expired,
                'cert_issuer': issuer,
                'less_trusted': less_trusted,
                'ocsp_validity': is_valid,
                'ocsp_info': is_valid_report

                }
    except:
        return {
            'success': False,
        }


# # # Usage
# domain = "roniib.com"
# ssl_cert = check_ssl_cert(domain)
# print(ssl_cert)
#

def check_redirections(url):
    try:
        def extract_domain(url):
            return tldextract.extract(url).domain

        def extract_suffix(url):
            return tldextract.extract(url).suffix

        suspicious_suffix = ['.xyz', '.info', '.tk', '.ru', '.biz']
        response = requests.get(url, allow_redirects=True)
        status_codes = [r.status_code for r in response.history]
        num_of_redirects = len(response.history)
        redirect_ip = [bool(re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', redirect_.url)) for redirect_ in
                       response.history]
        hasDomainChanged = [True if extract_domain(
            redirect_.url) != extract_domain(response.url) else False for redirect_ in
                            response.history]
        domain_change = [f"Warning: Redirect from {redirect_.url} to {response.url} crosses domains" if extract_domain(
            redirect_.url) != extract_domain(response.url) else None for redirect_ in
                         response.history]
        suffix_change = [
            f'Warning: Redirect to suspicious TLD  {redirect_.url}' if extract_suffix(
                redirect_.url) in suspicious_suffix else None for
            redirect_ in response.history]
        url_shortened = is_url_shortened(url)
        original_url = unshorten_url(url) if is_url_shortened(url) else url
        return {
            'hasRedirections': True if len(response.history) > 0 else False,
            'numOfRedirects': num_of_redirects,
            'success': False,
            'redirectToIp': True if redirect_ip.count(True) > 0 else False,
            'warningRedirectToIp': 'Warning: Redirect to IP ' if redirect_ip.count(True) > 0 else None,
            'multipleRedirects': "Warning: Multiple temporary redirects (302) detected" if status_codes.count(
                302) > 0 else None,
            'statusCodes': status_codes,
            'domainChanged': True if hasDomainChanged.count(True) > 0 else False,
            'domains': domain_change,
            'hasSuspiciousTLD': True if (
                    len(suffix_change) > 0 and extract_suffix(url) in suspicious_suffix) else False,
            'suspiciousSuffix': f"Warning: Suspicious TLD {extract_suffix(url)}" if extract_suffix(
                url) in suspicious_suffix else None,
            'suspiciousSuffixRedirects': suffix_change,
            'url_shortened': url_shortened,
            'original_url': original_url,
        }
    except:
        return {'success': False}

