# website scan
import copy
import json
from datetime import datetime
import ssl
import socket
import OpenSSL
import tldextract
import re
import whois
import requests
from urllib.parse import urlparse
from huggingface_hub import InferenceClient
import os
import requests
from .models import *
# from .utils import scan_file
with open('/etc/config.json') as file:
    config = json.load(file)


def is_url_shortened(url):
    shortener_domains = ["bit.ly", "tinyurl.com", "goo.gl", ]
    return any(shortener in url for shortener in shortener_domains)


def unshorten_url(short_url):
    try:
        response = requests.head(short_url, allow_redirects=True, timeout=10)
        return response.url
    except requests.RequestException as e:
        return False


def getAIResponse(system, prompt):
    # try:
    #     from openai import OpenAI
    #
    #     client = OpenAI(
    #         base_url="https://f3smmrjpunu5y79e.us-east-1.aws.endpoints.huggingface.cloud/v1/",
    #         api_key=config.get('HUGGINGFACE_KEY')
    #     )
    #
    #     chat_completion = client.chat.completions.create(
    #         model="tgi",
    #         messages=[
    #             {
    #                 "role": "system",
    #                 "content": system
    #             },
    #             {
    #                 "role": "user",
    #                 "content": prompt
    #             }
    #         ],
    #         stream=True,
    #         max_tokens=800
    #     )
    #     fd = ""
    #     for message in chat_completion:
    #         fd += message.choices[0].delta.content
    #     return fd
    #     # API_URL = "https://f3smmrjpunu5y79e.us-east-1.aws.endpoints.huggingface.cloud"
    #     # headers = {
    #     #     "Accept": "application/json",
    #     #     "Authorization": "Bearer config.get('HUGGINGFACE_KEY'),
    #     #     "Content-Type": "application/json"
    #     # }
    #     #
    #     # def query(payload):
    #     #     response = requests.post(API_URL, headers=headers, json=payload)
    #     #     return response.json()
    #     #
    #     # output = query({
    #     #     "inputs": prompt,
    #     #     "parameters": {
    #     #         "return_full_text": False
    #     #     }
    #     # })
    #     # print(output)
    #     # return output[0]['generated_text'].split('\n\n')[-1]
    # except Exception as e:
    #     print(e)
    try:
        client = InferenceClient(
            # "meta-llama/Meta-Llama-3-8B-Instruct",
            "mistralai/Mistral-7B-Instruct-v0.3",
            # token=config.get('HUGGINGFACE_API_KEY')[0],
            token= config.get('HUGGINGFACE_KEY'),
        )
        full_response = ""

        for message in client.chat_completion(
                messages=[{"role": "user",
                           "content": system + prompt}],
                max_tokens=800,
                stream=True,
        ):
            full_response += message.choices[0].delta.content
        return full_response
    except Exception as e:
        print('error', e)
        return None


def get_ssl_certificate_response(status, certificate_details=None):
    """
    Returns a dictionary with SSL certificate status and relevant information.

    :param status: The status of the SSL certificate (e.g., 'valid', 'expired', 'invalid', 'not_present').
    :param certificate_details: Optional dictionary containing details about the certificate.
    :return: A dictionary with status, explanation, and recommendations.
    """
    response = {
        'status': status,
        'details': '',
        'recommendations': []
    }

    if status == 'valid':
        response[
            'details'] = 'The SSL certificate is valid. This means that the connection between your browser and the website is encrypted and secure.'

    elif status == 'expired':
        response[
            'details'] = 'The SSL certificate has expired. This means that the website’s security certificate is no longer valid, and the connection is not secure.'

    elif status == 'invalid':
        response[
            'details'] = 'The SSL certificate is invalid. This can occur due to a variety of reasons, such as incorrect configuration or an untrusted certificate authority.'

    elif status == 'not_present':
        response[
            'details'] = 'No SSL certificate is found for the provided domain. This means that the site does not encrypt data between your browser and the server, leaving information vulnerable to interception.'
    elif status == 'domain_mismatch':
        response[
            'details'] = 'The SSL certificate does not match the domain name. This means that the certificate is not valid for the domain you are trying to visit, which could indicate a potential security risk or misconfiguration.'

    elif status == 'ocsp_invalid':
        response[
            'details'] = 'The Online Certificate Status Protocol (OCSP) response for the SSL certificate is invalid. This means that the certificate’s revocation status could not be confirmed, which may indicate a problem with the certificate status checking mechanism.'

    else:
        response['details'] = 'Unknown status. There may be an error in retrieving the SSL certificate information.'

    return response


def assess_risk(ssl_status, domain_registration, redirect_status, website_reputation):
    risk = 'Safe'

    # SSL Certificate Risk
    if ssl_status in ['invalid', 'not_present']:
        risk = 'Dangerous'
    elif ssl_status == 'expired':
        risk = 'Moderate'

    # Domain Registration Risk
    if domain_registration == 'suspicious':
        risk = 'Dangerous'
    elif domain_registration == 'recent':
        risk = 'Moderate'

    # Redirects Risk
    if redirect_status == 'malicious':
        risk = 'Dangerous'
    elif redirect_status == 'non_secure':
        risk = 'Moderate'

    # Website Reputation Risk
    if website_reputation == 'negative':
        risk = 'Dangerous'
    elif website_reputation == 'mixed':
        risk = 'Moderate'

    return risk


def get_domain_info(domain):
    url_shortened = False
    risk = []
    red_flags = []

    def domainPrompt(dninf):
        syst = ("DO NOT INCLUDE INTRODUCTORY WORDS.You are an expert in scam detection, phishing, and cybersecurity. "
                "A website visitor wants to know if it is safe to access the website.I AM NOT THE OWNER OF THE WEBSITE."
                " Your task is to summarize the information, focusing on potential security concerns, red flags, and "
                "indicators of possible scams or phishing activities.Please include the following in your summary:"
                "1. **Domain Registration Details:** Look for information about the registrant, registration dates, "
                "and contact details.2. **Privacy Protection:** Note if WHOIS privacy protection is enabled and its "
                "implications.3. **Domain Age:** Comment on the age of the domain and its relevance to potential "
                "security issues.4. **Registrar Information:** Mention the registrar and any related concerns.5."
                " **Any Red Flags:** Identify any unusual patterns, such as frequent changes in registration details "
                "or domains registered with known malicious intent.Please provide a concise summary based on the "
                "provided data, highlighting any relevant security concerns or potential risks without the introductory"
                " words. DO NOT INCLUDE INTRODUCTORY WORDS. You have researched and found the following whois and "
                "domain information ")
        # syst = "You are an expert in scam detection, phishing, and cybersecurity.Analyse this"
        dninf = f"{dninf}"
        return getAIResponse(syst, dninf)

    if is_url_shortened(domain):
        url_shortened = True
        if unshorten_url(domain):
            domain_info = whois.whois(unshorten_url(domain))
        else:
            domain_info = 'Could not get the original url'
    else:
        domain_info = whois.whois(domain)
    try:
        cd = domain_info.get('creation_date')[0]
    except Exception as e:
        cd = domain_info.get('creation_date')
    try:
        ed = domain_info.get('expiration_date')[0]
    except:
        ed = domain_info.get('expiration_date')
    try:
        if (datetime.now() - cd).days <= 366:
            vl = 'day(s)'
            pr = (datetime.now() - cd).days
            if (datetime.now() - cd).days > 30:
                vl = 'month(s)'
                pr = int((datetime.now() - cd).days / 30)
            risk.append('Moderate')
            red_flags.append(f"This domain was registered recently :- on {cd.strftime('%Y-%m-%d')} ({pr} {vl} ago")
        if (ed - cd).days <= 366:
            risk.append('Moderate')
            red_flags.append(f"This domain was registered for a short period of time :- {(ed - cd).days} days")
        if domain_info.get('org'):
            if 'whois' in domain_info.get('org').lower():
                risk.append('Moderate')
                red_flags.append(
                    f"The WHOIS data for this domain is currently hidden or obscured.  While this can be a standard"
                    f" practice for protecting personal information from spam and unsolicited contact, it may also raise"
                    f" concerns about the transparency and accountability of the website")
        else:
            if domain_info.get('name'):
                if 'whois' in domain_info.get('name').lower():
                    risk.append('Moderate')
                    red_flags.append(
                        f"The WHOIS data for this domain is currently hidden or obscured.  While this can be a standard"
                        f" practice for protecting personal information from spam and unsolicited contact, it may also raise"
                        f" concerns about the transparency and accountability of the website")
            else:
                risk.append('Moderate')
                red_flags.append(
                    f"The WHOIS data for this domain is currently hidden or obscured.  While this can be a standard"
                    f" practice for protecting personal information from spam and unsolicited contact, it may also raise"
                    f" concerns about the transparency and accountability of the website")
        value = domain_info.get('domain_name')
        dmname = []
        if isinstance(value, list):
            dmname = domain_info.get('domain_name')
        elif isinstance(value, str):
            dmname = [domain_info.get('domain_name')]
        dninf = {
            'isUrlShortened': url_shortened,
            'domain_name': dmname,
            'registrar': domain_info.get('registrar'),
            'whois_server': domain_info.get('whois_server'),
            'creation_date': cd.strftime('%Y-%m-%d'),
            'expiration_date': ed.strftime('%Y-%m-%d'),
            'emails': domain_info.get('emails'),
            'name': domain_info.get('name'),
            'org': domain_info.get('org'),
            'address': domain_info.get('address'),
            'city': domain_info.get('city'),
            'state': domain_info.get('state'),
            'registrant_postal_code': domain_info.get('registrant_postal_code'),
            'country': domain_info.get('country'),
            'red_flags': red_flags,

        }
        return {
            'isUrlShortened': url_shortened,
            'success': True,
            'domain_name': dmname,
            'registrar': domain_info.get('registrar'),
            'whois_server': domain_info.get('whois_server'),
            'creation_date': cd.strftime('%Y-%m-%d'),
            'expiration_date': ed.strftime('%Y-%m-%d'),
            # 'nameservers': domain_info.get('name_servers'),
            'emails': domain_info.get('emails'),
            'name': domain_info.get('name'),
            'org': domain_info.get('org'),
            'address': domain_info.get('address'),
            'city': domain_info.get('city'),
            'state': domain_info.get('state'),
            'registrant_postal_code': domain_info.get('registrant_postal_code'),
            'country': domain_info.get('country'),
            'summary': domainPrompt(dninf),
            'domainRisk': 'Safe' if risk == [] else 'Moderate',
            'red_flags': red_flags,

        }
    except Exception as e:
        return {
            'isUrlShortened': url_shortened,
            'domain_name': None,
            # 'summary': getAIResponse("NO information about the domain "),
            'success': False,
            'domainRisk': 'Uknown'
        }


# # # Usage
# domain = "https://z6a.info/governmentdox.vbs!RSiTx+5wis5lottowinner.dmg"
# domain_info = get_domain_info(domain)
# print(domain_info)
def check_ssl_cert(domain):
    red_flags = []
    green_flags = []

    def extract_domain(url_):
        dm = tldextract.extract(url_).domain
        sf = tldextract.extract(url_).suffix
        return f'{dm}.{sf}'

    domain = extract_domain(domain)
    print(domain)

    def passSSL():
        return (
            "DO NOT INCLUDE INTRODUCTORY WORDS.You are an expert in scam detection, phishing, and cybersecurity."
            " I am a website visitor and want to know if it is safe to access.I AM NOT THE OWNER OF THE WEBSITE."
            " I will provide you with details about an SSL certificate. Summarize the information focusing on potential"
            " security concerns, red flags, and indicators of possible vulnerabilities or issues with the certificate."
            "Include in the summary:"

            "Certificate Status: Whether the certificate is valid, expired, invalid, or not present."
            "Expiration Date: When the certificate is set to expire (if applicable)."
            "Issuer: The organization that issued the certificate."
            "Domain Mismatch: Indicate if the certificate’s domain does not match the intended domain."
            "Certificate Chain: Whether the certificate chain is complete or if there are issues with intermediate certificates."
            "Red Flags if any: Issues such as expired certificates, domain mismatches, incomplete certificate chains, or missing certificates."
            "Here is the SSL certificate gathered data:"
            "Provide a concise summary that highlights any relevant security concerns or potential risks, without any introductory phrases.  DO NOT INCLUDE INTRODUCTORY WORDS")

    try:
        risk = []
        context = ssl.create_default_context()
        context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3  # Disable outdated protocols
        port = 443

        # Create an SSL context with TLS settings
        with socket.create_connection((domain, port)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # Retrieve the server certificate
                cert_pem = ssock.getpeercert(binary_form=False)
                cert = ssl.DER_cert_to_PEM_cert(ssock.getpeercert(binary_form=True))
                # Load the certificate using OpenSSL
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
                sslStatus = 'Valid'

                def check_ssl_expiry():
                    expiry_date = datetime.strptime(x509.get_notAfter().decode('ascii'), "%Y%m%d%H%M%SZ")
                    return expiry_date

                expiry = check_ssl_expiry()
                if expiry < datetime.now():
                    sslStatus = 'Expired'
                    expired = True
                    sslValid = False
                    risk.append('Moderate')
                    if (datetime.now() - expiry).total_seconds() / 86400 >= 30:
                        risk.append('Dangerous')
                    red_flags.append(get_ssl_certificate_response(status='expired')['details'])
                else:
                    green_flags.append('The SSL certificate is valid and upto date')

                def check_ssl_issuer():
                    issuer_ = x509.get_issuer().organizationName
                    return issuer_

                issuer = check_ssl_issuer()
                trusted_cas = ['DigiCert', 'GlobalSign', 'Comodo', "Let's Encrypt", 'DigiCert Inc']
                if issuer not in trusted_cas:
                    risk.append('Moderate')
                    less_trusted = f"Certificate issued by less-known CA: {issuer}"
                    red_flags.append(less_trusted)
                else:
                    green_flags.append(f'The certificate issuer is well Known and trusted: {issuer}')

                def check_ocsp_revocation(ocsp_url):
                    if ocsp_url:
                        # Query the OCSP server
                        ocsp_response = requests.get(ocsp_url)
                        # print(ocsp_response.status_code)
                        return ocsp_response.status_code == 200  # 200 OK status means no revocation
                    else:
                        return False  # No OCSP URL found or unable to verify

                context = ssl.create_default_context()
                conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
                conn.connect((domain, 443))
                certificate = conn.getpeercert()
                modified_certificate = copy.deepcopy(certificate)

                # Check if the 'subjectAltName' field exists in the certificate
                if 'subjectAltName' in modified_certificate:
                    # Limit the SAN entries to the first 10
                    modified_certificate['subjectAltName'] = modified_certificate['subjectAltName'][:10]

                # Now you can return or process the modified certificate

                ocsp_url = certificate['OCSP'][0]
                is_valid = check_ocsp_revocation(ocsp_url)
                subject_alt_names = [dns[1] for dns in certificate['subjectAltName'] if dns[0] == 'DNS']

                def check_domain_mismatch():
                    subject = dict(x509.get_subject().get_components())
                    domain_in_cert_ = subject[b'CN'].decode('utf-8')
                    return domain_in_cert_

                domain_in_cert = check_domain_mismatch()
                cpy = [c.split('*.')[-1] for c in subject_alt_names if '*.' in c]
                dmn = domain_in_cert.lower()
                if '*.' in domain_in_cert.lower():
                    dmn = domain_in_cert.lower().split('*.')[0]
                if domain not in cpy:
                    if dmn != domain.lower():
                        risk.append('Dangerous')
                        red_flags.append(
                            f"Domain mismatch! SSL certificate is for {domain_in_cert}, but you are visiting {domain}")
                else:
                    green_flags.append(f'The domain in the certificate matches the domain you are visiting')
                if not is_valid:
                    risk.append('Moderate')
                    red_flags.append(f"The SSL certificate for {domain} might be revoked or OCSP check failed.")

                else:
                    green_flags.append(
                        f'The Online Certificate Status Protocol (OCSP) response for the SSL certificate is valid')
                if not red_flags and not risk:
                    sslRisk = 'Safe'

                else:
                    if 'Dangerous' in risk:
                        sslRisk = 'Dangerous'
                    else:
                        sslRisk = 'Moderate'
                summary = getAIResponse(passSSL(), f"{modified_certificate}")
                return {'domain_in_cert': domain_in_cert,
                        'success': True,
                        'ssl_present': True,
                        'sslStatus': sslStatus,
                        'sslRisk': sslRisk,
                        'subject_alt_names': subject_alt_names[:10],
                        'expiry': expiry.strftime('%Y-%m-%d '),
                        'cert_issuer': issuer,
                        'ocsp_validity': is_valid,
                        'red_flags': red_flags,
                        'green_flags': green_flags,
                        'summary': summary,

                        }
    except Exception as e:
        print(e)
        return {
            'success': False,
            'ssl_present': False,
            'sslStatus': 'Not Present',
            'sslRisk': 'Dangerous',
            'red_flags': red_flags.append(get_ssl_certificate_response(status='not_present')),
            'green_flags': [],
            'summary': getAIResponse(passSSL(), 'SSL IS NOT PRESENT')
        }


# # # Usage
# domain = "https://z6a.info/governmentdox.vbs!RSiTx+5wis5lottowinner.dmg"
# ssl_cert = check_ssl_cert('google.com')
# print(ssl_cert)

# print(ssl_cert)
#


def add_scheme_if_missing(url, schema_):
    # Parse the URL
    parsed_url = urlparse(url)

    # Check if the scheme is missing
    if not parsed_url.scheme:
        # Add 'https://' by default, you can use 'http://' if preferred
        return schema_ + url
    return url


def check_redirections(url):
    risk = []
    red_flags = []

    def redirectionsPrompt():
        return (
            "DO NOT INCLUDE INTRODUCTORY WORDS.You are an expert in scam detection, phishing, and cybersecurity. I am a website visitor and want to know if it is safe to access.I AM NOT THE OWNER OF THE WEBSITE. I will provide you with details about the redirection and links associated with a website. Summarize the information focusing on potential security concerns, red flags, and indicators of possible scams or phishing activities."
            "Here is the gathered data: "
            "Provide a concise summary that highlights any relevant security concerns or potential risks, without any introductory phrases.  DO NOT INCLUDE INTRODUCTORY WORDS")

    try:
        def extract_domain(url_):
            return tldextract.extract(url_).domain

        try:
            url = add_scheme_if_missing(url, 'https://')
            response = requests.get(url, allow_redirects=True)
        except:
            try:
                url = add_scheme_if_missing(url, 'http://')
                response = requests.get(url, allow_redirects=True)
            except:
                raise Exception

        status_codes = [r.status_code for r in response.history]
        num_of_redirects = len(response.history)
        redirect_ip = [bool(re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', redirect_.url)) for redirect_ in
                       response.history]
        redirect_urls = [i.url for i in response.history]
        if True in redirect_ip:
            risk.append('Dangerous')
            red_flags.append(
                'This website redirects to an IP address rather than a domain name. This can make it difficult to '
                'verify the legitimacy and ownership of the website, increasing the risk of encountering fraudulent or'
                ' malicious sites.')
            red_flags.append('Attackers often use IP address redirects to mask the true nature of their sites. This can'
                             ' be part of phishing schemes or spoofing attempts to deceive users into providing '
                             'sensitive information or credentials.')
        hasDomainChanged = [True if extract_domain(
            redirect_.url) != extract_domain(response.url) else False for redirect_ in
                            response.history]
        if True in hasDomainChanged:
            risk.append('Dangerous')
            red_flags.append('This website redirects to a different domain, which can be a red flag for potential scams'
                             ' or phishing attacks. Such domain changes may indicate attempts to deceive users or'
                             ' compromise their security. Proceed with caution and avoid entering sensitive information')
        domain_change = [f"Redirect from {redirect_.url} to {response.url} crosses domains" if extract_domain(
            redirect_.url) != extract_domain(response.url) else None for redirect_ in
                         response.history]
        url_shortened = is_url_shortened(url)
        original_url = unshorten_url(url) if is_url_shortened(url) else url

        ifi = {
            'has redirections': True if len(response.history) > 0 else False,
            'number of redirects': num_of_redirects,
            'domains redirected to': redirect_urls,
            'original domains'
            'redirect to IP': True if redirect_ip.count(True) > 0 else False,
            'redirect status codes': status_codes,
            'domain changed during redirection': True if hasDomainChanged.count(True) > 0 else False,

        }
        dt = getAIResponse(redirectionsPrompt(), f"{ifi}")
        return {
            'hasRedirections': True if len(response.history) > 0 else False,
            'numOfRedirects': num_of_redirects,
            'success': True,
            'redirectToIp': True if redirect_ip.count(True) > 0 else False,
            'warningRedirectToIp': 'Warning: Redirect to IP ' if redirect_ip.count(True) > 0 else None,
            'multipleRedirects': "Warning: Multiple temporary redirects (302) detected" if status_codes.count(
                302) > 0 else None,
            'statusCodes': status_codes,
            'domainChanged': True if hasDomainChanged.count(True) > 0 else False,
            'domains': domain_change,
            'url_shortened': url_shortened,
            'original_url': original_url,
            'redirectionRisk': 'Dangerous' if 'Dangerous' in risk else 'Safe',
            'red_flags': red_flags,
            "summary": dt

        }
    except Exception as e:
        dt = getAIResponse(redirectionsPrompt(), "This website has no redirections")

        return {'success': True,
                'hasRedirections': False,
                'numOfRedirects': 0,
                'redirectToIp': False,

                'redirectionRisk': '', 'summary': dt}


# domain = "https://z6a.info/governmentdox.vbs!RSiTx+5wis5lottowinner.dmg"
# red = check_redirections(domain)
# print(red)
def getFinalRecommendation(ssl_summary, domain_summary, redirection_summary, overall_risk):
    fprompt = (
        "DO NOT INCLUDE INTRODUCTORY WORDS.You are an expert in scam detection, phishing, and cybersecurity. I want to"
        " know if the website is safe to access.I AM NOT THE OWNER OF THE WEBSITE. I will provide you with details "
        "about"
        " the redirection and links associated with a website. Summarize the information focusing on potential security"
        " concerns, red flags, and indicators of possible scams or phishing activities."
        "Provide a concise summary that highlights any relevant security concerns or potential risks, and advice to a"
        " user who is looking to access and interact this website without any introductory phrases. "
        " DO NOT INCLUDE INTRODUCTORY WORDS. Answer this questions. Is it safe to proceed. Are thereprecautions one should take before accessing the site  ")
    dt = (f"Here is the gathered information"
          f"ssl  summary: {ssl_summary}"
          f"whois summary: {domain_summary}"
          f"redirection summary: {redirection_summary}"
          f"overall calculated risk: {overall_risk}")

    return getAIResponse(fprompt, dt)


import uuid


def generate_random_uuid():
    # Generate a random UUID (version 4)
    random_uuid = uuid.uuid4()
    return random_uuid


def analyseConversation(stage=1, sc_content=None, description='', model_res=None, users_res=None,
                        prev_prompt=None):
    if sc_content:
        screenshot_content = " ".join(sc_content)
    else:
        screenshot_content = None
    if stage == 1:
        # respnse = {
        #     "more_information": 'true/false',
        #     "follow_up_questions": '[<insert follow up questions>]',
        # }
        sys1 = " ".join(
            [
                'You are a scam analyst. DO NOT INCLUDE INTRODUCTORY WORDS, ONLY REPLY AS STRICTLY VALID JSON THAT CAN BE DECODED CORRECTLY WITHOUT ERRORS. WRAP KEYS IN DOUBLE QUOTES with the following keys . {"more_information":true/false, "follow_up_questions":[questions]}. A user has provided the following description of what happened',
                # f'You are a scam analyst. DO NOT INCLUDE INTRODUCTORY WORDS, ONLY REPLY AS STRICTLY VALID JSON with the following format .{respnse}. A user has provided the following description of what happened',
                "and conversation screenshots" if screenshot_content else "" + "for scam analysis:",
                "Based on the information, can you determine whether this is likely to be a scam?",
                "THESE ARE THE GUIDELINES YOU MUST FOLLOW",
                "1. DO NOT MAKE ASSUMPTIONS. 2.Make sure you are confident with your response. 3. STRICTLY DO NOT INCLUDE INTRODUCTORY WORDS"])

        prompt1 = " ".join([
            f"**extracted screenshot conversation: {screenshot_content}. (please Ignore special characters,replace possible names with [userX] whereX is a number alias)" if screenshot_content else "",
            f"**what happened :{description}"
        ])
        idf = generate_random_uuid()
        m_res = getAIResponse(sys1, prompt1)
        sc = ScamAnalysis(
            identifier=idf,
            first_prompt=sys1 + prompt1,
            first_response=m_res
        )
        sc.save()
        return idf, m_res

    else:

        sys1 = "You are a scam analyst. DO NOT INCLUDE INTRODUCTORY WORDS, ONLY REPLY AS STRICTLY VALID JSON THAT CAN BE DECODED CORRECTLY WITHOUT ERRORS. WRAP KEYS IN DOUBLE QUOTES. with the following format:'do_you_think_this_is_a_scam':true/false,'reasons_for_the_answer':[], 'scam_type':'type',definition_of_scam:'brief summary',variants_of_scam:[scam variants],'ways_to_protect_yourself:[ways], what_to_do_if_fallen_victim:[what to do],what_to_watch_out_for:'what_to_watch_out_for'.Below is a continuation of the previous conversation."
        # sys1 = f"You are a scam analyst. DO NOT INCLUDE INTRODUCTORY WORDS, ONLY REPLY AS STRICTLY VALID JSON with the following format:{respnse}.Below is a continuation of the previous conversation."
        prompt1 = " ".join(
            [f"Here is the previous prompt {prev_prompt} your and response  {model_res}",
             f" and the users answers to your questions :{users_res}"])

        return getAIResponse(sys1, prompt1)


def verifyCompanyContact(company, user_input):
    sys1 = """
        You are a virtual assistant tasked with helping users verify contact details and ensuring they are aware of potential security risks. Your responsibilities are as follows:
    
        1. **Compare User-Provided Contacts with Official Contacts**:
                VERIFY THOROUGHLY SO AS TO NOT PROVIDE FALSE NEGATIVES OR FALSE POSTITVES.CHECK THROUGH THE INTERNET IF POSSIBLE
           - **Retrieve**: Find and list the official contact details for the specified organization. For example, if the user specifies Microsoft, obtain official contact information such as customer support, sales, and corporate headquarters.
           - **Compare**: Compare the user-provided contacts with the official contacts you retrieved. Identify any discrepancies or matches. For each user-provided contact, indicate whether it matches the official contact or if it is incorrect or unverified.
    
        2. **Provide Additional Official Contacts**:
           - **List Additional Contacts**: In addition to the user-provided contacts, provide any additional official contact details for the organization that may be relevant. This includes alternative contact methods for customer support, sales, or other departments.
    
        3. **Security Awareness**:
           - **Explain Spoofing**: Describe what spoofing is, including how fraudsters may impersonate legitimate organizations to deceive individuals.
           - **Mitigation Tips**: Provide practical tips to help users avoid falling victim to spoofing. Include advice on verifying the authenticity of contact details and recognizing potential red flags.
    
       
        **Example Response IN JSON**:
        
        'summary': {
                     'provided_contact':'user provided contact',
                     'is_contact':true/false ,
                     'results_title':'short interesting and title with company name and whether the contact is correct or not ;example Hold up! This is not Apple's contact' ,
                     'findings':'summarise what you have found out in the comparison '   
                    }
        'all_official_contacts':[
                    {'title':'Customer Support','values':['Email: support@microsoft.com','Phone: +1 (800) 642-7676']},
                                                ]//do the same for all publicly available contacts websites emails telephone address and more
    
   

        'common_scams_against_such_companies':[{'scam_name':'name','scam_description':'discuss how such scam occurs','mitigation':['Ways to avoid such scams']}
        //repeat for all possible scams associated with the area in which this company/organization operates
            ]
        
    DO NOT USE INTRODUCTORY WORDS IN YOUR FINAL RESPONSE. FORMAT IN CORRECT JSON FORMAT THAT CAN BE DECODED WITHOUT ERRORS  WRAP KEYS IN DOUBLE QUOTES. 
    """

    prompt1 = f" Organization Name : {company} -User-Provided Contacts :{user_input} "
    return getAIResponse(sys1, prompt1)
