import sqlite3, urllib.parse, json
from webapp.lib.evaluategrade import *
from contextlib import closing
from urllib.parse import urlparse


def get_unique_websites():
    unique_list = []
    domain_list = []
    with closing(sqlite3.connect("results.db")) as connection:
        with closing(connection.cursor()) as cursor:
            cursor.execute("SELECT * FROM website WHERE statuscode = 200;")
            website_data = cursor.fetchall()
            duplicate_counter = 0
            for website in website_data:
                parsed_domain = urlparse(website[2]).netloc
                if parsed_domain not in domain_list:
                    domain_list.append(parsed_domain)
                    unique_list.append(website[0])
                else:
                    duplicate_counter += 1
            print("Total entries:", len(website_data), "Unique entries:", len(website_data) - duplicate_counter, "Duplicate entries:", duplicate_counter)
    return unique_list


def spacer_func():
    pass

def check_headers(id_list):
    header_counter = {'CSP': 0, 'CSP_tests_counter': {'default-src_good': 0, 'default-src_moderate': 0, 'child-src_good': 0, 'child-src_moderate': 0, 'connect-src_good': 0, 'connect-src_moderate': 0,
     'font-src_good': 0, 'font-src_moderate': 0, 'frame-src_good': 0, 'frame-src_moderate': 0, 'img-src_good': 0, 'img-src_moderate': 0, 'manifest-src_good': 0, 
     'manifest-src_moderate': 0, 'media-src_good': 0, 'media-src_moderate': 0, 'object-src_good': 0, 'object-src_moderate': 0, 'script-src_good': 0, 'script-src_moderate': 0, 
     'style-src_good': 0, 'style-src_moderate': 0, 'worker-src_good': 0, 'worker-src_moderate': 0, 'report-to/uri': 0,
     'base-uri_good': 0, 'base-uri_moderate': 0, 'form-action_good': 0, 'form-action_moderate': 0, 'frame-ancestors_good': 0, 'frame-ancestors_moderate': 0, 'sandbox': 0, 'upgrade-insecure-requests': 0}, 'X-Xss-Protection': 0, 
     'X-Xss-protection_tests_counter': {'xss_filter_enabled': 0, 'xss_filter_block_mode': 0} ,'HSTS': 0, 'HSTS_tests_counter': {'max-age_good': 0, 'max-age_moderate': 0, 'includesubdomains': 0, 'preload': 0},
     'X-Content-Type-Options': 0, 'X-Content-Type-Options_tests_counter': {'nosniff': 0},'X-Frame-Options': 0, 'X-Frame-Options_tests_counter': {'set_secure': 0},
     'set-cookie': 0, 'set-cookie_tests_counter': {'httponly': 0, 'samesite': 0, 'secure': 0, "httponly_and_samesite_and_secure": 0, "httponly_and_samesite": 0, "httponly_and_secure": 0,
     "secure_and_samesite": 0 }, 'referrer-policy': 0, 'referrer-policy_tests_counter': {'refpolicy': 0}, 'https': 0, 'https_tests_counter': {'redirect_to_https': 0, 'https_exists': 0}, 'external_tags_website': 0, 'sri_website': 0, 'sri_tests_counter': {'nr_external_tags': 0, 'nr_external_tags_SRI': 0} }
    for id in id_list:
        header_list = []
        with closing(sqlite3.connect("results.db")) as connection:
            with closing(connection.cursor()) as cursor:
                https_score = evaluate_https(id, {'redirect_to_https': 1, 'https_exists': 1})
                for score_key in https_score:
                    if score_key in header_counter['https_tests_counter']:
                        header_counter['https_tests_counter'][score_key] += https_score[score_key]
                cursor.execute("SELECT scheme, nr_external_tags, nr_external_tags_SRI FROM website WHERE id = ?", (id,))
                website_data = cursor.fetchone()
                if website_data[0] == 'https':
                    header_counter['https'] += 1
                if int(website_data[2]) > 0:
                    header_counter['sri_website'] += 1
                if int(website_data[1]) > 0:
                    header_counter['external_tags_website'] += 1
                header_counter['sri_tests_counter']['nr_external_tags'] += int(website_data[1])
                header_counter['sri_tests_counter']['nr_external_tags_SRI'] += int(website_data[2])


                cursor.execute("SELECT headertype FROM headers WHERE website_id = ? AND is_security_header = 1", (id,))
                headertypes = cursor.fetchall()
                for tupes in headertypes:
                    if tupes[0] not in header_list:
                        header_list.append(tupes[0])
                for header in header_list:
                    if header == 'content-security-policy':
                        header_counter['CSP'] += 1
                        score = evaluate_csp(id, {"base-uri": 1, "form-action": 1, "frame-ancestors": 1, "report-to/uri": 1, "sandbox": 1, "upgrade-insecure-requests": 1,
                        "child-src": 1, "connect-src": 1, "default-src": 1, "font-src": 1, "frame-src": 1, "img-src": 1, "manifest-src": 1, "media-src": 1, "object-src": 1,
                        "script-src": 1, "style-src": 1, "worker-src": 1})
                        for score_key in score:
                            if score_key in header_counter['CSP_tests_counter']:
                                header_counter['CSP_tests_counter'][score_key] += score[score_key]
                            else:
                                if score[score_key] == 0.5:
                                    header_counter['CSP_tests_counter'][score_key + "_moderate"] += 1
                                else:
                                    header_counter['CSP_tests_counter'][score_key + "_good"] += score[score_key]
                    if header == 'x-xss-protection':
                        header_counter['X-Xss-Protection'] += 1
                        score = evaluate_x_xss_protection(id, {"xss_filter_enabled": 1,"xss_filter_block_mode": 1})
                        for score_key in score:
                            header_counter['X-Xss-protection_tests_counter'][score_key] += score[score_key]
                    if header == 'strict-transport-security':
                        header_counter['HSTS'] += 1
                        score = evaluate_hsts(id, {"max-age": 1, "includesubdomains": 1, "preload": 1})
                        for score_key in score:
                            if score_key in header_counter['HSTS_tests_counter']:
                                header_counter['HSTS_tests_counter'][score_key] += score[score_key]
                            else:
                                if score[score_key] == 0.5:
                                    header_counter['HSTS_tests_counter'][score_key + "_moderate"] += 1
                                else:
                                    header_counter['HSTS_tests_counter'][score_key + "_good"] += score[score_key]
                    if header == 'x-content-type-options':
                        header_counter['X-Content-Type-Options'] += 1
                        score = evaluate_x_content_type_options(id, {"nosniff": 1})
                        for score_key in score:
                            header_counter['X-Content-Type-Options_tests_counter'][score_key] += score[score_key]
                    if header == 'x-frame-options':
                        header_counter['X-Frame-Options'] += 1
                        score = evaluate_x_frame_options(id, {"set_secure": 1})
                        for score_key in score:
                            header_counter['X-Frame-Options_tests_counter'][score_key] += score[score_key]
                    if header == 'set-cookie':
                        header_counter['set-cookie'] += 1
                        score = evaluate_set_cookie(id, {"httponly": 1, "samesite": 1, "secure": 1})
                        for score_key in score:
                            header_counter['set-cookie_tests_counter'][score_key] += score[score_key]
                        if score["httponly"] and score["samesite"] and score["secure"]:
                            header_counter['set-cookie_tests_counter']['httponly_and_samesite_and_secure'] += 1
                        elif score["httponly"] and score["samesite"]:
                            header_counter['set-cookie_tests_counter']['httponly_and_samesite'] += 1
                        elif score["httponly"] and score["secure"]:
                            header_counter['set-cookie_tests_counter']['httponly_and_secure'] += 1
                        elif score["secure"] and score["samesite"]:
                            header_counter['set-cookie_tests_counter']['secure_and_samesite'] += 1
                    if header == 'referrer-policy':
                        header_counter['referrer-policy'] += 1
                        score = evaluate_referrer_policy(id, {"refpolicy": 1})
                        for score_key in score:
                            header_counter['referrer-policy_tests_counter'][score_key] += score[score_key]
                    
                    
                    

                    
    
    print(json.dumps(header_counter))
                

    return header_counter


check_headers(get_unique_websites())
