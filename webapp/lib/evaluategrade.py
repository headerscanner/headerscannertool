import sqlite3
from contextlib import closing
import json
import validators

def urls_without_scheme(src_list):
    """
        Looks for urls/domains without scheme and if it exists, it returns true. otherwise false
    """
    result = False
    for item in src_list:
        if validators.domain(item.replace('*.', '').replace(':*', '').split(':', 1)[0].split('/', 1)[0]):
            return True
        else:
            result =  False
    return result

def csp_src_check(src_list, redirected_scheme):
    """
    Bad: = 0
        *
        unsafe-inline
        unsafe-eval
        unsafe-hashes
        data:
        http:
        http:// - urls
    Moderate: = 0.5
        https:
        URLs whitelist
        strict-dynamic
    Good: = 1
        'self'
        hash/nonce
        none
    """
    new_src_list = []
    for item in src_list:
        new_src_list.append(item[0])
    src_list = new_src_list
    if (urls_without_scheme(src_list) and redirected_scheme == 'http') or "'*'" in src_list or "'unsafe-inline'" in src_list or "'unsafe-eval'" in src_list or "'unsafe-hashes'" in src_list or "'http:'" in src_list or any('data:' in substring for substring in src_list) or any('http://' in substring for substring in src_list):
        return 0
    elif (urls_without_scheme(src_list) and redirected_scheme == 'https') or "'https:'" in src_list or "'strict-dynamic'" in src_list or any('https://' in substring for substring in src_list):
        return 0.5
    elif "'self'" in src_list or "'none'" in src_list or any('nonce-' in substring for substring in src_list) or any('sha256-' in substring for substring in src_list) or any('sha384-' in substring for substring in src_list) or any('sha512-' in substring for substring in src_list):
        return 1
    else:
        return 0

def csp_frame_ancestors_check(src_list, redirected_scheme):
    """
    Bad: = 0
        *
        http:
        http:// - urls
    Moderate: = 0.5
        https:
    Good: = 1
        https:// - urls
        none
        self
    """
    new_src_list = []
    for item in src_list:
        new_src_list.append(item[0])
    src_list = new_src_list
    if (urls_without_scheme(src_list) and redirected_scheme == 'http') or "'*'" in src_list or "'http:'" in src_list or any('http://' in substring for substring in src_list):
        return 0
    elif "'https:'" in src_list:
        return 0.5
    elif (urls_without_scheme(src_list) and redirected_scheme == 'https') or "'none'" in src_list or "'self'" or any('https://' in substring for substring in src_list):
        return 1
    else:
        return 0

def evaluate_csp(website_id, test_weights):
    """
        Checks:
            no fallback to default:
                base-uri
                form-action
                frame-ancestors
                
            report-to/uri    
            sandbox
            upgrade-insecure-requests

            src:    
                child-src
                connect-src
                default-src
                font-src
                frame-src - fallsback to child-src which falls back to default
                img-src
                manifest-src
                media-src
                object-src
                style-src
                script-src
                    strict-dynamic
                unsafe-hashes
                worker-src
        if a check is to be done on script-src for example but it's not explicitly defined but default-src is, use the score from default-src instead

    """
    score_dict = {'default-src': 0, 'child-src': 0, 'connect-src': 0, 'font-src': 0, 'frame-src': 0, 'img-src': 0, 'manifest-src': 0, 'media-src': 0, 'object-src': 0, 'script-src': 0, 'style-src': 0, 'worker-src': 0, 'report-to/uri': 0, 'base-uri': 0, 'form-action': 0, 'frame-ancestors': 0, 'sandbox': 0, 'upgrade-insecure-requests': 0}
    csp_data = None
    with closing(sqlite3.connect("results.db")) as connection:
        with closing(connection.cursor()) as cursor:
            csp_src_directives = ["default-src","child-src","connect-src","font-src","frame-src","img-src","manifest-src","media-src","object-src","script-src","style-src","worker-src"]
            csp_default_directive_score = 0
            csp_child_src_directive_score = 0
            cursor.execute("SELECT scheme FROM website WHERE id = ?", (website_id,))
            redirected_scheme = cursor.fetchone()
            if redirected_scheme != None:
                redirected_scheme = redirected_scheme[0]
            else:
                #Assume http
                redirected_scheme = "http"
            for directive in csp_src_directives:
                cursor.execute("SELECT csp_data FROM csp WHERE website_id = ? AND csp_type = ?", (website_id, directive))
                csp_data = cursor.fetchall()
                if len(csp_data) > 0:
                    result = csp_src_check(csp_data, redirected_scheme)
                    if directive == "default-src":
                        csp_default_directive_score = result
                    elif directive == "child-src":
                        csp_child_src_directive_score = result
                    score_dict[directive] = round(result * test_weights[directive], 4)
                elif directive == "frame-src":
                    score_dict[directive] = round(csp_child_src_directive_score * test_weights[directive], 4)
                elif directive == "child-src":
                    score_dict[directive] = round(csp_default_directive_score * test_weights[directive], 4)
                    csp_child_src_directive_score = csp_default_directive_score
                elif directive != "default-src":
                    score_dict[directive] = round(csp_default_directive_score * test_weights[directive], 4)
            csp_directives  = ["base-uri","form-action","frame-ancestors","report-to","report-uri","sandbox","upgrade-insecure-requests"]
            for directive in csp_directives:
                cursor.execute("SELECT csp_data FROM csp WHERE website_id = ? AND csp_type = ?", (website_id, directive))
                csp_data = cursor.fetchall()
                if len(csp_data) > 0:
                    result = 0
                    if directive == 'base-uri' or directive == 'form-action':
                        result = csp_src_check(csp_data, redirected_scheme)
                    elif directive == 'frame-ancestors':
                        result = csp_frame_ancestors_check(csp_data, redirected_scheme)
                    elif directive == 'report-to' or directive == 'report-uri':
                        result = 1
                    elif directive == 'sandbox':
                        result = 1
                    elif directive == 'upgrade-insecure-requests':
                        result = 1
                    if directive == 'report-to' or directive == 'report-uri':
                        score_dict['report-to/uri'] = round(result * test_weights['report-to/uri'], 4)
                    else:
                        score_dict[directive] = round(result * test_weights[directive], 4)
    return score_dict

def evaluate_sri(website_id, test_weights):
    """
        Checks ratio of external resources to external resources with SRI = 1
    """
    score_dict = {'sri': 0}
    website_data = None
    with closing(sqlite3.connect("results.db")) as connection:
        with closing(connection.cursor()) as cursor:
            cursor.execute("SELECT nr_external_tags, nr_external_tags_SRI FROM website WHERE id = ?", (website_id,))
            website_data = cursor.fetchone()
            if website_data == None:
                return score_dict
    if website_data[0] != 0:
        score_dict['sri'] = round((website_data[1]/website_data[0])*test_weights['sri'], 4)
    else:
        score_dict['sri'] = round(1*test_weights['sri'], 4)
    return score_dict

def evaluate_https(website_id, test_weights):
    """
        checks if https is there = 1
        tests if redirected to https = 1
    """
    score_dict = {'redirect_to_https': 0, 'https_exists': 0}
    website_data = None
    with closing(sqlite3.connect("results.db")) as connection:
        with closing(connection.cursor()) as cursor:
            cursor.execute("SELECT scheme, https_exists FROM website WHERE id = ?", (website_id,))
            website_data = cursor.fetchone()
            if website_data == None:
                return score_dict
    if website_data[0] == 'https':
        score_dict['redirect_to_https'] = round(1 * test_weights['redirect_to_https'], 4)
    if website_data[1] == 1:
        score_dict['https_exists'] = round(1 * test_weights['https_exists'], 4)
    return score_dict

def evaluate_x_xss_protection(website_id, test_weights):
    """
        checks if xss filter is enabled = 1
        checks if mode is set to block (and filter is enabled) (with this option enabled, rather than sanitizing, the browser prevents the rendering of the page) = 1
    """
    score_dict = {'xss_filter_enabled': 0, 'xss_filter_block_mode': 0}
    website_data = None
    with closing(sqlite3.connect("results.db")) as connection:
        with closing(connection.cursor()) as cursor:
            cursor.execute("SELECT headerdata FROM headers WHERE headertype = 'x-xss-protection' AND website_id = ?", (website_id,))
            website_data = cursor.fetchone()
            if website_data == None:
                return score_dict
    if website_data != None:
        website_data = website_data[0].split(',')
        website_data = website_data[-1].split(';')
        if len(website_data) > 1:
            if website_data[0] == '1' and website_data[1].lower() == 'mode=block':
                score_dict['xss_filter_block_mode'] = round(1 * test_weights['xss_filter_block_mode'], 4)
        if len(website_data) > 0:
            if website_data[0] == '1':
                score_dict['xss_filter_enabled'] = round(1 * test_weights['xss_filter_enabled'], 4)
    return score_dict


def evaluate_hsts(website_id, test_weights):
    """
        checks max-age of HSTS header, = 0 if <6months, = 0.5 if >=6months and <2years, = 1 if >=2 years
        checks includesubdomains = 1
        checks preload = 1 if includesubdomains exist and max_age is >= 1 year
    """
    score_dict = {'max-age': 0, 'includesubdomains': 0, 'preload': 0}
    isd_set = False
    max_age = 0
    headerdata = None
    with closing(sqlite3.connect("results.db")) as connection:
        with closing(connection.cursor()) as cursor:
            db_variable = (website_id,)
            cursor.execute("SELECT headerdata FROM headers WHERE headertype = 'strict-transport-security' AND website_id = ?;", db_variable)
            headerdata = cursor.fetchone()
            cursor.execute("SELECT scheme FROM website WHERE  id = ?;", db_variable)
            scheme = cursor.fetchone()
            scheme = scheme[0]
            if headerdata == None or scheme == "http":
                return score_dict
            headerdata = headerdata[0]
    if ',' in headerdata:
            split_data = headerdata.split(',')
            headerdata = split_data[len(split_data)-1]
    headerdata = headerdata.replace(' ', '')
    headerdata_list = headerdata.split(';')
    for directives in headerdata_list:
        directives = str(directives.lower())
        if "max-age=" in directives:
            max_age = int(directives.replace("max-age=", ''))
            if max_age >= 15780000 and max_age < 63072000:
                score_dict['max-age'] = round((1*test_weights['max-age'])/2, 4)
            elif max_age >= 63072000:
                score_dict['max-age'] = round(1*test_weights['max-age'], 4)
        if "includesubdomains" in directives:
            score_dict['includesubdomains'] = round(1*test_weights['includesubdomains'], 4)
            isd_set = True
        if "preload" in directives and isd_set and max_age >= 31536000:
            score_dict['preload'] = round(1*test_weights['preload'], 4)
    return score_dict

def evaluate_x_content_type_options(website_id, test_weights):
    """
        Checks if x-content-type-options is present with the nosniff value
    """
    score_dict = {'nosniff': 0}
    with closing(sqlite3.connect("results.db")) as connection:
        with closing(connection.cursor()) as cursor:
            db_variable = (website_id,)
            cursor.execute("SELECT headerdata FROM headers WHERE headertype = 'x-content-type-options' AND website_id = ?;", db_variable)
            headerdata = cursor.fetchone()
            if headerdata == None:
                return score_dict
            headerdata = headerdata[0]
            if "nosniff" in headerdata:
                score_dict['nosniff'] = round(1*test_weights['nosniff'], 4)
    return score_dict

def evaluate_x_frame_options(website_id, test_weights):
    """
        Checks if x-frame-options is present with deny or sameorigin values
    """
    score_dict = {'set_secure': 0}
    with closing(sqlite3.connect("results.db")) as connection:
        with closing(connection.cursor()) as cursor:
            db_variable = (website_id,)
            cursor.execute("SELECT headerdata FROM headers WHERE headertype = 'x-frame-options' AND website_id = ?;", db_variable)
            headerdata = cursor.fetchone()
            if headerdata == None:
                return score_dict
            headerdata = headerdata[0]
            if "deny" in headerdata.lower() or "sameorigin" in headerdata.lower():
                score_dict['set_secure'] = round(1*test_weights['set_secure'], 4)
    return score_dict

def evaluate_set_cookie(website_id, test_weights):
    score_dict = {'httponly': round(1*test_weights['httponly'], 4), 'samesite': round(1*test_weights['samesite'], 4), 'secure': round(1*test_weights['secure'], 4)}
    with closing(sqlite3.connect("results.db")) as connection:
        with closing(connection.cursor()) as cursor:
            db_variable = (website_id,)
            cursor.execute("SELECT headerdata FROM headers WHERE headertype = 'set-cookie' AND website_id = ?;", db_variable)
            headerdata = cursor.fetchall()
            if headerdata == None:
                return score_dict
            total_score = 3
            for jdata in headerdata:
                temp_score_dict = {'httponly': round(1*test_weights['httponly'], 4), 'samesite': round(1*test_weights['samesite'], 4), 'secure': round(1*test_weights['secure'], 4)}
                temp_score = 3
                data_dict = json.loads(jdata[0])
                if not ("Httponly" in data_dict['_rest'] or "HttpOnly" in data_dict['_rest']):
                    temp_score_dict['httponly'] = 0
                    temp_score -= round(1*test_weights['httponly'], 4)
                if not ("SameSite" in data_dict['_rest']):
                    temp_score_dict['samesite'] = 0
                    temp_score -= round(1*test_weights['samesite'], 4)
                else:
                    if data_dict['_rest']['SameSite'].lower() == "none":
                        temp_score_dict['samesite'] = 0
                        temp_score -= round(1*test_weights['samesite'], 4)
                if data_dict['secure'] == False:
                    temp_score_dict['secure'] = 0
                    temp_score -= round(1*test_weights['secure'], 4)
                if temp_score < total_score:
                    total_score = temp_score
                    score_dict = temp_score_dict.copy()
            
    return score_dict

def evaluate_referrer_policy(website_id, test_weights):
    score_dict = {'refpolicy': 0}
    with closing(sqlite3.connect("results.db")) as connection:
        with closing(connection.cursor()) as cursor:
            db_variable = (website_id,)
            cursor.execute("SELECT headerdata FROM headers WHERE headertype = 'referrer-policy' AND website_id = ?;", db_variable)
            headerdata = cursor.fetchone()
            if headerdata == None:
                score_dict['refpolicy'] = 0.5 * test_weights['refpolicy']
                return score_dict
            headerdata = headerdata[0]
            if ',' in headerdata:
                split_data = headerdata.split(',')
                headerdata = split_data[len(split_data)-1]
            if 'unsafe-url' not in headerdata:
                score_dict['refpolicy'] = round(1*test_weights['refpolicy'], 4)
    return score_dict

def get_score(json_string):
    input_data = None
    output_data = {}
    total_score = 0
    try:
        input_data = json.loads(json_string)
    except:
        raise Exception("Not valid JSON data")
    output_data['website_id'] = input_data['website_id']
    output_data['headers'] = []
    for category in input_data['headers']:
        if category['headertype'] == "HTTPS":
                scores = evaluate_https(int(input_data['website_id']), category['weights'])
                for score in scores:
                    total_score += scores[score]
                output_data['headers'].append({'headertype': 'HTTPS', 'scores': scores})
        if category['headertype'] == "X-Xss-Protection":
                scores = evaluate_x_xss_protection(int(input_data['website_id']), category['weights'])
                for score in scores:
                    total_score += scores[score]
                output_data['headers'].append({'headertype': 'X-Xss-Protection', 'scores': scores})
        if category['headertype'] == "CSP":
                scores = evaluate_csp(int(input_data['website_id']), category['weights'])
                for score in scores:
                    total_score += scores[score]
                output_data['headers'].append({'headertype': 'CSP', 'scores': scores})
        if category['headertype'] == "SRI":
                scores = evaluate_sri(int(input_data['website_id']), category['weights'])
                for score in scores:
                    total_score += scores[score]
                output_data['headers'].append({'headertype': 'SRI', 'scores': scores})
        if category['headertype'] == "HSTS":
                scores = evaluate_hsts(int(input_data['website_id']), category['weights'])
                for score in scores:
                    total_score += scores[score]
                output_data['headers'].append({'headertype': 'HSTS', 'scores': scores})
        if category['headertype'] == "X-Content-Type-Options":
                scores = evaluate_x_content_type_options(int(input_data['website_id']), category['weights'])
                for score in scores:
                    total_score += scores[score]
                output_data['headers'].append({'headertype': 'X-Content-Type-Options', 'scores': scores})
        if category['headertype'] == "X-Frame-Options":
                scores = evaluate_x_frame_options(int(input_data['website_id']), category['weights'])
                for score in scores:
                    total_score += scores[score]
                output_data['headers'].append({'headertype': 'X-Frame-Options', 'scores': scores})
        if category['headertype'] == "set-cookie":
                scores = evaluate_set_cookie(int(input_data['website_id']), category['weights'])
                for score in scores:
                    total_score += scores[score]
                output_data['headers'].append({'headertype': 'set-cookie', 'scores': scores})
        if category['headertype'] == "referrer-policy":
                scores = evaluate_referrer_policy(int(input_data['website_id']), category['weights'])
                for score in scores:
                    total_score += scores[score]
                output_data['headers'].append({'headertype': 'referrer-policy', 'scores': scores})
    output_data['total_score'] = round(total_score, 4)
    return output_data

def test():
    with open('sample.json', 'r') as file:
        data = file.read()
        jsontest = json.loads(data)
        for jt in jsontest['headers']:
            if jt['headertype'] == "CSP":
                print(evaluate_csp(int(jsontest['website_id']), jt['weights']))
            if jt['headertype'] == "SRI":
                print(evaluate_sri(int(jsontest['website_id']), jt['weights']))
            if jt['headertype'] == "HTTPS":
                print(evaluate_https(int(jsontest['website_id']), jt['weights']))
            elif jt['headertype'] == "HSTS":
                print(evaluate_hsts(int(jsontest['website_id']), jt['weights']))
            elif jt['headertype'] == "X-Xss-Protection":
                print(evaluate_x_xss_protection(int(jsontest['website_id']), jt['weights']))
            elif jt['headertype'] == "X-Content-Type-Options":
                print(evaluate_x_content_type_options(int(jsontest['website_id']), jt['weights']))
            elif jt['headertype'] == "X-Frame-Options":
                print(evaluate_x_frame_options(int(jsontest['website_id']), jt['weights']))
            elif jt['headertype'] == "set-cookie":
                print(evaluate_set_cookie(int(jsontest['website_id']), jt['weights']))
            elif jt['headertype'] == "referrer-policy":
                print(evaluate_referrer_policy(int(jsontest['website_id']), jt['weights']))