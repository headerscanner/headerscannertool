import requests, urllib.parse, time
from urllib.parse import urlparse
import csv
import sqlite3
import datetime
from contextlib import closing
from bs4 import BeautifulSoup as BS4
import json


def get_domains(inputFile):
    # Get domains from a CSV/JSON file and return a list of domains
    with open(inputFile, 'rt') as csvfile:
        reader = csv.reader(csvfile)
        for url in reader:
            URLList = url
    return URLList

def is_local_url(full_url, hostname):
    is_local = False
    parsed_full = urlparse(full_url)
    parsed_host = str(parsed_full.hostname)
    if parsed_host == hostname:
        is_local = True
    elif parsed_host == 'None':
        is_local = True
    return is_local

def tag_integrity_counter(tags, tag_type, hostname):
    tags_total = 0
    tags_with_integrity = 0
    for tag in tags:
        local_file = False
        src_attribute = False
        integrity_check = False
        tags_total += 1
        for attribute in tag.attrs:
            if tag_type == 'script':
                if attribute.lower() == "src" or attribute.lower() == "data-src":
                    src_attribute = True
                    if is_local_url(tag.attrs[attribute], hostname):
                        local_file = True
            elif tag_type == 'style':
                if attribute.lower() == "href":
                    src_attribute = True
                    if is_local_url(tag.attrs[attribute], hostname):
                        local_file = True
            if str(attribute.lower()) == "integrity":
                integrity_check = True
        if not src_attribute and tag_type == 'script':
            tags_total -= 1
        if local_file:
            tags_total -= 1
        elif integrity_check and src_attribute:
            tags_with_integrity += 1
    return (tags_total, tags_with_integrity)

def get_nr_integrity(document_html, hostname):
    soup = BS4(document_html, 'html5lib')
    scripts = soup.find_all('script')
    script_result = tag_integrity_counter(scripts, 'script', hostname)
    styles = soup.find_all(lambda tag: tag.name == 'link' and tag.get('rel') == ['stylesheet'])
    style_result = tag_integrity_counter(styles, 'style', hostname)
    return tuple(map(lambda i, j: i + j, script_result, style_result))


def get_data(originalURL):
    # Get headers and other data from a URL and return a dictionary
    parsedURL = urlparse(originalURL)
    if parsedURL.scheme == "":
        httpURL = 'http://' + originalURL
    requestHeaders = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate", 
        "Accept-Language": "en,en-US;q=0.8,sv-SE;q=0.5,sv;q=0.3",
        "Dnt": "1",
        "Host": parsedURL.hostname,
        "Upgrade-Insecure-Requests": "1", 
        "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:85.0) Gecko/20100101 Firefox/85.0", 
    }
    req = requests.get(httpURL,headers=requestHeaders)
    parsedURL = urlparse(req.url)
    cookies_list = []
    for cookie in req.cookies:
        cookies_list.append(json.dumps(cookie.__dict__))

    https_exists = 0
    if parsedURL.scheme.lower() == "http":
        httpsURL = 'https://' + originalURL
        try:
            req = requests.get(httpsURL,headers=requestHeaders)
            if req.status_code < 400:
                https_exists = 1
        except:
            print("No https available for", originalURL)
    else:
        https_exists = 1
 
    result_tuple = get_nr_integrity(req.text, parsedURL.hostname)

    returnData = {
            "statusCode": req.status_code,
            "scheme": parsedURL.scheme,
            "https_exists": https_exists,
            "redirectedURL": req.url,
            "headers": req.headers,
            "cookies": cookies_list,
            "redirections": req.history,
            "total_tags": result_tuple[0],
            "total_SRIs": result_tuple[1],
            }
    print(req.status_code, " Redirects:", len(req.history), httpURL, " -> ", req.url) 
    return returnData

def csp_parser(csp_string):
    result_list = []
    csp_directives_list = csp_string.split(';')
    for directive in csp_directives_list:
        csp_values = directive.split()
        if len(csp_values) > 0:
            directive_name = csp_values[0]
            csp_values.pop(0)
            if len(csp_values) > 0:
                for value in csp_values:
                    result_list.append((directive_name, value))
            else:
                result_list.append((directive_name, ''))
    return result_list

def csp_db_prepare(csp_string, website_id, header_id):
    result_tuple_list = []
    static_tuple = (header_id, website_id)
    csp_tuple_list = csp_parser(csp_string)
    for csp_tuple in csp_tuple_list:
        result_tuple_list.append(static_tuple + csp_tuple)
    return result_tuple_list

def is_security_header(header):
    is_sec = False
    security_header_list = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options', 'X-XSS-Protection', 'Set-Cookie', 'X-Content-Type-Options', 'Referrer-Policy', 'Permissions-Policy']
    if header.lower() in [x.lower() for x in security_header_list]:
        is_sec = True
    return is_sec

def store_data(dataDict, originalURL):
    # Get the data from the dictionary and store in a database
    with closing(sqlite3.connect("results.db")) as connection:
        with closing(connection.cursor()) as cursor:
            # Store information about website in database
            cursor.execute("CREATE TABLE IF NOT EXISTS website (id INTEGER NOT NULL PRIMARY KEY, original_url TEXT, redirected_url TEXT, scheme TEXT, https_exists INTEGER, nr_of_redirects INTEGER, statuscode INTEGER, nr_external_tags INTEGER, nr_external_tags_SRI INTEGER,  date_time TIMESTAMP)")
            data_tuple = (originalURL, dataDict['redirectedURL'], dataDict['scheme'], dataDict['https_exists'], len(dataDict['redirections']), int(dataDict['statusCode']), int(dataDict['total_tags']), int(dataDict['total_SRIs']),  datetime.datetime.now())
            cursor.execute("INSERT INTO website(original_url, redirected_url, scheme, https_exists, nr_of_redirects, statuscode, nr_external_tags, nr_external_tags_SRI, date_time) VALUES (?,?,?,?,?,?,?,?,?)", data_tuple)
            website_id = cursor.lastrowid
            

            # Store all headers in database
            cursor.execute("CREATE TABLE IF NOT EXISTS headers (id INTEGER NOT NULL PRIMARY KEY, website_id INTEGER NOT NULL, headertype TEXT, headerdata TEXT, is_security_header INTEGER)")
            data_list = []
            for header in dataDict['headers']:
                # Due to a bug in the requests package, cookies are merged into one header. https://github.com/psf/requests/issues/3957
                # Split the cookies into separate ones
                if str(header.lower()) != 'set-cookie':
                    data_tuple = (int(website_id), str(header.lower()), dataDict['headers'][header].replace(' ', ''), is_security_header(header))
                    data_list.append(data_tuple)
            for cookie in dataDict['cookies']:
                data_tuple = (int(website_id), 'set-cookie', cookie, is_security_header('set-cookie'))
                data_list.append(data_tuple)
            cursor.executemany("INSERT INTO headers(website_id, headertype, headerdata, is_security_header) VALUES (?,?,?,?)", data_list)

            # Get id of CSP header from database
            cursor.execute("SELECT id FROM headers WHERE website_id = ? AND headertype = ?", (website_id, "content-security-policy"))
            header_id = cursor.fetchone()
            if header_id != None:
                if len(header_id) > 0:
                    header_id = header_id[0]
            # Store CSP values individually in database
            if header_id != None:
                csp_dict = ""
                for header in dataDict['headers']:
                    if "Content-Security-Policy".lower() in header.lower():
                        csp_dict = dataDict['headers'][header]
                        print("CSP FOUND FOR", originalURL)
                        break
                
                cursor.execute("CREATE TABLE IF NOT EXISTS csp (id INTEGER NOT NULL PRIMARY KEY, header_id INTEGER NOT NULL, website_id INTEGER NOT NULL, csp_type TEXT, csp_data TEXT)")
                if csp_dict != "":
                    data_list = csp_db_prepare(csp_dict, int(website_id), int(header_id))
                    cursor.executemany("INSERT INTO csp(header_id, website_id, csp_type, csp_data) VALUES (?,?,?,?)", data_list)
            connection.commit()
            return website_id



def main():
    testlist = get_domains('ListAgencies.csv')
    index = 0
    errors = 0
    for x in testlist:
        index = index +1
        try:
            res = get_data(x)
            store_data(res, x)
        except:
            errors = errors +1
            print(x, "Error")
        print("Website nr", index)
        print("Errors nr", errors)
    

if __name__ == "__main__":
    main()
