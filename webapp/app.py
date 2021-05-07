from flask import Flask, jsonify, request, render_template, redirect, url_for
from lib.evaluategrade import *
from lib.scanner import *
import json

app = Flask(__name__)

@app.route('/weight/<website_id>')
def weight(website_id):
    # Get data from database if profile is set in get parameter
    profile_id = request.args.get('profile')
    profile_dict = {"base-uri": 0, "form-action": 0, "frame-ancestors": 0, "report-to/uri": 0, "sandbox": 0, "upgrade-insecure-requests": 0, "child-src": 0, "connect-src": 0, "default-src": 0, "font-src": 0, "frame-src": 0, "img-src": 0, "manifest-src": 0, "media-src": 0, "object-src": 0, "script-src": 0, "style-src": 0, "worker-src": 0, "sri": 0, "redirect_to_https": 0, "https_exists": 0, "xss_filter_enabled": 0, "xss_filter_block_mode": 0, "max-age": 0, "includesubdomains": 0, "preload": 0, "nosniff": 0, "set_secure": 0, "httponly": 0, "samesite": 0, "secure": 0, "refpolicy": 0}
    if profile_id != None:
        # get dict from DB
        profile_dict = {'xss_filter_enabled': 10, 'xss_filter_block_mode': 20, 'default-src': 90}
        with closing(sqlite3.connect("results.db")) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute("CREATE TABLE IF NOT EXISTS profile (id INTEGER NOT NULL PRIMARY KEY, profile_name TEXT, json_data TEXT)")
                cursor.execute("SELECT json_data FROM profile WHERE id = ?", (profile_id,))
                profile_json = cursor.fetchone()
                if profile_json != None:
                    profile_dict = json.loads(profile_json[0])
                connection.commit()
    # Get a list of all profiles in database
    with closing(sqlite3.connect("results.db")) as connection:
        with closing(connection.cursor()) as cursor:
            cursor.execute("CREATE TABLE IF NOT EXISTS profile (id INTEGER NOT NULL PRIMARY KEY, profile_name TEXT, json_data TEXT)")
            cursor.execute("SELECT id, profile_name FROM profile")
            profile_list = cursor.fetchall()
            connection.commit()
    return render_template('test.html', website_id=website_id, profile_dict=profile_dict, profile_list=profile_list)

@app.route('/result', methods=['POST'])
def return_result():
    divider = 0
    profile_dict = {'profile_name': "", 'json_data': {}}
    save_profile = False
    for weights in request.form:
        if weights == 'profilecheckbox' or weights == 'profiletextbox':
            save_profile = True
        else:
            divider += int(request.form[weights])
    divider = divider - int(request.form['website_id'])
    if divider < 100:
        divider = 100
    list_of_headers = ["CSP", "SRI", "HTTPS", "X-Xss-Protection", "HSTS", "X-Content-Type-Options", "X-Frame-Options", "set-cookie", "referrer-policy"]
    formatted_dict = {'website_id': int(request.form['website_id']), 'headers': []}
    for header in list_of_headers:
        if header == 'CSP':
            header_dict = {'headertype': header, 'weights': {'base-uri': round(int(request.form['csp_base_uri'])/divider, 4), 'form-action': round(int(request.form['csp_form_action'])/divider, 4),
            'frame-ancestors': round(int(request.form['csp_frame_ancestors'])/divider, 4), 'report-to/uri': round(int(request.form['csp_report_to_report_uri'])/divider, 4), 'sandbox': round(int(request.form['csp_sandbox'])/divider, 4), 
            'upgrade-insecure-requests': round(int(request.form['csp_upgrade_insecure_requests'])/divider, 4), 'child-src': round(int(request.form['csp_child_src'])/divider, 4), 
            'connect-src': round(int(request.form['csp_connect_src'])/divider, 4), 'default-src': round(int(request.form['csp_default_src'])/divider, 4), 'font-src': round(int(request.form['csp_font_src'])/divider, 4),
            'frame-src': round(int(request.form['csp_frame_src'])/divider, 4), 'img-src': round(int(request.form['csp_img_src'])/divider, 4), 'manifest-src': round(int(request.form['csp_manifest_src'])/divider, 4),
            'media-src':  round(int(request.form['csp_media_src'])/divider, 4), 'object-src': round(int(request.form['csp_object_src'])/divider, 4), 'script-src': round(int(request.form['csp_script_src'])/divider, 4), 
            'worker-src': round(int(request.form['csp_worker_src'])/divider, 4), 'style-src': round(int(request.form['csp_style_src'])/divider, 4)}}
            formatted_dict['headers'].append(header_dict)
        elif header == 'SRI':
            header_dict = {'headertype': header, 'weights': {'sri': round(int(request.form['sri'])/divider, 4)}}
            formatted_dict['headers'].append(header_dict)
        elif header == 'HTTPS':
            header_dict = {'headertype': header, 'weights': {'redirect_to_https': round(int(request.form['https_redirect'])/divider, 4), 'https_exists': round(int(request.form['https_exists'])/divider, 4)}}
            formatted_dict['headers'].append(header_dict)
        elif header == 'X-Xss-Protection':
            header_dict = {'headertype': header, 'weights': {'xss_filter_enabled': round(int(request.form['xss_filter_enabled'])/divider, 4), 'xss_filter_block_mode': round(int(request.form['xss_filter_block_mode'])/divider, 4)}}
            formatted_dict['headers'].append(header_dict)
        elif header == 'HSTS':
            header_dict = {'headertype': header, 'weights': {'max-age': round(int(request.form['HSTS_max_age'])/divider, 4), 'includesubdomains': round(int(request.form['HSTS_include_subdomains'])/divider, 4), 'preload': round(int(request.form['HSTS_preload'])/divider, 4)}}
            formatted_dict['headers'].append(header_dict)
        elif header == 'X-Content-Type-Options':
            header_dict = {'headertype': header, 'weights': {'nosniff': round(int(request.form['XCTO_nosniff'])/divider, 4)}}
            formatted_dict['headers'].append(header_dict)
        elif header == 'X-Frame-Options':
            header_dict = {'headertype': header, 'weights': {'set_secure': round(int(request.form['x_frame_options'])/divider, 4)}}
            formatted_dict['headers'].append(header_dict)
        elif header == 'set-cookie':
            header_dict = {'headertype': header, 'weights': {'httponly': round(int(request.form['SC_httponly'])/divider, 4), 'samesite': round(int(request.form['SC_samesite'])/divider, 4), 'secure': round(int(request.form['SC_secure'])/divider, 4)}}
            formatted_dict['headers'].append(header_dict)
        elif header == 'referrer-policy':
            header_dict = {'headertype': header, 'weights': {'refpolicy': round(int(request.form['refpolicy'])/divider, 4)}}
            formatted_dict['headers'].append(header_dict)
    
    if save_profile:
        profile_dict['profile_name'] = str(request.form['profiletextbox'])
        temp_dict = {}
        for weights in formatted_dict['headers']:
            temp_dict2 = dict(temp_dict)
            temp_dict2.update(weights['weights'])
            temp_dict = temp_dict2
        for keys in temp_dict:
            temp_dict[keys] =  round(temp_dict[keys]*divider)
        profile_dict['json_data'] = temp_dict
        with closing(sqlite3.connect("results.db")) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute("CREATE TABLE IF NOT EXISTS profile (id INTEGER NOT NULL PRIMARY KEY, profile_name TEXT, json_data TEXT)")
                data_tuple = (profile_dict['profile_name'], json.dumps(profile_dict['json_data']))
                cursor.execute("INSERT INTO profile(profile_name, json_data) VALUES (?,?)", data_tuple)
                connection.commit()

    score = get_score(json.dumps(formatted_dict))
    url_list = []
    with closing(sqlite3.connect("results.db")) as connection:
        with closing(connection.cursor()) as cursor:
            cursor.execute("SELECT original_url FROM website WHERE id = ?", (int(request.form['website_id']),))
            url = cursor.fetchone()
            if url != None:
                url = url[0]
            else:
                url = "Could not load website url"
    total_score_dict = {}
    for header in formatted_dict['headers']:
        total_score_dict[header['headertype']] = '-'
        for directive in header['weights']:
            if header['weights'][directive] != 0:
                total_score_dict[header['headertype']] = 0.0
    for header in score['headers']:
        if total_score_dict[header['headertype']] != '-':
            for directive in header['scores']:
                total_score_dict[header['headertype']] += header['scores'][directive]
            total_score_dict[header['headertype']] = round(total_score_dict[header['headertype']] * 100, 2)
    score['total_score'] = int(round(score['total_score'] * 100, 0))
    return render_template('result.html', score=score, divider=divider, formatted_dict=formatted_dict, total_score_dict=total_score_dict, url=url)

def save_website(url):
    try:
        res = get_data(url)
        website_id = store_data(res, url)
        print("Saved website with id:", website_id)
        return website_id
    except:
        return False
        print(x, "Error")

@app.route('/request_scan', methods=['POST'])
def scan_website():
    url = request.form['url_textbox'].lower().replace('http://','').replace('https://','')
    website_id = save_website(url)
    if website_id:
        return redirect(url_for('weight', website_id=website_id))
    else:
        return redirect(url_for('index'))
        
    


@app.route('/')
def index():
    website_list = get_URLs()
    return render_template('index.html', website_list=website_list)

@app.route('/api/score', methods=['POST'])
def api_score():
    # TODO unused currently
    if request.is_json:
        #print(request.get_json(), type(request.get_json()))
        data = json.dumps(request.get_json())
    return jsonify(get_score(data))


def get_URLs():
    url_list = []
    with closing(sqlite3.connect("results.db")) as connection:
        with closing(connection.cursor()) as cursor:
            cursor.execute("CREATE TABLE IF NOT EXISTS website (id INTEGER NOT NULL PRIMARY KEY, original_url TEXT, redirected_url TEXT, scheme TEXT, https_exists INTEGER, nr_of_redirects INTEGER, statuscode INTEGER, nr_external_tags INTEGER, nr_external_tags_SRI INTEGER,  date_time TIMESTAMP)")
            cursor.execute("CREATE TABLE IF NOT EXISTS headers (id INTEGER NOT NULL PRIMARY KEY, website_id INTEGER NOT NULL, headertype TEXT, headerdata TEXT, is_security_header INTEGER)")
            cursor.execute("CREATE TABLE IF NOT EXISTS csp (id INTEGER NOT NULL PRIMARY KEY, header_id INTEGER NOT NULL, website_id INTEGER NOT NULL, csp_type TEXT, csp_data TEXT)")
            
            cursor.execute("SELECT id, original_url FROM website WHERE statuscode = 200")
            website_urls = cursor.fetchall()
            for tupes in website_urls:
                url_list.append(tupes)
    return url_list


if __name__ == '__main__':
    app.run(debug=True, host='localhost')
