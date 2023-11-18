import requests
from bs4 import BeautifulSoup
import urllib.parse
import urllib3

# Suppress only the single specific warning from urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Login details
login_details = {"username": "test@test.com", "password": "testpassword"}

# A set of common names for username/email and password fields
usernames_set = {"username", "user", "email", "login", "log", "userid", "user_id", "loginid", "login_id", "emailid", "email_id", "name",
                 "user_name", "emailaddress", "loginname", "uname"}
passwords_set = {"pass", "password", "pwd", "passwd", "passcode", "pass_id", "password_id", "pass",
                 "pass_word", "loginpass", "userpass", "userpwd"}

def process_subdomains(subdomains):
    results = []

    for line in subdomains:
        url = line.split(' - ')[-1].strip()

        try:
            response = requests.get(url, verify=False, timeout=10)  # waits 10 seconds
        except requests.exceptions.RequestException as e:
            continue

        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')

        for form in forms:
            result = {'url': url, 'form': {}, 'post': None}
            params = {}
            user_field_found = False
            pass_field_found = False
            for input in form.find_all('input'):
                if input.get("name"):
                    default_value = input.get('value', '')
                    if (input.get("name") and input.get("name").lower() in usernames_set) or \
                            (input.get("id") and input.get("id").lower() in usernames_set) or \
                            (input.get("placeholder") and input.get("placeholder").lower() in usernames_set):
                        params[input.get("name")] = login_details["username"]
                        user_field_found = True
                    elif (input.get("type") == "password") or (input.get("name") and input.get("name").lower() in passwords_set) or \
                            (input.get("id") and input.get("id").lower() in passwords_set) or \
                            (input.get("placeholder") and input.get("placeholder").lower() in passwords_set):
                        params[input.get("name")] = login_details["password"]
                        pass_field_found = True
                    else:
                        params[input.get("name")] = default_value

            action = form.get('action')
            if not urllib.parse.urlparse(action).netloc:
                action = urllib.parse.urljoin(url, action)
            elif action.startswith('//'):
                action = 'https:' + action

            result['form'] = {'action': action, 'params': params}

            if user_field_found and pass_field_found:
                try:
                    post_response = requests.post(action, data=params, verify=False, timeout=10)
                    parsed_url = urllib.parse.urlparse(post_response.url)
                    post = {'method': 'POST', 'path': parsed_url.path, 'host': parsed_url.netloc, 'headers': {}, 'params': params}
                    for key, value in post_response.request.headers.items():
                        if key.lower() != 'host':
                            post['headers'][key] = value
                    result['post'] = post
                except requests.exceptions.RequestException as e:
                    continue

            results.append(result)

    return results


def print_results(results):
    for result in results:
        #print(f'\nProcessing {result["url"]}...')
        print(f'Form parameters found: {result["form"]["action"]}?{urllib.parse.urlencode(result["form"]["params"])}')
        if result['post']:
            print(f'\nPossible login form found. POST request sent.\n')
            print('---BEGIN BURP SUITE STYLE REQUEST---')
            print(f'{result["post"]["method"]} {result["post"]["path"]} HTTP/1.1')
            print(f'Host: {result["post"]["host"]}')
            for key, value in result["post"]["headers"].items():
                print(f'{key}: {value}')
            print()
            print(urllib.parse.urlencode(result["post"]["params"]))
            print('---END BURP SUITE STYLE REQUEST---\n')
    print('Scan complete.')


# Usage
# Prompt user for subdomains
print("Enter the subdomains to process, separated by commas (include full protocol aka http/https):")
subdomains_input = input(">> ")
subdomains = [subdomain.strip() for subdomain in subdomains_input.split(',')]
              
results = process_subdomains(subdomains)
print_results(results)
