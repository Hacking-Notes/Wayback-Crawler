import re
import os
import sys
import csv
import time
import json
import requests
import itertools
import concurrent
from concurrent.futures import ThreadPoolExecutor

print("""
██╗    ██╗ █████╗ ██╗   ██╗██████╗  █████╗  ██████╗██╗  ██╗     ██████╗██████╗  █████╗ ██╗    ██╗██╗     ███████╗██████╗ 
██║    ██║██╔══██╗╚██╗ ██╔╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝    ██╔════╝██╔══██╗██╔══██╗██║    ██║██║     ██╔════╝██╔══██╗
██║ █╗ ██║███████║ ╚████╔╝ ██████╔╝███████║██║     █████╔╝     ██║     ██████╔╝███████║██║ █╗ ██║██║     █████╗  ██████╔╝
██║███╗██║██╔══██║  ╚██╔╝  ██╔══██╗██╔══██║██║     ██╔═██╗     ██║     ██╔══██╗██╔══██║██║███╗██║██║     ██╔══╝  ██╔══██╗
╚███╔███╔╝██║  ██║   ██║   ██████╔╝██║  ██║╚██████╗██║  ██╗    ╚██████╗██║  ██║██║  ██║╚███╔███╔╝███████╗███████╗██║  ██║
 ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝     ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝  ╚═╝
""")

# Set Variables
class Set_Variables():
    website = input("What is the domain that is being targeted? (e.g. domain.com): ").lower()
    website = website.replace("http://", "").replace("https://", "").replace("www.", "")
    website_without_extension = website.split(".")[0]
    print("")

    # Ask user if they want to test the subdomain accessibility
    active = ""
    while active not in ["Y", "y", "N", "n"]:
        active = input("Check if subdomain is active (Y/N): ")

    # Ask user to check for potential vulnerabilities
    vulnerable = ""
    while vulnerable not in ["Y", "y", "N", "n"]:
        vulnerable = input("Check for vulnerable GET parameters (Y/N): ")
        if vulnerable == "Y" or vulnerable == "y":
            custom_wordlist_yes_no = input(
                "Would you like to use a custom keyword wordlist? (Y/N - default): ") or "N"
            custom_wordlist = "keywords.txt"
            while custom_wordlist_yes_no not in ["Y", "y", "N", "n"]:
                custom_wordlist_yes_no = input(
                    "Would you like to use a custom keyword wordlist? (Y/N - default): ") or "N"
                if custom_wordlist_yes_no == "Y" or custom_wordlist_yes_no == "y":
                    print("")
                    custom_wordlist = input(
                        "Enter the name of your file (Ensure that it is in the same folder as this project): ")
                    while not os.path.isfile(custom_wordlist):
                        custom_wordlist = input(
                            "File not found. Enter the name of your file again (Ensure that it is in the same folder as this project): ")
                else:
                    custom_wordlist = "keywords.txt"
        else:
            pass

#=================================================

def wayback_crawler(website, active, vulnerable, website_without_extension, custom_wordlist):
    def analyzing(website, website_without_extension, custom_wordlist):

        def search_subdomains(website, website_without_extension):
            url = f'https://crt.sh/?q=%25.{website}&output=json'

            try:
                subdomains = set()
                response = requests.get(url)
                for entry in response.json():
                    subdomain = entry['name_value'].lower().lstrip('*.')
                    subdomains.add(subdomain)

                with open(website_without_extension + '_subdomains.txt', 'w') as f:
                    for subdomain in sorted(subdomains, key=str.lower):
                        if not subdomain.startswith('www.'):
                            f.write(f"{subdomain}\n")

                with open(website_without_extension + '_subdomains.txt', 'r') as f:
                    lines = f.readlines()

                subdomain_list = [{'url': line.strip()} for line in lines if
                                  not line.strip().lower().startswith('www.')]

                with open(website_without_extension + '_subdomains.txt', 'w') as f:
                    f.write(json.dumps(subdomain_list))

            except (json.JSONDecodeError, requests.exceptions.RequestException) as e:
                print(f"Failed to retrieve subdomains: {e}")

            # Open the file and load the subdomains into a list of dictionaries
            with open(website_without_extension + '_subdomains.txt', 'r') as f:
                subdomains = json.load(f)

            # Create a set to store the unique subdomains
            unique_subdomains = set()

            # Create a list to store the duplicate subdomains
            duplicate_subdomains = []

            # Loop through the subdomains and add unique subdomains to the set, and duplicate subdomains to the list
            for subdomain in subdomains:
                if subdomain['url'] in unique_subdomains:
                    duplicate_subdomains.append(subdomain)
                else:
                    unique_subdomains.add(subdomain['url'])

            # Remove the duplicates from the subdomains list
            for duplicate in duplicate_subdomains:
                subdomains.remove(duplicate)

            # Write the updated subdomains list back to the file
            with open(website_without_extension + '_subdomains.txt', 'w') as f:
                f.write(json.dumps(subdomains))

        def search_wayback_machine(website, website_without_extension):
            url = f'https://web.archive.org/cdx/search/cdx?url={website}&matchType=domain'

            response = requests.get(url)

            if response.status_code == 200:
                reader = csv.reader(response.text.strip().split('\n'), delimiter=' ')
                urls = []
                for row in reader:
                    if len(row) >= 3:
                        urls.append(row[2].rstrip('/'))
                with open(website_without_extension + '_wayback_url.txt', 'w') as file:
                    for url in sorted(set(urls)):
                        if url == f'https://{website}' or url == f'http://{website}':
                            continue
                        if not re.search(r'(https?:\/\/)(?!www\.)([a-z0-9]+\.)*[a-z0-9]+\.[a-z]+', url) or re.search(
                                r'(https?:\/\/)(www\.)?' + website.replace('.', r'\.') + r'\/', url):
                            continue
                        file.write(f'{url}\n')

                subdomains = set()

                with open(website_without_extension + '_wayback_url.txt', 'r') as file:
                    lines = file.readlines()
                    for line in lines:
                        subdomain = line.split('//')[1].split('.')[0]
                        subdomains.add(subdomain)

                subdomain_list = []
                with open(website_without_extension + '_subdomains.txt', 'r+') as file:
                    try:
                        subdomain_list = json.load(file)
                    except json.JSONDecodeError:
                        pass

                    for subdomain in subdomains:
                        if not any(subdomain in d.get('url', '') for d in subdomain_list):
                            subdomain_list.append({'url': f'{subdomain}.{website}'})

                    subdomain_list = sorted(subdomain_list, key=lambda d: d.get('url', '').lower())

                    file.seek(0)
                    file.truncate()
                    json.dump(subdomain_list, file, indent=None)

        def accessibility(website_without_extension):
            with open(website_without_extension + "_subdomains.txt", "r") as f:
                data = f.read()

            json_data = json.loads(data)

            def check_status(item):
                if "url" in item:
                    url = item["url"]
                    if not url.startswith("http://") and not url.startswith("https://"):
                        url = "https://" + url
                    try:
                        response = requests.get(url, allow_redirects=True, timeout=10)
                        status = response.status_code
                    except requests.exceptions.Timeout:
                        status = "unknown"
                    except requests.exceptions.ConnectionError:
                        status = "unknown"
                    except requests.exceptions.RequestException as e:
                        status = str(e)
                    return {"url": item["url"], "status": status}

            with concurrent.futures.ThreadPoolExecutor() as executor:
                results = executor.map(check_status, json_data)

            with open(website_without_extension + "_status.txt", "w") as f:
                for result in results:
                    f.write('{"url": "' + result["url"] + '", "status": "' + str(result["status"]) + '"}\n')

        def vulnerability(website_without_extension, custom_wordlist):
            # Define the query parameter keywords to search for
            with open(custom_wordlist) as f:
                keywords = [line.strip() for line in f]

            # Load URLs from file
            with open(website_without_extension + '_wayback_url.txt') as f:
                urls = [line.strip() for line in f]

            # Check each URL for keywords
            with open(website_without_extension + '_vulnerable_parameters.txt', 'w') as file:
                for url in urls:
                    for keyword in keywords:
                        if '?' + keyword in url or '&' + keyword + '=' in url:
                            output = '{{"parameter": "{}", "url": "{}"}}\n'.format(keyword, url)
                            file.write(output)

        if __name__ == '__main__':
            search_subdomains(website, website_without_extension)
            search_wayback_machine(website, website_without_extension)

            if active == "Y" or active == "y":
                accessibility(website_without_extension)
            else:
                pass
            if vulnerable == "Y" or vulnerable == "y":
                vulnerability(website_without_extension, custom_wordlist)
            else:
                pass

    def animation(future_analyzing):
        spinner = itertools.cycle(['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'])
        while not future_analyzing.done():
            sys.stdout.write("\rSearching & Analysing Subdomains " + next(spinner))
            sys.stdout.flush()
            time.sleep(0.5)
        print("")

    def output(active, vulnerable, subdomains, website_without_extension):
        # Read the subdomains from subdomains.txt
        with open(website_without_extension + '_subdomains.txt', 'r') as f:
            subdomains = json.load(f)
            number_of_subdomains = len(subdomains)

        if not subdomains:
            print("No subdomains found.")
            sys.exit()

        print(f"\033[4mA total of {number_of_subdomains} subdomains were discovered:\033[0m")
        print("")

        if active == "Y" or active == "y":
            results = []
            for subdomain in subdomains:
                url = subdomain['url']
                # Fetch the status of the subdomain from status.txt
                with open(website_without_extension + '_status.txt', 'r') as f:
                    statuses = f.readlines()
                    for status in statuses:
                        data = json.loads(status)
                        if data['url'] == url:
                            status_code = data['status']
                            break
                    else:
                        status_code = 'Not Found'
                # Append the result to the results list
                results.append({'Status Code': status_code, 'Subdomain': url})

                # Determine the maximum length of the status codes
            max_status_length = max(len(result['Status Code']) for result in results)

            # Print the results in a table format with aligned columns and colored text
            print(f"\033[1m{'Status Code':<{max_status_length + 1}}  {'Subdomain':<40}\033[0m")
            print("-" * 40)
            for result in results:
                status_code = result['Status Code']
                subdomain = result['Subdomain']
                if status_code == '200':
                    status_code = f"    \033[32m{status_code}\033[0m"  # Green color for status 200
                    subdomain = f"{subdomain}"  # Underline subdomains with status 200
                if status_code == '403':
                    status_code = f"    \033[33m{status_code}\033[0m"  # Yellow color for status 403
                    subdomain = f"{subdomain}"  # Underline subdomains with status 403
                if status_code == '404':
                    status_code = f"\033[31m{status_code}\033[0m"  # Red color for status 404
                    subdomain = f"{subdomain}"  # Underline subdomains with status 404
                print(f"  {status_code:>{max_status_length}}    {subdomain.ljust(40)}")

        else:
            results = []
            for subdomain in subdomains:
                url = subdomain['url']
                print(url)

        # Separation

        #Vulnerability found
        if vulnerable == "Y" or vulnerable == "y":
            class separation():
                print("")
                print("")
                print("")

            with open(website_without_extension + "_vulnerable_parameters.txt", "r") as f:
                data = f.readlines()
                vulnerable_parameters = len(data)

            if len(data) == 0:
                print("File is empty. Exiting...")
                exit()

            params = []
            for d in data:
                params.append(json.loads(d.strip()))

            print(f"\033[4mFound {vulnerable_parameters} potential vulnerable parameters in the following URL's:\033[0m")
            print("")
            print("{:<12} {:<70}".format('\033[1mParameter\033[0m', '\033[1m   URL\033[0m'))
            print("-" * 80)
            for p in params[:20]:
                print("{:<12} {:<70}".format(p['parameter'], p['url']))
            print("...")
            print("")
            print(f"All the vulnerability found have been saved in ---> {website_without_extension}_vulnerable_parameters.txt")
        else:
            pass

    if __name__ == '__main__':
        class start_UI():
            print("")
            print("=" * 45)
            print("")
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_analyzing = executor.submit(analyzing, website, website_without_extension, custom_wordlist)
            animation(future_analyzing)
            subdomains = future_analyzing.result()
            class start_UI():
                print("")
                print("=" * 45)
                print("")
            output(active, vulnerable, subdomains, website_without_extension)

#=================================================

# Retrieve Variables
website = Set_Variables.website
active = Set_Variables.active
vulnerable = Set_Variables.vulnerable
website_without_extension = Set_Variables.website_without_extension
custom_wordlist = Set_Variables.custom_wordlist

# Launch Functions
wayback_crawler(website, active, vulnerable, website_without_extension, custom_wordlist)