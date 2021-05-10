from typing import List
import argparse
import json
import re

# iterating log file
def get_matches(log_file, regex):
    with open(log_file, 'r') as f:
        line = f.readline()
        while line:
            line = line.strip()
            matches = re.match(regex, line)
            if not matches:
                print('WARNING, unable to parse log message: {}'.format(line))
                line = f.readline()
                continue
            groups = matches.groups()
            yield groups
            line = f.readline()

# converting apache log formats in JSON
def parse_apache_logs(log_file):
    logs = []
    # regex pattern
    regex = re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3}) \- \- \[(.+)\] "(\w+) (\S+) (\S+)" (\d+) ([\d\-]+) "(\S+)"(?: "(.+)")?$', re.IGNORECASE)
    # iterating log file
    for groups in get_matches(log_file, regex):
        if groups[0] == '127.0.0.1':
            continue
        # dictionary format
        log_dict = {'client_ip': groups[0], 'datetime': groups[1], 'request_method': groups[2],
                    'request_path': groups[3], 'protocol': groups[4], 'response_code': groups[5],
                    'response_size': groups[6], 'referer': groups[7], 'user_agent': groups[8]}
        logs.append(log_dict)
    return logs

def analyze_apache_logs(input_file, http_response_code_threshold=0.5):
    malicious_logs = []
    http_response_ratios = {}
    with open(input_file, 'r') as f:
        logs = json.load(f)
    # look for specific message types and count number of HTTP 200 response codes versus error codes
    for log in logs:
        if 'Nmap Scripting Engine' in log['user_agent']:
            mal_data = {'category': 'NMAP Scanning', 'client_ip': log['client_ip'], 'datetime': log['datetime']}
            malicious_logs.append(mal_data)
        if log['client_ip'] not in http_response_ratios:
            http_response_ratios[log['client_ip']] = {'200': 0, 'error': 0}
        if log['response_code'] != '200':
            http_response_ratios[log['client_ip']]['error'] += 1
        else:
            http_response_ratios[log['client_ip']]['200'] += 1
        http_response_ratios[log['client_ip']]['datetime'] = log['datetime']

    # process HTTP response code ratios and append to malicious logs if ratio is under given threshold
    for k, v in http_response_ratios.items():
        http_200 = v['200']
        http_error = v['error']
        total = http_200 + http_error
        ratio = http_200 / total
        if ratio < http_response_code_threshold:
            v['ratio'] = ratio
            v['category'] = 'Web Directory Enumeration'
            tmp_dict = {'category': 'Web Directory Enumeration', 'client_ip': k, 'datetime': v['datetime']}
            malicious_logs.append(tmp_dict)
    # JSON object with positive cases of malicious code attempts
    return malicious_logs

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='This application analyzes parsed log files to find malicious activity.')
    parser.add_argument('-i', '--input', required=True, help='Raw Apache log file to read from')
    parser.add_argument('-o', '--output', help='Intermediate JSON transformed object')
    args = parser.parse_args()

    # arguments
    input_file = args.input
    output = args.output

    # processing intermediate traffic json
    print('[*] Processing, please wait ...')
    parsed = parse_apache_logs(input_file)
    with open(output, 'w') as o:
        json.dump(parsed, o, indent=2)

    # analyzing malicious on .json file (ratio - status codes - user_agent and more)
    malicious_logs = analyze_apache_logs(output)
    print(json.dumps(malicious_logs, indent=2))
