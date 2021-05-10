# Analyzing Apache logs

The following script is intended to automate possible unwanted o rare `http` activity based on an Apache log file.

This script is divided into two parts. The first one is a simple JSON parser for Apache log files, based on a known record structure. And the second half is an analysis mechanism for diagnosing and detect possible malicious request attempts made to a server based on the `user agents`, `status codes`, and `activity ratio`.

These three scenarios are evaluated by a threshold percentage which will vary in the possible success cases, false positives, or real attack attempts.

## Work it works?

With a given and legit `Apache` log file (could be the famous `access.log` file), and the magic of `regex` patterns, all the log records are converted into valid JSON objects that later will be appended in a JSON file set by your output flag argument.

Python is used to find specific hints inside the logs records, and depending on the hardcoded criteria set in the user agents and the number of status codes detected against the threshold value, the program will determine whether the request is malicious or not, and will be returned in a dictionary data object.

## Usage

Just run: `python3 apache_logs.py -i /path/to/logs.log -o /path/to/output.json`

Here's the working example:

Run: `python3 malicious.py -i logs/malicious_access.log -o logs/traffic.json`

## Output Example

```
[
  {
    "category": "Web Directory Enumeration",
    "client_ip": "192.168.37.128",
    "datetime": "29/Jan/2020:18:33:46 -0500"
  }
]
```

## Credits

 - [David E Lares](https://twitter.com/davidlares3)

## License

 - [MIT](https://opensource.org/licenses/MIT)
