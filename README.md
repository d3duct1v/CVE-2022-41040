# CVE-2022-41040
Code set relating to CVE-2022-41040.

scanner.py is a Python based scanner testing for the CVE-2022-41040.

## Requirements
The only additional modules needed to run this code is requests and colorama.
```shell
pip install -r requirements.txt
```

## Usage
This script takes a single URL or a list of URLs.
Leave the trailing '/' for the base url.

```shell
usage: scanner.py [-h] (-i INFILE | -t TARGET)
```

List:
```shell
python3 scanner.py -i test_sites
```
Single site:
```
python3 scanner.py -t http://example.com
```
