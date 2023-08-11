# history-fp
:feet: Create a behavioral fingerprint based on your zsh command line history

## Description
`history-fp` project allows you to create a unique fingerprint based on your zsh history file. 
This fingerprint can be safely shared with anyone to compare your usage behavior and discover similarities. 
You can think of it as a system that answers the question "How similar do we work?" or "How similar are we?"

No 3rd party services or APIs are involved, everything is calculated locally.

## Quick Example
You can use the following example fingerprint to compare it with your usage behavior, the payload is:
```
bmFtZUBleGFtcGxlOjB4NDgwOTUxNDNkOTNlZWMxMDo2NDozOjM6MTAwOjE6MToxMA==
```
- _Which decodes to:_
```
name@example:0x48095143d93eec10:64:3:3:100:1:1:10
```
- _Where the representation format is:_
```
<contact info>:hex(<fingerprint>):<hash bits>:<shingle size>:<command complexity>:<max commands>:<included flags>:<case insensitive>:<segment threshold>
```
- _Which was created as:_
```python
from fp import HistoryFingerprint, encode_fp

commands = ["ls", "docker ps", "kubectl", "python3", "git commit"] * 20  # example
fp = HistoryFingerprint(commands).calculate()
payload = encode_fp(fp, "name@example")
print(payload)
```
The following operation will calculate your fp and compare it with the example above:
```
make compare payload=bmFtZUBleGFtcGxlOjB4NDgwOTUxNDNkOTNlZWMxMDo2NDozOjM6MTAwOjE6MToxMA==
```
In my case, the example has almost 44% similarity comparing with my behavior:
```
match with 'name@example': 43.75% similarity (different)
```
For you, it can be totally different.

Same way, you can share your fingerprint with someone else to compare. Please, refer to the `Usage` section for more details or use `--help` on module.


## Requirements
No specific requirements or 3rd party dependencies are required, everything is included.
- Python 3
- `python-hashes` package (required modules are already included in the project, [official repository](https://github.com/sean-public/python-hashes))

## Usage
### Create a fingerprint
Create a personal fingerprint based on your zsh history file:
```bash
make create contact=<nickname, username, e-mail, etc.>
```
Or:
```bash
python3 fp.py create --history ~/.zsh_history --contact <nickname, username, e-mail, etc.>
```
Expected result:
```bash
payload with fingerprint: <payload>
```
This payload can be safely shared with anyone to compare.

### Compare a shared fingerprint
Compare someone's fingerprint (as a payload) with your personal fingerprint:
```bash
make compare payload=<payload>
```
Or:
```bash
python3 fp.py compare --history ~/.zsh_history --payload <payload>
```
Expected result:
```bash
match with '<contact>': 100.0% similarity (identical)
```
