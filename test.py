#!/usr/bin/env python3

import subprocess
import sys
import time
import urllib.request, urllib.parse, urllib.error
import os
import socket
import html.parser
import http.cookiejar

class HTTPNoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, hdrs, newurl):
        return None

TIMEOUT = 10 # seconds
CURRENT = "hw7"
SERVER = None
SESSIONID = None
COOKIE_JAR = http.cookiejar.CookieJar()
OPENER = urllib.request.build_opener(
    HTTPNoRedirectHandler(),
    urllib.request.HTTPCookieProcessor(COOKIE_JAR)
)

def name(n):
    def decorator(f):
        f.phase_name = n
        return f
    return decorator

def download_file(url, path):
    resp = urllib.request.urlopen(url)
    with open(path, "wb") as out:
        while True:
            s = resp.read1()
            if not s: break
            out.write(s)

def prerun(hw):
    if hw not in [HW1, HW2, HW3a, HW7]:
        download_file("https://raw.githubusercontent.com/utah-cs3550-fa24/assignments/main/resources/makedata.py", "makedata.py")
        assert os.path.exists("makedata.py")
        if os.path.exists("db.sqlite3"): os.unlink("db.sqlite3")
        subprocess.run(["python3", "manage.py", "migrate"],
                       check=True, executable=sys.executable, timeout=TIMEOUT)
        subprocess.run(["python3", "makedata.py"],
                       check=True, executable=sys.executable, timeout=TIMEOUT)
    if hw in [HW7]:
        subprocess.run(["python3", "-m", "pip", "install", "dnspython"])
        import dns.resolver


@name("Server starts up")
def start_server(timeout=TIMEOUT):
    start_time = time.time()
    server = subprocess.Popen(
        ["python3", "manage.py", "runserver", "--noreload"],
        executable=sys.executable,
        stdin=None, stdout=sys.stdout, stderr=sys.stderr,
        encoding="latin1"
    )
    while time.time() - start_time < timeout:
        current_time = time.time()
        timeout_left = timeout - (current_time - start_time)
        try:
            s = socket.create_connection(("localhost", 8000), timeout=timeout_left)
        except OSError:
            time.sleep(0.1)
        else:
            s.close()
            break
    global SERVER
    SERVER = server

def check_get(url):
    @name(f"Check that {url} exists")
    def f(timeout=TIMEOUT):
        start_server(timeout)
        response = urllib.request.urlopen("http://localhost:8000" + url, timeout=timeout)
        assert 200 <= response.status < 300, \
            f"Expected a successful response, got {response.status} {response.reason}"
    return f

class HTMLFindElement(html.parser.HTMLParser):
    def __init__(self, tagname):
        html.parser.HTMLParser.__init__(self)
        self.found = []
        self.tagname = tagname

    def handle_starttag(self, tag, attrs):
        if tag == self.tagname:
            html_attrs = "".join(f" {k}='{v}'" for k, v in attrs)
            print(f"Found <{tag}{html_attrs}>")
            self.found.append(dict(attrs))

def check_has_css(url, css):
    @name(f"Check that {url} links to {css}")
    def f(timeout=TIMEOUT):
        start_server(timeout)
        response = urllib.request.urlopen("http://localhost:8000" + url, timeout=timeout)
        assert 200 <= response.status < 300, \
            f"Expected a successful response, got {response.status} {response.reason}"
        parser = HTMLFindElement("link")
        parser.feed(response.read().decode('latin1')) # to avoid ever erroring in decode
        for link in parser.found:
            if "rel" in link and link["rel"] == "stylesheet":
                if link["href"] == css:
                    assert "title" not in link, "<link> element should not have title attribute"
                    assert "media" not in link, "<link> element should not have media attribute"
                    if "type" in link: assert link["type"] == "text/css", "Stylesheets should have type=text/css"
                    return
        else:
            raise ValueError(f"Could not find a <link> element with href={css}")
    return f

def check_has_js(url, js):
    @name(f"Check that {url} links to {js}")
    def f(timeout=TIMEOUT):
        start_server(timeout)
        response = urllib.request.urlopen("http://localhost:8000" + url, timeout=timeout)
        assert 200 <= response.status < 300, \
            f"Expected a successful response, got {response.status} {response.reason}"
        parser = HTMLFindElement("script")
        parser.feed(response.read().decode('latin1')) # to avoid ever erroring in decode
        for script in parser.found:
            if "src" in script and script["src"] == js:
                assert "type" in script, "<script> element should have type"
                assert script["type"] == "module", "<script> element should use type=module"
                assert "async" not in script, "<script> should not use async"
                assert "defer" not in script, "<script> should not use defer, that's implied for modules"
                return
        else:
            raise ValueError(f"Could not find a <script> element with src={js}")
    return f

def check_has_form(url, method, action):
    @name(f"Check that {url} has a form pointing to {action}")
    def f(timeout=TIMEOUT):
        start_server(timeout)
        response = urllib.request.urlopen("http://localhost:8000" + url, timeout=timeout)
        assert 200 <= response.status < 300, \
            f"Expected a successful response, got {response.status} {response.reason}"
        parser = HTMLFindElement("form")
        parser.feed(response.read().decode('latin1')) # to avoid ever erroring in decode
        for form in parser.found:
            if "method" in form and form["method"].casefold() == method.casefold():
                print(f"Form has method={method}, as expected")
            elif "method" not in form:
                print(f"ERROR: Form does not have method attribute")
                continue
            else:
                print(f'ERROR: Form has method=\"{form["method"]}\", not method=method')
                continue
            if "action" in form and form["action"].rstrip("/") == action.rstrip("/"):
                print(f"Form has action={action}, as expected")
            elif "action" not in form:
                print(f"ERROR: Form does not have action attribute")
                continue
            else:
                print(f'ERROR: Form has action=\"{form["action"]}\", not action=action')
                continue
            break
        else:
            raise ValueError(f"Could not find <form method={method} action={action}> element")
    return f

def check_submit_redirect(url, fields, next_url):
    @name(f"Submitting form at {url} with {fields} should redirect to {next_url}")
    def f(timeout=TIMEOUT):
        start_server(timeout)
        response = OPENER.open("http://localhost:8000" + url, timeout=timeout)
        assert 200 <= response.status < 300, \
            f"Expected a successful response, got {response.status} {response.reason}"
        parser = HTMLFindElement("input")
        parser.feed(response.read().decode('latin1')) # to avoid ever erroring in decode
        filled_fields = {}
        for iput in parser.found:
            if "name" not in iput: continue
            if iput["name"].casefold() in fields:
                print("Found input field", iput["name"])
                filled_fields[iput["name"].casefold()] = fields[iput["name"].casefold()]
            elif "type" in iput and iput["type"].casefold() == "hidden":
                if "name" not in iput or "value" not in iput: continue
                print("Saving hidden input", iput["name"], "of", iput["value"])
                filled_fields[iput["name"]] = iput["value"]
            else:
                print("Confused by extra input element", iput, "skipping")
        if set(filled_fields) < set(fields):
            remaining_fields = set(fields) - set(filled_fields)
            raise ValueError(f"Could not find input field for {', '.join(remaining_fields)}")
        data = urllib.parse.urlencode(dict(filled_fields)).encode("utf8")
        try:
            form_response = OPENER.open("http://localhost:8000" + url, data, timeout=timeout)
        except urllib.error.HTTPError as e:
            assert 300 <= e.code < 400, \
                f"Expected a redirect, got {e.code} {e.reason}"
            location = e.headers["Location"]
        else:
            assert False, \
                f"Expected a redirect, got {form_response.status} {form_response.reason}"
        assert location == next_url, \
            f"Expected a redirect to {next_url}, got redirect to {location}"
        for cookie in COOKIE_JAR:
            if cookie.name == "sessionid":
                global SESSIONID
                SESSIONID = cookie.value
                print(f"Received a session cookie, {SESSIONID}")
                break
            else:
                print(f"Skipping uninteresting cookie for {cookie.name}")
    return f

# TODO: Make sure it works even if the next input is first
def check_login(url, user, pwd):
    @name(f"Log in to {url} as {user}:{pwd}")
    def f(timeout=TIMEOUT):
        start_server(timeout)
        response = OPENER.open("http://localhost:8000" + url, timeout=timeout)
        assert 200 <= response.status < 300, \
            f"Expected a successful response, got {response.status} {response.reason}"
        parser = HTMLFindElement("input")
        parser.feed(response.read().decode('latin1')) # to avoid ever erroring in decode
        username_name = None
        password_name = None
        other_fields = []
        for iput in parser.found:
            if "name" not in iput: continue
            if "type" in iput and iput["type"].casefold() == "hidden":
                if "name" not in iput or "value" not in iput: continue

                print("Saving hidden input", iput["name"], "of", iput["value"])
                other_fields.append((iput["name"], iput["value"]))
            elif "type" in iput and iput["type"] == "password":
                password_name = iput["name"]
            elif not username_name:
                username_name = iput["name"]
            else:
                print("Confused by extra input element", iput)
        if not username_name:
            raise ValueError(f"Count not find username input field on {url}")
        if not password_name:
            raise ValueError(f"Count not find password input field on {url}; make sure to use type=password")
        print(f"Found <input name={username_name}> for username")
        print(f"Found <input name={password_name}> for password")
        data = urllib.parse.urlencode({
            username_name: user,
            password_name: pwd,
        } | dict(other_fields)).encode("utf8")
        login_response = OPENER.open("http://localhost:8000" + url, data, timeout=timeout)
        assert 200 <= login_response.status < 300, \
            f"Expected a redirect from a successful login, got {login_response.status} {login_response.reason}"
        for cookie in COOKIE_JAR:
            if cookie.name == "sessionid":
                global SESSIONID
                SESSIONID = cookie.value
                print(f"Received a session cookie, {SESSIONID}")
                break
            else:
                print(f"Skipping uninteresting cookie for {cookie.name}")
        else:
            raise ValueError("Did not receive a session cookie!")
    return f

def check_not_login(url, uname, pwd):
    @name(f"Log in to {url} as {uname}:{pwd} should fail")
    def f(timeout=TIMEOUT):
        try:
            check_login(url, uname, pwd)(timeout)
        except ValueError as e:
            print(f"Ran into expected issue: {e}")
        else:
            print("Login succeeded; that's bad, it should fail!")
    return f

def check_get_logged_in(url, uname, pwd, url2):
    @name(f"Check {url2} after logging in as {uname}:{pwd}")
    def f(timeout=TIMEOUT):
        check_login(url, uname, pwd)(timeout)
        assert SESSIONID, "Could not find a session id, please report this immediately"
        response = OPENER.open("http://localhost:8000" + url2)
        assert uname in response.read().decode("latin1"), \
            f"Could not find {uname} on {url2} after logging in as {uname}:{pwd}"
        print(f"Found {uname} in {url2}")
    return f


def check_logout(url, uname, pwd, url2):
    @name(f"Check {url2} after logging in as {uname}:{pwd}")
    def f(timeout=TIMEOUT):
        check_login(url, uname, pwd)(timeout)
        assert SESSIONID, "Could not find a session id, please report this immediately"
        response = OPENER.open("http://localhost:8000" + url2, timeout=timeout)
        assert 200 <= response.status < 300, \
            f"Expected a successful logout, got {login_response.status} {login_response.reason}"
        for cookie in COOKIE_JAR:
            if cookie.name == "sessionid":
                assert cookie.value in ["", '""'], "Got a new sessionid cookie instead of clearing the existing one"
        print("Sessionid cookie gone, successful logout")
    return f

def check_contains(url, s):
    @name(f"Check that {url} contains the string {s!r}")
    def f(timeout=TIMEOUT):
        start_server(timeout)
        response = urllib.request.urlopen("http://localhost:8000" + url, timeout=timeout)
        assert 200 <= response.status < 300, \
            f"Expected a successful response, got {response.status} {response.reason}"
        assert s in response.read().decode('latin1'), \
            f"Count not find {s!r} in {url}"
    return f

        

@name("Look for a DOMAIN.md file")
def check_dns_file():
    names = [
        "DOMAIN.md", "domain.md", "Domain.md",
        "DOMAINS.md", "domains.md", "Domains.md",
        "DOMAIN.txt", "domain.txt", "Domain.txt",
        "DOMAINS.txt", "domains.txt", "Domains.txt",
    ]
    for i in names:
        if os.path.exists(i):
            with open(i) as f:
                domain = next(f).strip()
                assert " " not in domain, f"Expected domain, got {domain!r}"
                assert "." in domain, f"Expected domain, got {domain!r}"
            return

@name("Check that the TXT record matches")
def check_dns_txt_record():
    import dns.resolver
    names = [
        "DOMAIN.md", "domain.md", "Domain.md",
        "DOMAINS.md", "domains.md", "Domains.md",
        "DOMAIN.txt", "domain.txt", "Domain.txt",
        "DOMAINS.txt", "domains.txt", "Domains.txt",
    ]
    repo_name = os.getenv("GITHUB_REPOSITORY").split("/", 1)[1].replace("PE-A", "PENA")
    for i in names:
        if os.path.exists(i):
            with open(i) as f:
                domain = next(f).strip()
                assert " " not in domain, f"Expected domain, got {domain!r}"
                assert "." in domain, f"Expected domain, got {domain!r}"
                break

    answers = dns.resolver.query(domain, "TXT")
    matched = False
    attempted = False
    for rdata in answers:
        for txt_string in rdata.strings:
            txt_string = txt_string.decode("latin1")
            print("Found TXT record", txt_string)
            attempted = True
            if match_txt_record(txt_string, repo_name):
                matched = True
                print("  Matched repository name")
            else:
                print("  No match for repository name")
    assert matched, "Did not find a matching TXT record" + \
        ("" if not attempted else f". Please TXT record to {repo_name}")

def match_txt_record(record, repo):
    r_parts = record.casefold().replace("-", " ").split()
    n_parts = repo.casefold().replace("-", " ").split()
    overlap = set(r_parts) & set(n_parts)
    if len(overlap) >= 2:
        return True
    else:
        return False


HW1 = [
    start_server,
    check_get("/static/test.html"),
]

HW2 = [
    start_server,
    check_get("/static/main.css"),
    check_has_css("/static/index.html", "/static/main.css"),
    check_has_css("/static/assignment.html", "/static/main.css"),
    check_has_css("/static/submissions.html", "/static/main.css"),
    check_has_css("/static/profile.html", "/static/main.css"),
    check_has_css("/static/login.html", "/static/main.css"),
]

HW3a = [
    start_server,
    check_get("/"),
    check_get("/1/"),
    check_get("/1/submissions"),
    check_get("/profile"),
    check_get("/profile/login"),
]

HW3 = [
    start_server,
    check_get("/"),
    check_get("/1/"),
    check_get("/1/submissions"),
    check_get("/profile"),
    check_get("/profile/login"),
]

HW4 = [
    start_server,
    check_has_form("/1/submissions", "post", "/1/submissions"),
    check_submit_redirect("/1/submissions", { "grade-1": "0.0" }, "/1/submissions")
]

HW5 = [
    start_server,
    check_has_form("/profile/login/", "post", "/profile/login/"),
    check_login("/profile/login/", "pavpan", "pavpan"),
    check_login("/profile/login/", "g", "g"),
    check_login("/profile/login/", "a", "a"),
    check_not_login("/profile/login/", "a", "b"),
    check_get_logged_in("/profile/login/", "a", "a", "/profile/"),
    check_get_logged_in("/profile/login/", "b", "b", "/profile/"),
    check_logout("/profile/login/", "a", "a", "/profile/logout/"),
]

HW6 = [
    start_server,
    check_get("/static/main.js"),
    check_has_js("/profile/login/", "/static/main.js"),
    check_contains("/static/main.js", "console.log"),
    check_contains("/static/main.js", "import { $ } from \"/static/jquery/src/jquery.js\";"),
]

HW7 = [
    check_dns_file,
    check_dns_txt_record,
]

HWS = {
    "hw1": HW1,
    "hw2": HW2,
    "hw3a": HW3a,
    "hw3": HW3,
    "hw4": HW4,
    "hw5": HW5,
    "hw6": HW6,
    "hw7": HW7,
}

def run(hw, part):
    prerun(hw)
    assert part < len(hw), f"Homework does not have a part {i + 1}"
    hw[part]()
    return 0

def gh(hw):
    assert os.getenv("GITHUB_ENV"), "Cannot execute gh subcommand without GITHUB_ENV set"
    with open(os.getenv("GITHUB_ENV"), "a") as ghenv:
        ghenv.write(f"HWPARTS={len(hw)}\n")
        for i in range(5):
            if i < len(hw):
                name = getattr(hw[i], "phase_name", hw[i].__name__)
            else:
                name = f"No phase {i + 1} for this homework"
            ghenv.write(f"HWPART{i+1}={name}\n")
    print("Saved Github information in environment variables")
    return 0
    
def usage():
    print("USAGE: test.py hw<N> part<M>      Run part M of homework N")
    print("       test.py gh                 Save Github information")
    return 1

def main():
    hwname = sys.argv[1] if len(sys.argv) > 1 else "--help"
    if hwname == "current": hwname = CURRENT
    try:
        if hwname == "--help":
            return usage()
        elif hwname in HWS:
            hw = HWS[hwname]
            part = sys.argv[2] if len(sys.argv) > 2 else "--error"
            if part == "--error" or part == "--help":
                return usage()
            elif part == "gh":
                return gh(hw)
            elif part.isdigit() and int(part) - 1 < len(hw):
                return run(hw, int(part) - 1)
            else:
                print(f"Invalid part {part} of homework {hwname}; it only has {len(hw)} parts")
                return 1
        else:
            print(f"Invalid homework {hwname}; valid options are", " ".join(HWS))
            return 1
    except (OSError, AssertionError) as e:
        name = type(e).__name__
        message = str(e)
        print(f"{name}: {message}")
        return 127

if __name__ == "__main__":
    errcode = main()
    if SERVER: SERVER.kill()
    sys.exit(errcode)
