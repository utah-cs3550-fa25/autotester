#!/usr/bin/env python3

import subprocess
import sys
import time
import urllib.request, urllib.parse, urllib.error
import os
import socket
import html.parser
import http.cookiejar
import re
import ssl
import io

TIMEOUT = 10 # seconds
REMOTE_TIMEOUT = 30 # seconds for remote requests
CURRENT = "hw7"
SERVER = None
SESSIONID = None
COOKIE_JAR = http.cookiejar.CookieJar()
OPENER = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(COOKIE_JAR))

# Remote testing globals (for HW7)
REMOTE_DOMAIN = None
REMOTE_IP = None
REMOTE_BASE_URL = None  # Will be set to https://domain or http://domain or http://ip
REMOTE_COOKIE_JAR = http.cookiejar.CookieJar()
REMOTE_SSL_CONTEXT = ssl.create_default_context()
REMOTE_SSL_CONTEXT.check_hostname = False
REMOTE_SSL_CONTEXT.verify_mode = ssl.CERT_NONE  # Allow self-signed certs initially
REMOTE_OPENER = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(REMOTE_COOKIE_JAR),
    urllib.request.HTTPSHandler(context=REMOTE_SSL_CONTEXT)
)

def name(n):
    def decorator(f):
        f.phase_name = n
        return f
    return decorator

def git_clone(url, path):
    subprocess.run(["git", "clone", url, path])

def setup():
    subprocess.run(["python3", "-m", "pip", "install", "django>=5", "pillow", "dnspython"])
    subprocess.run(["python3", "manage.py", "migrate"])

def prerun(hw):
    if hw in [HW3, HW4, HW5, HW6]:
        git_clone("https://github.com/utah-cs3550-fa25/assignments.git", "assignments")
        assert os.path.exists("assignments/assets/makedata.py")
        if os.path.exists("db.sqlite3"): os.unlink("db.sqlite3")
        subprocess.run(["python3", "manage.py", "migrate"],
                       check=True, executable=sys.executable, timeout=TIMEOUT)
        subprocess.run(["python3", "assignments/assets/makedata.py"],
                       check=True, executable=sys.executable, timeout=TIMEOUT)
    if hw in [HW7]:
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

class HTMLFindFormInput(html.parser.HTMLParser):
    def __init__(self, method, action):
        html.parser.HTMLParser.__init__(self)
        self.found = []
        self.in_form = False
        self.method = method
        self.action = action
        self.current_textarea = None
        self.textarea_content = ""

    def handle_starttag(self, tag, attrs):
        if tag == "form":
            html_attrs = "".join(f" {k}='{v}'" for k, v in attrs)
            print(f"Found form <{tag}{html_attrs}>")
            attrs = dict(attrs)
            if "method" not in attrs or attrs["method"].casefold() != self.method:
                print(f"  Skipping, method {attrs.get('method', '')!r} but looking for {self.method}")
                return
            if "action" not in attrs or attrs["action"] not in (self.action, self.action + "/"):
                print(f"  Skipping, action {attrs.get('action', '')!r} but looking for {self.action}")
                return
            print(f"  Collecting input elements")
            self.in_form = True
            self.action = attrs["action"]
        if tag == "input" and self.in_form:
            html_attrs = "".join(f" {k}='{v}'" for k, v in attrs)
            print(f"Found <{tag}{html_attrs}>")
            self.found.append(dict(attrs))
        if tag == "textarea" and self.in_form:
            self.current_textarea = dict(attrs)
            self.textarea_content = ""

    def handle_data(self, data):
        if self.current_textarea is not None:
            self.textarea_content += data

    def handle_endtag(self, tag):
        if tag == "form" and self.in_form:
            self.in_form = False
        if tag == "textarea" and self.current_textarea is not None:
            self.current_textarea["value"] = self.textarea_content
            self.current_textarea["_is_textarea"] = True
            self.found.append(self.current_textarea)
            self.current_textarea = None


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

def check_meta_viewport(url):
    @name(f"Check that {url} has a <meta name=viewport> tag")
    def f(timeout=TIMEOUT):
        start_server(timeout)
        response = urllib.request.urlopen("http://localhost:8000" + url, timeout=timeout)
        assert 200 <= response.status < 300, \
            f"Expected a successful response, got {response.status} {response.reason}"
        parser = HTMLFindElement("meta")
        parser.feed(response.read().decode('latin1')) # to avoid ever erroring in decode
        for meta in parser.found:
            if "name" in meta and meta["name"] == "viewport":
                assert "content" in meta, "<meta> element should have a content element"
                parts = [part.strip() for part in meta["content"].split(",") if part.strip()]
                assert "width=device-width" in parts, "<meta> content should have width=device-width"
                assert "initial-scale=1" in parts, "<meta> content should have initial-scale=1"
                assert len(parts) == 2, "<meta> content should have two fields"
                return
        else:
            raise ValueError(f"Could not find a <meta name=viewport>")
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
            if "action" in form and form["action"].rstrip("/") == action.rstrip("/"):
                print(f"SUCCESS: Found form with action={action}, grading")
            elif "action" not in form:
                print(f"ERROR: Form does not have action attribute")
                continue
            elif url.endswith("/edit") and action.endswith("/edit") and "action" in form and \
                 form["action"].rstrip("/") == action.rstrip("/edit"):
                # TODO: bug that is grandfathered in for Fall 2025
                print(f"ALLOWED: Found form with action={form['action']}, passing")
                print(f"         The form should actually point to {action}")
                print(f"         However, there was a bug in the auto-tester so")
                print(f"         your (incorrect) form is being accepted.")
                
            else:
                print(f"NOTE: Found form with action=\"{form['action']}\", skipping")
                continue

            if "method" in form and form["method"].casefold() == method.casefold():
                print(f"SUCCESS: Form has method={method}, as expected")
            elif "method" not in form:
                print(f"ERROR: Form does not have method attribute")
                continue
            else:
                print(f'ERROR: Form has method=\"{form["method"]}\", not method={method}')
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
        parser = HTMLFindFormInput("post", url)
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
        nonlocal url
        start_server(timeout)
        try:
            response = OPENER.open("http://localhost:8000" + url, timeout=timeout)
        except urllib.error.HTTPError:
            url += "/"
            response = OPENER.open("http://localhost:8000" + url, timeout=timeout)
        assert 200 <= response.status < 300, \
            f"Expected a successful response, got {response.status} {response.reason}"
        parser = HTMLFindFormInput("post", url)
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
            raise ValueError(f"Could not find username input field on {url}")
        if not password_name:
            raise ValueError(f"Could not find password input field on {url}; make sure to use type=password")
        print(f"Found <input name={username_name}> for username")
        print(f"Found <input name={password_name}> for password")
        data = urllib.parse.urlencode({
            username_name: user,
            password_name: pwd,
        } | dict(other_fields)).encode("utf8")
        login_response = OPENER.open("http://localhost:8000" + parser.action, data, timeout=timeout)
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

def check_get_logged_in(url, uname, pwd, url2, content):
    @name(f"Check {url2} after logging in as {uname}:{pwd}")
    def f(timeout=TIMEOUT):
        check_login(url, uname, pwd)(timeout)
        assert SESSIONID, "Could not find a session id, please report this immediately"
        response = OPENER.open("http://localhost:8000" + url2)
        assert content in response.read().decode("latin1"), \
            f"Could not find {content!r} on {url2} after logging in as {uname}:{pwd}"
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
    s_name = s if isinstance(s, str) else s.pattern.replace(r"\s*", " ").replace("\\", "")
    @name(f"Check that {url} contains the string {s_name!r}")
    def f(timeout=TIMEOUT):
        start_server(timeout)
        response = urllib.request.urlopen("http://localhost:8000" + url, timeout=timeout)
        assert 200 <= response.status < 300, \
            f"Expected a successful response, got {response.status} {response.reason}"
        if isinstance(s, str):
            assert s in response.read().decode('latin1'), \
                f"Count not find {s_name!r} in {url}"
        elif isinstance(s, re.Pattern):
            assert s.search(response.read().decode('latin1')), \
                f"Count not find {s_name!r} in {url}"
        else:
            raise Exception(f"Invalid pattern {s!r}")
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
    domain = None
    for i in names:
        if os.path.exists(i):
            with open(i) as f:
                domain = next(f).strip()
                assert " " not in domain, f"Expected domain, got {domain!r}"
                assert "." in domain, f"Expected domain, got {domain!r}"
                break
    assert domain, "No domain found in DOMAIN.md"
        

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
        ("" if not attempted else f". Please change TXT record to {repo_name}")

def match_txt_record(record, repo):
    r_parts = record.casefold().replace("-", " ").split()
    n_parts = repo.casefold().replace("-", " ").split()
    overlap = set(r_parts) & set(n_parts)
    if len(overlap) >= 2:
        return True
    else:
        return False


# =============================================================================
# HW7 Remote Testing Helpers
# =============================================================================

def get_domain_file_contents():
    """Read domain and optionally IP from DOMAIN.md file."""
    names = [
        "DOMAIN.md", "domain.md", "Domain.md",
        "DOMAINS.md", "domains.md", "Domains.md",
        "DOMAIN.txt", "domain.txt", "Domain.txt",
        "DOMAINS.txt", "domains.txt", "Domains.txt",
    ]
    for fname in names:
        if os.path.exists(fname):
            with open(fname) as f:
                lines = [line.strip() for line in f.readlines() if line.strip()]
                domain = lines[0] if len(lines) > 0 else None
                ip = lines[1] if len(lines) > 1 else None
                return domain, ip
    return None, None


def is_valid_ip(ip):
    """Check if string is a valid IPv4 address."""
    if not ip:
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def is_valid_domain(domain):
    """Basic domain validation."""
    if not domain:
        return False
    if " " in domain:
        return False
    if "." not in domain:
        return False
    return True


def remote_request(url, data=None, method=None, headers=None, timeout=REMOTE_TIMEOUT):
    """Make a request to a remote server, returning (response, body) or raising."""
    req = urllib.request.Request(url, data=data, method=method)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    response = REMOTE_OPENER.open(req, timeout=timeout)
    body = response.read()
    return response, body


def try_remote_url(base_url, path="/", timeout=REMOTE_TIMEOUT):
    """Try to fetch a URL, returns (response, body) or (None, None) on failure."""
    url = base_url.rstrip("/") + path
    try:
        return remote_request(url, timeout=timeout)
    except Exception as e:
        print(f"  Failed to reach {url}: {e}")
        return None, None


def determine_base_url(domain, ip):
    """Determine the best base URL to use for testing (https > http domain > http ip)."""
    # Try HTTPS with domain first
    if domain:
        try:
            url = f"https://{domain}/"
            print(f"Trying {url}...")
            req = urllib.request.Request(url)
            response = REMOTE_OPENER.open(req, timeout=REMOTE_TIMEOUT)
            print(f"  Success! Using https://{domain}")
            return f"https://{domain}"
        except Exception as e:
            print(f"  HTTPS failed: {e}")
    
    # Try HTTP with domain (may redirect to HTTPS)
    if domain:
        try:
            url = f"http://{domain}/"
            print(f"Trying {url}...")
            req = urllib.request.Request(url)
            response = REMOTE_OPENER.open(req, timeout=REMOTE_TIMEOUT)
            final_url = response.geturl()
            if final_url.startswith("https://"):
                print(f"  Redirected to HTTPS, using https://{domain}")
                return f"https://{domain}"
            print(f"  Success! Using http://{domain}")
            return f"http://{domain}"
        except Exception as e:
            print(f"  HTTP domain failed: {e}")
    
    # Fall back to HTTP with IP
    if ip:
        try:
            url = f"http://{ip}/"
            print(f"Trying {url}...")
            req = urllib.request.Request(url)
            response = REMOTE_OPENER.open(req, timeout=REMOTE_TIMEOUT)
            print(f"  Success! Using http://{ip}")
            return f"http://{ip}"
        except Exception as e:
            print(f"  HTTP IP failed: {e}")
    
    return None


def is_png(data):
    """Check if data starts with PNG magic bytes."""
    return len(data) >= 4 and data[0] == 0x89 and data[1] == 0x50 and data[2] == 0x4E and data[3] == 0x47


def do_remote_login(username, password):
    """Log in to the remote server. Must be called after REMOTE_BASE_URL is set."""
    global REMOTE_BASE_URL
    assert REMOTE_BASE_URL, "REMOTE_BASE_URL must be set before logging in"
    
    # Get login page
    login_url = REMOTE_BASE_URL + "/login"
    response, body = try_remote_url(REMOTE_BASE_URL, "/login")
    if not response:
        response, body = try_remote_url(REMOTE_BASE_URL, "/login/")
        login_url = REMOTE_BASE_URL + "/login/"
    assert response, "Failed to fetch login page"
    
    body_text = body.decode('latin1')
    parser = HTMLFindFormInput("post", "/login")
    parser.feed(body_text)
    
    login_data = {}
    username_field = None
    password_field = None
    
    for iput in parser.found:
        if "name" not in iput:
            continue
        if "type" in iput and iput["type"] == "hidden":
            login_data[iput["name"]] = iput.get("value", "")
        elif "type" in iput and iput["type"] == "password":
            password_field = iput["name"]
        elif not username_field:
            username_field = iput["name"]
    
    assert username_field and password_field, "Could not find login form fields"
    login_data[username_field] = username
    login_data[password_field] = password
    
    data = urllib.parse.urlencode(login_data).encode("utf8")
    try:
        REMOTE_OPENER.open(login_url, data, timeout=REMOTE_TIMEOUT)
    except urllib.error.HTTPError as e:
        if not (300 <= e.code < 400):
            raise
    
    # Verify we got a session cookie
    for cookie in REMOTE_COOKIE_JAR:
        if cookie.name == "sessionid":
            print(f"Logged in as {username}")
            return
    raise AssertionError(f"Failed to log in as {username}")


def create_minimal_png():
    """Create a minimal valid 1x1 red PNG file."""
    # Minimal 1x1 red PNG
    return bytes([
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,  # PNG signature
        0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,  # IHDR chunk
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,  # 1x1
        0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,  # 8-bit RGB
        0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41,  # IDAT chunk
        0x54, 0x08, 0xD7, 0x63, 0xF8, 0xCF, 0xC0, 0x00,  # compressed data
        0x00, 0x00, 0x03, 0x00, 0x01, 0x00, 0x18, 0xDD,
        0x8D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45,  # IEND chunk
        0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82
    ])


# =============================================================================
# HW7 Phase 2 Tests
# =============================================================================

@name("Check that DOMAIN.md contains a valid IP address")
def check_domain_has_ip():
    domain, ip = get_domain_file_contents()
    assert domain, "No domain found in DOMAIN.md"
    assert is_valid_domain(domain), f"Invalid domain format: {domain!r}"
    assert ip, "No IP address found on line 2 of DOMAIN.md"
    assert is_valid_ip(ip), f"Invalid IP address format: {ip!r}"
    print(f"Found domain: {domain}")
    print(f"Found IP: {ip}")
    global REMOTE_DOMAIN, REMOTE_IP
    REMOTE_DOMAIN = domain
    REMOTE_IP = ip


@name("Check that machine at IP address is reachable")
def check_machine_reachable():
    domain, ip = get_domain_file_contents()
    assert ip and is_valid_ip(ip), "No valid IP in DOMAIN.md"
    
    # Try to connect on port 443 first, then 80
    connected = False
    for port in [443, 80]:
        try:
            print(f"Trying to connect to {ip}:{port}...")
            s = socket.create_connection((ip, port), timeout=REMOTE_TIMEOUT)
            s.close()
            print(f"  Successfully connected to port {port}")
            connected = True
            break
        except OSError as e:
            print(f"  Port {port} failed: {e}")
    
    assert connected, f"Could not connect to {ip} on port 80 or 443"


# =============================================================================
# HW7 Phase 3 Tests
# =============================================================================

@name("Check that HTTP request returns response with NGINX server header")
def check_nginx_response():
    domain, ip = get_domain_file_contents()
    global REMOTE_BASE_URL
    
    REMOTE_BASE_URL = determine_base_url(domain, ip)
    assert REMOTE_BASE_URL, "Could not connect to server via HTTPS or HTTP"
    
    response, body = try_remote_url(REMOTE_BASE_URL, "/")
    assert response, f"Failed to get response from {REMOTE_BASE_URL}"
    
    server = response.getheader("Server", "")
    print(f"Server header: {server!r}")
    assert "nginx" in server.lower(), f"Expected Server header to contain 'nginx', got {server!r}"
    print("NGINX detected!")


@name("Check that static files are served")
def check_static_files():
    global REMOTE_BASE_URL
    domain, ip = get_domain_file_contents()
    if not REMOTE_BASE_URL:
        REMOTE_BASE_URL = determine_base_url(domain, ip)
    assert REMOTE_BASE_URL, "Could not determine base URL"
    
    # Check main.css
    response, body = try_remote_url(REMOTE_BASE_URL, "/static/main.css")
    assert response, "Failed to fetch /static/main.css"
    assert response.status == 200, f"Expected 200 for /static/main.css, got {response.status}"
    print(f"/static/main.css: {len(body)} bytes")
    
    # Check main.js
    response, body = try_remote_url(REMOTE_BASE_URL, "/static/main.js")
    assert response, "Failed to fetch /static/main.js"
    assert response.status == 200, f"Expected 200 for /static/main.js, got {response.status}"
    print(f"/static/main.js: {len(body)} bytes")


# =============================================================================
# HW7 Phase 4 Tests
# =============================================================================

@name("Check that homepage loads")
def check_homepage():
    global REMOTE_BASE_URL
    domain, ip = get_domain_file_contents()
    if not REMOTE_BASE_URL:
        REMOTE_BASE_URL = determine_base_url(domain, ip)
    assert REMOTE_BASE_URL, "Could not determine base URL"
    
    response, body = try_remote_url(REMOTE_BASE_URL, "/")
    assert response, "Failed to fetch homepage"
    assert response.status == 200, f"Expected 200 for homepage, got {response.status}"
    assert len(body) > 100, "Homepage seems too short"
    print(f"Homepage loaded: {len(body)} bytes")


@name("Check that login works (user c, password c)")
def check_login_works():
    global REMOTE_BASE_URL
    domain, ip = get_domain_file_contents()
    if not REMOTE_BASE_URL:
        REMOTE_BASE_URL = determine_base_url(domain, ip)
    assert REMOTE_BASE_URL, "Could not determine base URL"
    
    # Get login page to find CSRF token
    login_url = REMOTE_BASE_URL + "/login"
    print(f"Fetching login page: {login_url}")
    response, body = try_remote_url(REMOTE_BASE_URL, "/login")
    if not response:
        # Try with trailing slash
        response, body = try_remote_url(REMOTE_BASE_URL, "/login/")
        login_url = REMOTE_BASE_URL + "/login/"
    assert response, "Failed to fetch login page"
    
    # Parse to find form inputs
    body_text = body.decode('latin1')
    parser = HTMLFindFormInput("post", "/login")
    parser.feed(body_text)
    
    # Build login data
    login_data = {}
    username_field = None
    password_field = None
    
    for iput in parser.found:
        if "name" not in iput:
            continue
        if "type" in iput and iput["type"] == "hidden":
            login_data[iput["name"]] = iput.get("value", "")
        elif "type" in iput and iput["type"] == "password":
            password_field = iput["name"]
        elif not username_field:
            username_field = iput["name"]
    
    assert username_field, "Could not find username field"
    assert password_field, "Could not find password field"
    
    login_data[username_field] = "c"
    login_data[password_field] = "c"
    
    print(f"Logging in with {username_field}=c, {password_field}=c")
    data = urllib.parse.urlencode(login_data).encode("utf8")
    
    # Use the form's action URL (with trailing slash) to avoid POST->GET redirect
    post_url = REMOTE_BASE_URL + parser.action
    try:
        response = REMOTE_OPENER.open(post_url, data, timeout=REMOTE_TIMEOUT)
    except urllib.error.HTTPError as e:
        if 300 <= e.code < 400:
            print(f"Login redirected to {e.headers.get('Location', 'unknown')}")
            response = e
        else:
            raise
    
    # Check for session cookie
    session_found = False
    for cookie in REMOTE_COOKIE_JAR:
        print(f"Cookie: {cookie.name}={cookie.value[:20]}...")
        if cookie.name == "sessionid":
            session_found = True
    
    assert session_found, "Did not receive session cookie after login"
    print("Login successful!")


@name("Check that recipe edit page works")
def check_recipe_edit():
    global REMOTE_BASE_URL
    domain, ip = get_domain_file_contents()
    if not REMOTE_BASE_URL:
        REMOTE_BASE_URL = determine_base_url(domain, ip)
    assert REMOTE_BASE_URL, "Could not determine base URL"
    
    # Need to log in first (each test is a separate process)
    do_remote_login("c", "c")
    
    response, body = try_remote_url(REMOTE_BASE_URL, "/recipe/2/edit")
    if not response:
        response, body = try_remote_url(REMOTE_BASE_URL, "/recipe/2/edit/")
    
    assert response, "Failed to fetch /recipe/2/edit"
    assert response.status == 200, f"Expected 200 for recipe edit, got {response.status}"
    
    body_text = body.decode('latin1')
    assert "form" in body_text.lower(), "Edit page should contain a form"
    assert "potato" in body_text.lower(), "Edit page should contain 'Potato' (recipe title)"
    print(f"Recipe edit page loaded: {len(body)} bytes")


@name("Check that recipe photo is served as PNG")
def check_recipe_photo():
    global REMOTE_BASE_URL
    domain, ip = get_domain_file_contents()
    if not REMOTE_BASE_URL:
        REMOTE_BASE_URL = determine_base_url(domain, ip)
    assert REMOTE_BASE_URL, "Could not determine base URL"
    
    # Just fetch first few bytes to check PNG magic bytes
    photo_url = REMOTE_BASE_URL + "/recipe/2/photo"
    try:
        req = urllib.request.Request(photo_url)
        req.add_header("Range", "bytes=0-7")  # Just get first 8 bytes
        response = REMOTE_OPENER.open(req, timeout=REMOTE_TIMEOUT)
        body = response.read()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print("No photo for recipe 2, trying recipe 3...")
            photo_url = REMOTE_BASE_URL + "/recipe/3/photo"
            try:
                req = urllib.request.Request(photo_url)
                req.add_header("Range", "bytes=0-7")
                response = REMOTE_OPENER.open(req, timeout=REMOTE_TIMEOUT)
                body = response.read()
            except urllib.error.HTTPError as e2:
                if e2.code == 404:
                    print("No photos found, skipping PNG check")
                    return
                raise
        else:
            raise
    
    assert is_png(body), "Recipe photo should be a PNG file"
    print(f"Recipe photo starts with PNG magic bytes")


@name("Check that photo upload works")
def check_photo_upload():
    global REMOTE_BASE_URL
    domain, ip = get_domain_file_contents()
    if not REMOTE_BASE_URL:
        REMOTE_BASE_URL = determine_base_url(domain, ip)
    assert REMOTE_BASE_URL, "Could not determine base URL"
    
    # Need to log in first (each test is a separate process)
    do_remote_login("c", "c")
    
    # Get the edit page to find the CSRF token and form structure
    response, body = try_remote_url(REMOTE_BASE_URL, "/recipe/2/edit")
    if not response:
        response, body = try_remote_url(REMOTE_BASE_URL, "/recipe/2/edit/")
    assert response, "Failed to fetch edit page for upload"
    
    body_text = body.decode('latin1')
    
    # Find CSRF token
    csrf_match = re.search(r'name=["\']csrfmiddlewaretoken["\'] value=["\']([^"\']+)["\']', body_text)
    if not csrf_match:
        csrf_match = re.search(r'value=["\']([^"\']+)["\'] name=["\']csrfmiddlewaretoken["\']', body_text)
    assert csrf_match, "Could not find CSRF token"
    csrf_token = csrf_match.group(1)
    print(f"Found CSRF token: {csrf_token[:20]}...")
    
    # Create a minimal PNG for upload
    png_data = create_minimal_png()
    
    # Build multipart form data
    boundary = "----WebKitFormBoundary" + "x" * 16
    
    # We need to include all required form fields. Let's parse them.
    parser = HTMLFindFormInput("post", "/recipe/2/edit")
    parser.feed(body_text)
    
    parts = []
    
    # Add CSRF token
    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="csrfmiddlewaretoken"\r\n\r\n{csrf_token}')
    
    # Add other form fields with their current/default values
    for iput in parser.found:
        if "name" not in iput:
            continue
        name = iput["name"]
        if name == "csrfmiddlewaretoken":
            continue
        value = iput.get("value", "")
        # For the photo field, we'll add it separately
        if iput.get("type") == "file":
            continue
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}')
    
    # Add the photo file
    # Find the file input name
    file_input_name = "photo"  # default guess
    for iput in parser.found:
        if iput.get("type") == "file" and "name" in iput:
            file_input_name = iput["name"]
            break
    
    parts.append(
        f'--{boundary}\r\n'
        f'Content-Disposition: form-data; name="{file_input_name}"; filename="test.png"\r\n'
        f'Content-Type: image/png\r\n\r\n'
    )
    
    # Combine parts
    body_parts = "\r\n".join(parts).encode('utf8')
    body_parts += png_data
    body_parts += f'\r\n--{boundary}--\r\n'.encode('utf8')
    
    # Submit the form
    edit_url = REMOTE_BASE_URL + "/recipe/2/edit"
    if parser.action:
        edit_url = REMOTE_BASE_URL + parser.action
    
    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}"
    }
    
    req = urllib.request.Request(edit_url, data=body_parts, headers=headers, method="POST")
    try:
        response = REMOTE_OPENER.open(req, timeout=REMOTE_TIMEOUT)
        print(f"Upload response: {response.status}")
    except urllib.error.HTTPError as e:
        if 300 <= e.code < 400:
            print(f"Upload redirected (success): {e.headers.get('Location', 'unknown')}")
        else:
            print(f"Upload failed: {e.code} {e.reason}")
            raise
    
    # Verify the photo was uploaded by fetching it and comparing exact bytes
    response, body = try_remote_url(REMOTE_BASE_URL, "/recipe/2/photo")
    if not response:
        response, body = try_remote_url(REMOTE_BASE_URL, "/recipe/2/photo/")
    
    assert response, "Could not fetch uploaded photo"
    assert response.status == 200, f"Could not fetch uploaded photo: {response.status}"
    assert body == png_data, f"Uploaded photo doesn't match: expected {len(png_data)} bytes, got {len(body)} bytes"
    print(f"Photo upload verified: uploaded and retrieved {len(body)} bytes match exactly")


# =============================================================================
# HW7 Phase 5 Tests
# =============================================================================

@name("Check that domain has A record matching IP")
def check_dns_a_record():
    import dns.resolver
    domain, ip = get_domain_file_contents()
    assert domain, "No domain in DOMAIN.md"
    assert ip, "No IP in DOMAIN.md"
    
    print(f"Looking up A record for {domain}...")
    try:
        answers = dns.resolver.resolve(domain, "A")
    except Exception as e:
        assert False, f"Could not resolve A record for {domain}: {e}"
    
    found_ips = []
    matched = False
    for rdata in answers:
        found_ip = str(rdata)
        found_ips.append(found_ip)
        print(f"  Found A record: {found_ip}")
        if found_ip == ip:
            matched = True
            print(f"  Matches IP from DOMAIN.md!")
    
    assert matched, f"A record IPs {found_ips} do not match DOMAIN.md IP {ip}"


@name("Check that HTTPS works")
def check_https_works():
    domain, ip = get_domain_file_contents()
    assert domain, "No domain in DOMAIN.md"
    
    # Create a strict SSL context that validates certificates
    strict_ctx = ssl.create_default_context()
    strict_opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(REMOTE_COOKIE_JAR),
        urllib.request.HTTPSHandler(context=strict_ctx)
    )
    
    url = f"https://{domain}/"
    print(f"Testing HTTPS with certificate validation: {url}")
    
    try:
        response = strict_opener.open(url, timeout=REMOTE_TIMEOUT)
        print(f"HTTPS works with valid certificate!")
        print(f"Response: {response.status}")
    except ssl.SSLCertVerificationError as e:
        assert False, f"HTTPS certificate validation failed: {e}"
    except Exception as e:
        assert False, f"HTTPS connection failed: {e}"


@name("Check that invalid page returns plain 404 (production mode)")
def check_production_404():
    global REMOTE_BASE_URL
    domain, ip = get_domain_file_contents()
    if not REMOTE_BASE_URL:
        REMOTE_BASE_URL = determine_base_url(domain, ip)
    assert REMOTE_BASE_URL, "Could not determine base URL"
    
    url = REMOTE_BASE_URL + "/thispageshouldnotexist12345/"
    print(f"Fetching non-existent page: {url}")
    
    try:
        req = urllib.request.Request(url)
        response = REMOTE_OPENER.open(req, timeout=REMOTE_TIMEOUT)
        assert False, f"Expected 404, got {response.status}"
    except urllib.error.HTTPError as e:
        assert e.code == 404, f"Expected 404, got {e.code}"
        body = e.read().decode('latin1')
        print(f"Got 404 response: {len(body)} bytes")
        
        # Check it's NOT the Django debug page
        assert "Traceback" not in body, "404 page contains 'Traceback' - debug mode is on!"
        assert "DEBUG" not in body or "DEBUG = True" not in body, "404 page mentions DEBUG - debug mode is on!"
        assert "Request Method:" not in body, "404 page looks like Django debug page"
        
        # Should be a simple/minimal page
        if len(body) > 5000:
            print(f"WARNING: 404 page is quite large ({len(body)} bytes), might be debug page")
        
        print("404 page looks like production mode (no debug info)")


def any_whitespace(s):
    return re.compile(re.escape(s).replace(r"\ ", r"\s*"))

HW1 = [
    start_server,
    check_get("/static/test.html"),
]

HW2 = [
    start_server,
    check_get("/static/main.css"),
    check_contains("/static/main.css", any_whitespace("* { margin: 0; padding: 0; box-sizing: border-box; }")),
    check_meta_viewport("/static/index.html"),
    check_meta_viewport("/static/recipe.html"),
    check_meta_viewport("/static/search.html"),
    check_meta_viewport("/static/login.html"),
    check_meta_viewport("/static/profile.html"),
]

HW3 = [
    start_server,
    check_get("/"),
    check_get("/profile/b"),
    check_get("/recipe/3"),
    check_get("/s?tag:comfort"),
    check_get("/login"),
]

VALID_RECIPE = {
    "title":"Scone with Honey Butter",
    "prep_time":"20",
    "cook_time":"15",
    "serves":"8",
    "description":"xyz",
    "x38":"xyz",
    "y54amount":"2.5","y54unit":"cup","y54name":"all-purpose flour",
    "y55amount":"0.25","y55unit":"cup","y55name":"granulated sugar",
    "y56amount":"1.0","y56unit":"tablespoon","y56name":"baking powder",
    "y57amount":"0.5","y57unit":"teaspoon","y57name":"salt",
    "x39":"xyz",
    "y58amount":"0.5","y58unit":"cup","y58name":"butter, cold and cubed",
    "x40":"xyz",
    "y59amount":"0.5","y59unit":"cup","y59name":"heavy cream",
    "y60amount":"1.0","y60unit":"large","y60name":"egg",
    "x41":"xyz",
    "x42":"xyz",
    "y61amount":"2.0","y61unit":"tablespoon","y61name":"milk",
    "x43":"xyz",
    "x44":"xyz",
    "y62amount":"0.25","y62unit":"cup","y62name":"butter, softened",
    "y63amount":"1.0","y63unit":"tablespoon","y63name":"honey",
    "x45":"xyz",
}

HW4 = [
    start_server,
    check_has_form("/recipe/7", "get", "/recipe/7/edit"),
    check_has_form("/recipe/7/edit", "post", "/recipe/7/edit"),
    #check_submit_redirect("/recipe/7/edit", VALID_RECIPE, "/recipe/7")
]

HW5 = [
    start_server,
    check_has_form("/login", "post", "/login"),
    check_login("/login", "pavpan", "pavpan"),
    check_login("/login", "c", "c"),
    check_not_login("/login", "b", "a"),
    check_get_logged_in("/login", "d", "d", "/", "Dan Doughkneeder"),
    check_logout("/login", "a", "a", "/logout"),
]

HW6 = [
    start_server,
    check_get("/static/main.js"),
    check_contains("/static/main.js", "console.log"),
    check_has_js("/", "/static/main.js"),
    check_has_js("/login", "/static/main.js"),
    check_has_js("/recipe/27", "/static/main.js"),
    check_has_js("/s", "/static/main.js"),
]

# =============================================================================
# HW7 Combined Tests (to fit within 10 test limit)
# =============================================================================

@name("Phase 2: Check IP address and machine reachability")
def check_phase2_combined():
    check_domain_has_ip()
    check_machine_reachable()

@name("Phase 3: Check NGINX and static files")
def check_phase3_combined():
    check_nginx_response()
    check_static_files()

@name("Phase 4: Check recipe photo display and upload")
def check_phase4_photo_combined():
    check_recipe_photo()
    check_photo_upload()

@name("Phase 5: Check DNS A record and HTTPS")
def check_phase5_dns_https():
    check_dns_a_record()
    check_https_works()


HW7 = [
    # Phase 1 (10 pts)
    check_dns_file,              # 5 pts
    check_dns_txt_record,        # 5 pts
    # Phase 2 (30 pts)
    check_phase2_combined,       # 30 pts (ip + reachable)
    # Phase 3 (15 pts)
    check_phase3_combined,       # 15 pts (nginx + static)
    # Phase 4 (15 pts)
    check_homepage,              # 3 pts
    check_login_works,           # 4 pts
    check_recipe_edit,           # 3 pts
    check_phase4_photo_combined, # 5 pts (photo display + upload)
    # Phase 5 (25 pts)
    check_phase5_dns_https,      # 17 pts (dns a record + https)
    check_production_404,        # 8 pts
]

HWS = {
    "hw1": HW1,
    "hw2": HW2,
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
            elif part == "setup":
                return setup()
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
