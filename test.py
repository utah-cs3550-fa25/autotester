#!/usr/bin/env python3

import subprocess
import sys
import time
import urllib.request
import os
import socket
import html.parser

TIMEOUT = 10 # seconds
CURRENT = "hw2"
SERVER = None

def name(n):
    def decorator(f):
        f.phase_name = n
        return f
    return decorator

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
            html_attrs = "".join(f" {k}='{v}'" for k, v in attrs.items())
            print(f"Found <{tag}{html_attrs}>")
            self.found.append(attrs)

def check_has_css(url, css):
    @name(f"Check that {url} links to {css}")
    def f(timeout=TIMEOUT):
        start_server(timeout)
        response = urllib.request.urlopen("http://localhost:8000" + url, timeout=timeout)
        assert 200 <= response.status < 300, \
            f"Expected a successful response, got {response.status} {response.reason}"
        parser = HTMLFindElement("link")
        parser.feed(response)
        for link in parser.found:
            if "rel" in link and link["rel"] == "stylesheet":
                if link["href"] == css:
                    assert "title" not in link, "<link> element should not have title attribute"
                    assert "media" not in link, "<link> element should not have media attribute"
                    if "type" in link: assert link["type"] == "text/css", "Stylesheets should have type=text/css"
        else:
            raise ValueError(f"Could not find a <link> element with href={css}")
    return f


HW1 = [
    start_server,
    check_get("/static/test.html"),
    check_get("/static/index.html"),
    check_get("/static/assignments.html"),
    check_get("/static/submissions.html"),
    check_get("/static/profile.html"),
    check_get("/static/login.html"),
]

HW2 = [
    start_server,
    check_get("/static/main.css"),
    check_has_css("/static/index.html", "/static/main.css"),
    check_has_css("/static/assignments.html", "/static/main.css"),
    check_has_css("/static/submissions.html", "/static/main.css"),
    check_has_css("/static/profile.html", "/static/main.css"),
    check_has_css("/static/login.html", "/static/main.css"),
]

HWS = {
    "hw1": HW1,
    "hw2": HW2,
}

def run(hw, part):
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
