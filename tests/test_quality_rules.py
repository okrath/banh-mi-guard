"""
The quality matrix's line rules: each finds the risky line in the files it is about, leaves the safe
form, comments, docs and tests alone, and turns into a LOW note with `guard-allow <rule>: <reason>`.
"""

import pytest

from guard.core.rulebook import LINE_RULES, OCRRulebookRunner


def found(path: str, *lines: str) -> list:
    diff = f"+++ b/{path}\n@@ -0,0 +1,{len(lines)} @@\n" + "".join(f"+{line}\n" for line in lines)
    ids = {r[0] for r in LINE_RULES} | {"SEC-002", "SEC-003"}
    return [(v.rule_id, v.severity) for v in OCRRulebookRunner().scan_diff(diff) if v.rule_id in ids]


@pytest.mark.parametrize("path, risky, safe, rule, severity", [
    # SEC-002: SQL built from strings
    ("app/query.py", 'query = f"SELECT * FROM users WHERE id = {user_id}"', 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))', "SEC-002", "CRITICAL"),
    ("web/query.ts", 'const query = `SELECT * FROM users WHERE id = ${userId}`;', 'db.query("SELECT * FROM users WHERE id = ?", [userId])', "SEC-002", "CRITICAL"),
    ("pkg/db.go", 'q := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userId)', 'db.Query("SELECT * FROM users WHERE id = $1", userId)', "SEC-002", "CRITICAL"),
    ("app/models.rb", 'query = "SELECT * FROM users WHERE id = #{user_id}"', 'User.where("id = ?", user_id)', "SEC-002", "CRITICAL"),
    ("src/db.php", '$query = "SELECT * FROM users WHERE id = " . $id;', '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");', "SEC-002", "CRITICAL"),
    ("src/UserDao.java", 'String q = String.format("SELECT * FROM users WHERE id = \'%s\'", userId);', 'conn.prepareStatement("SELECT * FROM users WHERE id = ?");', "SEC-002", "CRITICAL"),
    ("src/UserDao.kt", 'val q = "SELECT * FROM users WHERE id = $userId"', 'conn.prepareStatement("SELECT * FROM users WHERE id = ?")', "SEC-002", "CRITICAL"),
    ("src/Repo.cs", 'var q = $"SELECT * FROM users WHERE id = {userId}";', 'new SqlCommand("SELECT * FROM users WHERE id = @id", conn);', "SEC-002", "CRITICAL"),
    ("src/db.rs", 'let q = format!("SELECT * FROM users WHERE id = {}", user_id);', 'sqlx::query("SELECT * FROM users WHERE id = $1");', "SEC-002", "CRITICAL"),
    ("src/Db.swift", r'let q = "SELECT * FROM users WHERE id = \(userId)"', 'db.prepare("SELECT * FROM users WHERE id = ?")', "SEC-002", "CRITICAL"),
    ("lib/db.dart", 'var q = "SELECT * FROM users WHERE id = $userId";', 'db.query("SELECT * FROM users WHERE id = ?", [userId]);', "SEC-002", "CRITICAL"),
    # SEC-003: Raw HTML sinks
    ("web/page.js", "node.innerHTML = userInput;", "node.innerHTML = DOMPurify.sanitize(userInput);", "SEC-003", "HIGH"),
    ("app/views.py", "html = mark_safe(user_input)", "html = escape(user_input)", "SEC-003", "HIGH"),
    ("pkg/render.go", "tmpl := template.HTML(userInput)", "tmpl := template.HTMLEscapeString(userInput)", "SEC-003", "HIGH"),
    ("app/views.rb", "content = user_input.html_safe", "content = sanitize(user_input)", "SEC-003", "HIGH"),
    ("web/Page.cs", "var html = Html.Raw(userInput);", "var html = WebUtility.HtmlEncode(userInput);", "SEC-003", "HIGH"),
    ("web/comp.ts", "this.sanitizer.bypassSecurityTrustHtml(htmlSnippet);", "this.sanitizer.sanitize(SecurityContext.HTML, htmlSnippet);", "SEC-003", "HIGH"),
    ("src/view.php", 'echo $_GET["name"];', 'echo htmlspecialchars($_GET["name"], ENT_QUOTES, "UTF-8");', "SEC-003", "HIGH"),
    # SEC-004: Unsafe deserialization
    ("app/load.py", "cfg = yaml.load(stream)", "cfg = yaml.load(stream, Loader=yaml.SafeLoader)", "SEC-004", "HIGH"),
    ("app/load.py", "obj = pickle.loads(blob)", "obj = json.loads(blob)", "SEC-004", "HIGH"),
    ("src/Loader.java", "Object o = new ObjectInputStream(s).readObject();", "Object o = jsonMapper.readValue(s, User.class);", "SEC-004", "HIGH"),
    ("src/Config.kt", "mapper.enableDefaultTyping();", "mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);", "SEC-004", "HIGH"),
    ("src/parse.php", "$data = unserialize($payload);", "$data = json_decode($payload, true);", "SEC-004", "HIGH"),
    ("app/loader.rb", "obj = Marshal.load(data)", "obj = JSON.parse(data)", "SEC-004", "HIGH"),
    ("app/loader.rb", "cfg = YAML.load(yaml_str)", "cfg = YAML.safe_load(yaml_str)", "SEC-004", "HIGH"),
    ("src/Store.cs", "var obj = new BinaryFormatter().Deserialize(stream);", "var obj = JsonSerializer.Deserialize<User>(stream);", "SEC-004", "HIGH"),
    # SEC-005: A string run as shell or code
    ("app/run.py", "subprocess.run(cmd, shell=True)", "subprocess.run([\"git\", \"status\"])", "SEC-005", "HIGH"),
    ("app/run.py", "value = eval(text)", "value = ast.literal_eval(text)", "SEC-005", "HIGH"),
    ("web/app.ts", "const f = new Function(body)", "const f = () => body", "SEC-005", "HIGH"),
    ("pkg/exec.go", 'cmd := exec.Command("sh", "-c", userCmd)', 'cmd := exec.Command("ls", dir)', "SEC-005", "HIGH"),
    ("src/Shell.java", 'new ProcessBuilder("sh", "-c", userCmd).start();', 'new ProcessBuilder("ls", dir).start();', "SEC-005", "HIGH"),
    ("src/Shell.kt", 'ProcessBuilder("bash", "-c", userCmd).start()', 'ProcessBuilder("ls", dir).start()', "SEC-005", "HIGH"),
    ("src/cmd.php", "system($cmd);", "escapeshellcmd($cmd);", "SEC-005", "HIGH"),
    ("app/runner.rb", "system(cmd)", 'Open3.capture2("ls", dir)', "SEC-005", "HIGH"),
    ("src/Proc.cs", 'Process.Start("cmd.exe", "/c " + cmd);', 'Process.Start("notepad.exe", path);', "SEC-005", "HIGH"),
    ("src/proc.rs", 'Command::new("sh").arg("-c").arg(user_cmd).spawn();', 'Command::new("ls").arg("-l").spawn();', "SEC-005", "HIGH"),
    ("src/Proc.swift", 'let task = Process(); task.launchPath = "/bin/sh"', 'let task = Process(); task.launchPath = "/usr/bin/git"', "SEC-005", "HIGH"),
    # SEC-006, SEC-007
    ("app/http.py", "requests.get(url, verify=False)", "requests.get(url, verify=ca_bundle)", "SEC-006", "HIGH"),
    ("web/https.js", "const agent = new Agent({ rejectUnauthorized: false })", "const agent = new Agent({ ca })", "SEC-006", "HIGH"),
    ("api/main.py", "app.add_middleware(CORSMiddleware, allow_origins=[\"*\"])",
     "app.add_middleware(CORSMiddleware, allow_origins=[\"https://app.example.com\"])", "SEC-007", "MEDIUM"),
    # SEC-008: Credential in client storage
    ("web/auth.ts", "localStorage.setItem('access_token', token)", "localStorage.setItem('theme', 'dark')", "SEC-008", "MEDIUM"),
    ("web/session.ts", 'sessionStorage.setItem("access_token", token)', 'sessionStorage.setItem("theme", "dark")', "SEC-008", "MEDIUM"),
    ("web/native.ts", 'AsyncStorage.setItem("auth_token", token)', 'AsyncStorage.setItem("theme", "dark")', "SEC-008", "MEDIUM"),
    ("app/Prefs.java", 'editor.putString("auth_token", token);', 'editor.putString("theme", "dark");', "SEC-008", "MEDIUM"),
    ("app/Prefs.kt", 'editor.putString("password", pass)', 'editor.putString("theme", "dark")', "SEC-008", "MEDIUM"),
    ("src/Store.swift", 'UserDefaults.standard.set(token, forKey: "auth_token")', 'UserDefaults.standard.set(true, forKey: "notificationsEnabled")', "SEC-008", "MEDIUM"),
    ("lib/prefs.dart", 'prefs.setString("api_key", apiKey);', 'prefs.setString("theme", "dark");', "SEC-008", "MEDIUM"),
    # Infra and Mobile
    ("k8s/deploy.yaml", "        privileged: true", "        privileged: false", "INFRA-001", "HIGH"),
    ("k8s/deploy.yaml", "        image: nginx:latest", "        image: nginx:1.27.2", "INFRA-002", "MEDIUM"),
    ("Dockerfile", "FROM python", "FROM python:3.12-slim", "INFRA-002", "MEDIUM"),
    ("docker/api.Dockerfile", "USER root", "USER app", "INFRA-003", "MEDIUM"),
    ("android/app/src/main/AndroidManifest.xml", "    android:debuggable=\"true\"", "    android:debuggable=\"false\"",
     "MOB-001", "HIGH"),
    ("android/app/src/main/AndroidManifest.xml", "    android:allowBackup=\"true\"", "    android:allowBackup=\"false\"",
     "MOB-002", "MEDIUM"),
])
def test_each_rule_finds_the_risky_line_and_leaves_the_safe_one(path, risky, safe, rule, severity):
    assert (rule, severity) in found(path, risky)
    assert not [f for f in found(path, safe) if f[0] == rule]


def test_a_rule_only_looks_at_the_files_it_is_about():
    assert not found("docs/setup.md", "subprocess.run(cmd, shell=True)")  # docs
    assert not found("tests/test_run.py", "subprocess.run(cmd, shell=True)")  # tests
    assert not found("app/run.js", "cfg = yaml.load(stream)")  # a Python rule in JavaScript
    assert not found("app/values.yaml", "USER root")  # a Dockerfile rule in YAML


def test_comments_and_names_quoted_in_prose_are_not_code():
    assert not found("app/run.py", "# never call eval(text) here")
    assert not found("app/run.py", "this is like running ``eval()`` on the input")
    assert not found("web/a.ts", "// new Function(body) is not allowed")


def test_guard_allow_keeps_the_line_as_a_low_note():
    assert found("app/run.py", "subprocess.run(cmd, shell=True)  # guard-allow SEC-005: fixed command, no input") == \
        [("SEC-005", "LOW")]
    assert found("app/run.py", "subprocess.run(cmd, shell=True)  # guard-allow SEC-004: wrong rule") == [("SEC-005", "HIGH")]


def test_one_line_reports_a_rule_once():
    assert found("app/run.py", "os.system(cmd); subprocess.run(cmd, shell=True)") == [("SEC-005", "HIGH")]


@pytest.mark.parametrize("path, risky, safe, rule", [
    ("web/App.tsx", "<img src={logo} className=\"logo\" />", "<img src={logo} alt=\"Company logo\" />", "UX-002"),
    ("web/index.html", "<img src=\"hero.png\">", "<img src=\"hero.png\" alt=\"\">", "UX-002"),
])
def test_ux_rules_find_the_line_and_leave_the_accessible_form(path, risky, safe, rule):
    assert (rule, "MEDIUM") in found(path, risky)
    assert not [f for f in found(path, safe) if f[0] == rule]


def test_an_image_whose_props_are_spread_may_carry_its_alt():
    assert not [f for f in found("web/Card.tsx", "<img {...imageProps} />") if f[0] == "UX-002"]



def test_the_review_cases_stay_quiet():
    assert not found("web/App.tsx", "<img src={a} onError={() => setBroken(true)} alt=\"Avatar\" />")
    assert not found("web/theme.css", "a { outline: 0.2rem solid var(--ring); }")
    assert not found("web/theme.css", ":focus:not(:focus-visible) { outline: none; }")
    assert not found("app/run.py", "run(job)  # unlike exec(code), this takes a function")


def test_a_dockerfile_stage_is_not_an_unpinned_image():
    lines = ("FROM node:20.11-slim AS build", "RUN npm ci", "FROM build AS runtime")
    assert not found("Dockerfile", *lines)
    assert ("INFRA-002", "MEDIUM") in found("Dockerfile", "FROM node AS build")


def test_code_right_after_a_docstring_is_still_read():
    diff = ('+++ b/app/run.py\n@@ -10,3 +10,4 @@\n     """Run the job.\n\n     """\n+    os.system(cmd)\n')
    assert [v.rule_id for v in OCRRulebookRunner().scan_diff(diff) if v.rule_id == "SEC-005"] == ["SEC-005"]


def test_a_removed_focus_ring_is_a_low_hint():
    assert found("web/theme.css", "button:focus { outline: none; }") == [("UX-001", "LOW")]
    assert not found("web/theme.css", "button:focus-visible { outline: 2px solid var(--ring); }")


def test_ordinary_code_the_second_review_found_stays_quiet():
    assert not found("ml/model.py", "    def eval(self, batch):")
    assert not found("app/cfg.py", "cfg = yaml.load(open(p), Loader=yaml.SafeLoader)")
    assert not found("android/app/src/debug/AndroidManifest.xml", '    android:usesCleartextTraffic="true"')
    assert not found("_data/site.yml", "image: cover.jpg") and not found("_data/site.yml", "image: /assets/img/logo.png")
    assert not found("web/ui.ts", "localStorage.setItem('sessionSidebarOpen', '1')")
    assert not found("web/App.tsx", "<img")  # the tag goes on over the next lines: not judged here
    assert not found("web/App.svelte", "<img {src} {alt} />")


def test_a_dockerfile_that_ends_as_a_user_may_switch_to_root_for_a_step():
    assert not found("Dockerfile", "USER root", "RUN apt-get install -y curl", "USER app")
    assert ("INFRA-003", "MEDIUM") in found("Dockerfile", "USER app", "RUN make", "USER root")


def test_python_floor_division_is_not_a_comment():
    assert ("SEC-006", "HIGH") in found("app/http.py", "requests.get(url, timeout=t // 2, verify=False)")


def test_test_files_are_known_by_name_and_folder():
    assert ("SEC-005", "HIGH") in found("app/latest_config.py", "os.system(cmd)")  # not a test file
    assert not found("src/__tests__/a.test.ts", "eval(x)") and not found("pkg/run_test.py", "os.system(cmd)")


def test_the_stage_pattern_is_fast_on_an_odd_line():
    import time
    start = time.monotonic()
    found("Dockerfile", "FROM " + " " * 5000 + "x")
    assert time.monotonic() - start < 1


def test_more_forms_are_found():
    assert ("SEC-005", "HIGH") in found("web/a.js", "window.eval(code)")
    assert ("SEC-006", "HIGH") in found("Dockerfile", "ENV NODE_TLS_REJECT_UNAUTHORIZED=0")



def test_a_very_long_line_is_skipped_quickly():
    import time
    start = time.monotonic()
    assert not found("web/bundle.html", "<img src=x " * 20000)
    assert time.monotonic() - start < 2



def test_a_parenthesis_inside_a_string_does_not_close_the_sanitize_call():
    diff = "+++ b/web/view.js\n@@ -0,0 +1,1 @@\n+node.innerHTML = DOMPurify.sanitize(\")\") + userInput;\n"
    assert [v.severity for v in OCRRulebookRunner().scan_diff(diff) if v.rule_id == "SEC-003"] == ["HIGH"]


def test_each_yaml_load_is_judged_on_its_own_arguments():
    assert ("SEC-004", "HIGH") in found("app/cfg.py", "a = yaml.load(untrusted) or yaml.load(data, Loader=yaml.SafeLoader)")
    assert not found("app/cfg.py", "a = yaml.load(data, Loader=yaml.SafeLoader)")


def test_guard_allow_in_a_string_downgrades_nothing():
    assert found("app/run.py", 'eval(user_input), "guard-allow SEC-005: harmless"') == [("SEC-005", "HIGH")]


def test_smaller_review_cases():
    assert ("INFRA-002", "MEDIUM") in found("Dockerfile", "FROM registry.example:5000/app")
    assert ("INFRA-002", "MEDIUM") in found("Dockerfile", "FROM node AS node")
    assert not found("app/cli.py", "parser.add_argument('--verify', default=False); run(verify=False)")
    assert ("SEC-006", "HIGH") in found("app/http.py", "requests.get(url, verify=False)")


def test_safeloader_counts_only_inside_the_calls_own_arguments():
    assert ("SEC-004", "HIGH") in found("app/cfg.py", "cfg = yaml.load(untrusted); log(SafeLoader)")
    assert not found("app/cfg.py", "cfg = yaml.load(open(p, 'r'), Loader=yaml.SafeLoader)")
    assert ("SEC-004", "HIGH") in found("app/cfg.py", "cfg = yaml.load(f'{x})')  # SafeLoader")


def test_a_comment_inside_a_string_is_not_a_comment():
    assert found("app/run.py", 'eval(user_input); message = "# guard-allow SEC-005: harmless"') == [("SEC-005", "HIGH")]
    assert found("app/run.py", "eval(fixed)  # guard-allow SEC-005: a constant expression") == [("SEC-005", "LOW")]
    assert ("SEC-005", "HIGH") in found("web/a.js", 'const u = "http://x"; eval(code)')  # `//` in a string is no comment


def test_docs_pages_and_strings_are_not_code():
    assert not found("docs/examples/deploy.yaml", "        privileged: true")
    assert not found("docs/index.html", "<img src=\"x.png\">")
    # a string is read like code: it may hold code that runs
    assert ("SEC-005", "HIGH") in found("web/a.js", "const x = `${eval(input)}`")
    assert ("SEC-004", "HIGH") in found("app/cfg.py", "cfg = yaml.unsafe_load(stream)")



def test_an_edited_dockerfile_reports_only_what_the_diff_can_show():
    edited = "+++ b/Dockerfile\n@@ -8,1 +8,2 @@\n FROM node:20-slim AS app\n+FROM build AS runtime\n+USER root\n"
    # a stage or a final USER outside the diff cannot be seen: the rules report, the author marks it
    assert sorted(v.rule_id for v in OCRRulebookRunner().scan_diff(edited) if v.rule_id.startswith("INFRA-00")) == \
        ["INFRA-002", "INFRA-003"]
    latest = "+++ b/Dockerfile\n@@ -8,1 +8,2 @@\n RUN make\n+FROM nginx:latest\n"
    assert [v.rule_id for v in OCRRulebookRunner().scan_diff(latest) if v.rule_id == "INFRA-002"] == ["INFRA-002"]


def test_an_escaped_backslash_ends_the_string_before_real_code():
    assert ("SEC-005", "HIGH") in found("app/run.py", 'path = "C:\\\\"; eval(user_input)')


def test_each_image_tag_needs_its_own_alt():
    assert ("UX-002", "MEDIUM") in found("web/a.html", '<img src="a.png"><img src="b.png" alt="B">')
    assert not found("web/a.html", '<img src="a.png" alt="A"><img src="b.png" alt="B">')



def test_code_after_a_closed_block_comment_is_read():
    assert ("SEC-005", "HIGH") in found("app/a.js", "value = 1; /* note */ eval(input)")
    assert ("SEC-005", "HIGH") in found("app/a.js", "/* note */ eval(input)")
    assert not found("app/a.js", "/* eval(input) is gone")


def test_android_attributes_in_single_quotes():
    assert ("MOB-001", "HIGH") in found("app/src/main/AndroidManifest.xml", "<application android:debuggable='true'>")
    assert ("MOB-002", "MEDIUM") in found("app/src/main/AndroidManifest.xml", "<application android:allowBackup='true'>")


def test_an_api_key_in_local_storage():
    assert ("SEC-008", "MEDIUM") in found("web/a.js", 'localStorage.setItem("api_key", key)')
    assert ("SEC-008", "MEDIUM") in found("web/a.js", 'localStorage.setItem("apiKey", key)')


def test_safeloader_in_a_string_is_not_the_loader():
    assert ("SEC-004", "HIGH") in found("app/cfg.py", 'cfg = yaml.load(untrusted, note="SafeLoader")')


def test_a_universal_selector_is_css_not_a_comment():
    assert ("UX-001", "LOW") in found("web/a.css", "* { outline: none; }")


def test_context_lines_keep_line_numbers():
    diff = "+++ b/app/run.py\n@@ -1,2 +1,3 @@\n import os\n x = 1\n+eval(user_input)\n"
    assert [(v.rule_id, v.line_number) for v in OCRRulebookRunner().scan_diff(diff) if v.rule_id == "SEC-005"] == [("SEC-005", 3)]


def test_multi_document_yaml_loaders():
    assert ("SEC-004", "HIGH") in found("app/cfg.py", "docs = yaml.load_all(stream)")
    assert ("SEC-004", "HIGH") in found("app/cfg.py", "docs = yaml.unsafe_load_all(stream)")
    assert not found("app/cfg.py", "docs = yaml.load_all(stream, Loader=yaml.SafeLoader)")


def test_local_storage_writes_by_property_or_index():
    assert ("SEC-008", "MEDIUM") in found("web/a.js", "localStorage.token = token")
    assert ("SEC-008", "MEDIUM") in found("web/a.js", "localStorage['access_token'] = token")
    assert not found("web/a.js", "const t = localStorage['access_token']")
    assert not found("web/a.js", 'const t = localStorage.getItem("token")')


def test_a_block_comment_across_lines_is_not_code():
    diff = "+++ b/web/a.js\n@@ -0,0 +1,4 @@\n+/*\n+eval(userInput)\n+*/ eval(real)\n+run()\n"
    assert [(v.rule_id, v.line_number) for v in OCRRulebookRunner().scan_diff(diff) if v.rule_id == "SEC-005"] == [("SEC-005", 3)]
    assert not found("web/a.js", "/* eval(input) */ run()")



def test_comments_opened_or_closed_on_context_lines():
    inside = "+++ b/web/a.js\n@@ -1,1 +1,3 @@\n /*\n+eval(userInput)\n+*/\n"
    assert [v for v in OCRRulebookRunner().scan_diff(inside) if v.rule_id == "SEC-005"] == []
    closed = "+++ b/web/a.js\n@@ -1,2 +1,3 @@\n /*\n */\n+eval(real)\n"
    assert [v.rule_id for v in OCRRulebookRunner().scan_diff(closed) if v.rule_id == "SEC-005"] == ["SEC-005"]



def test_guard_allow_in_a_closed_block_comment():
    assert found("web/a.js", "/* guard-allow SEC-005: fixed expression */ eval(constant)") == [("SEC-005", "LOW")]


def test_an_image_tag_over_several_lines():
    diff = '+++ b/web/A.jsx\n@@ -0,0 +1,3 @@\n+<img\n+  src={logo}\n+/>\n'
    assert [(v.rule_id, v.line_number) for v in OCRRulebookRunner().scan_diff(diff) if v.rule_id == "UX-002"] == [("UX-002", 1)]
    described = '+++ b/web/A.jsx\n@@ -0,0 +1,3 @@\n+<img\n+  src={logo} alt="Logo"\n+/>\n'
    assert [v for v in OCRRulebookRunner().scan_diff(described) if v.rule_id == "UX-002"] == []



def test_a_comment_closed_on_its_line_leaves_the_next_line_code():
    diff = "+++ b/web/a.js\n@@ -0,0 +1,2 @@\n+x = 1; /* note */ y = 2\n+eval(userInput)\n"
    assert [v.rule_id for v in OCRRulebookRunner().scan_diff(diff) if v.rule_id == "SEC-005"] == ["SEC-005"]



def test_a_hunk_gap_ends_an_open_comment():
    diff = "+++ b/web/a.js\n@@ -1,1 +1,2 @@\n+/* starts here\n@@ -40,1 +41,2 @@\n+eval(userInput)\n"
    assert [v.rule_id for v in OCRRulebookRunner().scan_diff(diff) if v.rule_id == "SEC-005"] == ["SEC-005"]


def test_a_comparison_inside_jsx_does_not_end_the_image_tag():
    diff = '+++ b/web/A.jsx\n@@ -0,0 +1,4 @@\n+<img\n+  src={n > 1 ? a : b}\n+  alt="Logo"\n+/>\n'
    assert [v for v in OCRRulebookRunner().scan_diff(diff) if v.rule_id == "UX-002"] == []



def test_a_greater_than_inside_a_quoted_attribute_does_not_end_the_image_tag():
    diff = '+++ b/web/A.jsx\n@@ -0,0 +1,4 @@\n+<img\n+  title="x > y"\n+  alt="A"\n+/>\n'
    assert [v for v in OCRRulebookRunner().scan_diff(diff) if v.rule_id == "UX-002"] == []



def test_yaml_glob_does_not_open_block_comment():
    diff = "+++ b/k8s/deploy.yaml\n@@ -0,0 +1,2 @@\n+include: foo/*\n+  privileged: true\n"
    assert [v.rule_id for v in OCRRulebookRunner().scan_diff(diff) if v.rule_id == "INFRA-001"] == ["INFRA-001"]


def test_python_glob_and_division_do_not_open_block_comment():
    diff = '+++ b/app/run.py\n@@ -0,0 +1,2 @@\n+paths = glob("src/*")\n+eval(user_input)\n'
    assert [v.rule_id for v in OCRRulebookRunner().scan_diff(diff) if v.rule_id == "SEC-005"] == ["SEC-005"]
    diff2 = "+++ b/app/run.py\n@@ -0,0 +1,2 @@\n+x = a /* b\n+eval(user_input)\n"
    assert [v.rule_id for v in OCRRulebookRunner().scan_diff(diff2) if v.rule_id == "SEC-005"] == ["SEC-005"]


def test_js_block_comment_suppresses_rule():
    diff = "+++ b/web/a.js\n@@ -0,0 +1,3 @@\n+/*\n+eval(userInput)\n+*/\n"
    assert [v.rule_id for v in OCRRulebookRunner().scan_diff(diff) if v.rule_id == "SEC-005"] == []


def test_html_block_comment_suppresses_img_rule():
    diff = '+++ b/web/index.html\n@@ -0,0 +1,3 @@\n+<!--\n+<img src="a.png">\n+-->\n'
    assert [v.rule_id for v in OCRRulebookRunner().scan_diff(diff) if v.rule_id == "UX-002"] == []


def test_unclosed_img_tag_over_max_length_dropped():
    padding = "+  " + "x" * 80 + "\n"
    diff = f'+++ b/web/A.jsx\n@@ -0,0 +1,33 @@\n+<img\n{padding * 30}+/>\n'
    violations = OCRRulebookRunner().scan_diff(diff)
    assert [v for v in violations if v.rule_id == "UX-002"] == []


def test_html_literal_slash_star_does_not_hide_img():
    diff = '+++ b/web/index.html\n@@ -0,0 +1,2 @@\n+<p>path/*</p>\n+<img src="a.png">\n'
    assert [v.rule_id for v in OCRRulebookRunner().scan_diff(diff) if v.rule_id == "UX-002"] == ["UX-002"]


def test_multiline_img_tag_closed_on_line_past_cap():
    tail = "x" * 2000
    diff = f"+++ b/web/A.jsx\n@@ -0,0 +1,2 @@\n+<img src={{logo}}\n+/> {tail}\n"
    violations = [v for v in OCRRulebookRunner().scan_diff(diff) if v.rule_id == "UX-002"]
    assert len(violations) == 1
    assert violations[0].rule_id == "UX-002"
    assert violations[0].line_number == 1


def test_block_comments_fallback_only_for_code_and_css():
    from guard.core.rulebook import _block_comments
    assert _block_comments("a.json") == ()
    assert _block_comments("a.css") == (("/*", "*/"),)
    assert _block_comments("a.go") == (("/*", "*/"),)


def test_sec_002_string_literal_reasoning():
    # Positives across language forms:
    # Python interpolation, concatenation, %, .format
    assert ("SEC-002", "CRITICAL") in found("app/query.py", 'query = f"SELECT * FROM users WHERE id = {user_id}"')
    assert ("SEC-002", "CRITICAL") in found("app/query.py", 'query = "SELECT * FROM users WHERE id = " + user_id')
    assert ("SEC-002", "CRITICAL") in found("app/query.py", 'query = "SELECT * FROM users WHERE id = %s" % user_id')
    assert ("SEC-002", "CRITICAL") in found("app/query.py", 'query = "SELECT * FROM users WHERE id = {}".format(user_id)')
    # JS/TS backtick, concatenation
    assert ("SEC-002", "CRITICAL") in found("web/query.ts", 'const query = `SELECT * FROM users WHERE id = ${userId}`;')
    assert ("SEC-002", "CRITICAL") in found("web/query.js", 'const query = "SELECT * FROM users WHERE id = " + userId;')
    # C# $ interpolation, string.Format
    assert ("SEC-002", "CRITICAL") in found("src/Repo.cs", 'var q = $"SELECT * FROM users WHERE id = {userId}";')
    assert ("SEC-002", "CRITICAL") in found("src/Repo.cs", 'var q = string.Format("SELECT * FROM users WHERE id = {0}", userId);')
    # Ruby #{ interpolation, concatenation
    assert ("SEC-002", "CRITICAL") in found("app/models.rb", 'query = "SELECT * FROM users WHERE id = #{user_id}"')
    assert ("SEC-002", "CRITICAL") in found("app/models.rb", 'query = "SELECT * FROM users WHERE id = " + user_id')
    # PHP . concatenation, $name interpolation, {$name} interpolation
    assert ("SEC-002", "CRITICAL") in found("src/db.php", '$query = "SELECT * FROM users WHERE id = " . $id;')
    assert ("SEC-002", "CRITICAL") in found("src/db.php", '$query = "SELECT * FROM users WHERE id = $id";')
    assert ("SEC-002", "CRITICAL") in found("src/db.php", '$query = "SELECT * FROM users WHERE id = {$id}";')
    # Kotlin $name, ${name}
    assert ("SEC-002", "CRITICAL") in found("src/UserDao.kt", 'val q = "SELECT * FROM users WHERE id = $userId"')
    assert ("SEC-002", "CRITICAL") in found("src/UserDao.kt", 'val q = "SELECT * FROM users WHERE id = ${userId}"')
    # Dart $name, ${name}
    assert ("SEC-002", "CRITICAL") in found("lib/db.dart", 'var q = "SELECT * FROM users WHERE id = $userId";')
    assert ("SEC-002", "CRITICAL") in found("lib/db.dart", 'var q = "SELECT * FROM users WHERE id = ${userId}";')
    # Swift \(name)
    assert ("SEC-002", "CRITICAL") in found("src/Db.swift", r'let q = "SELECT * FROM users WHERE id = \(userId)"')
    # Go fmt.Sprintf
    assert ("SEC-002", "CRITICAL") in found("pkg/db.go", 'q := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userId)')
    # Java String.format
    assert ("SEC-002", "CRITICAL") in found("src/UserDao.java", 'String q = String.format("SELECT * FROM users WHERE id = \'%s\'", userId);')
    # Rust format!
    assert ("SEC-002", "CRITICAL") in found("src/db.rs", 'let q = format!("SELECT * FROM users WHERE id = {}", user_id);')

    # SQL clauses split across concatenations still fire (.py and .js)
    assert ("SEC-002", "CRITICAL") in found("app/db.py", 'q = "UPDATE " + table + " SET x = 1"')
    assert ("SEC-002", "CRITICAL") in found("web/db.js", 'const q = "UPDATE " + table + " SET x = 1";')
    assert ("SEC-002", "CRITICAL") in found("app/db.py", 'q = "INSERT INTO " + table')
    assert ("SEC-002", "CRITICAL") in found("web/db.js", 'const q = "INSERT INTO " + table;')
    assert ("SEC-002", "CRITICAL") in found("app/db.py", 'q = "DELETE FROM " + table')
    assert ("SEC-002", "CRITICAL") in found("web/db.js", 'const q = "DELETE FROM " + table;')
    assert ("SEC-002", "CRITICAL") in found("app/db.py", 'q = "SELECT * FROM " + table')
    assert ("SEC-002", "CRITICAL") in found("web/db.js", 'const q = "SELECT * FROM " + table;')
    assert ("SEC-002", "CRITICAL") in found("app/db.py", 'q = "UPDATE users SET " + col + " = 1"')
    assert ("SEC-002", "CRITICAL") in found("web/db.js", 'const q = "UPDATE users SET " + col + " = 1";')

    # Negatives: must be quiet
    assert not [f for f in found("app/db.py", 'msg = "Failed to update " + err') if f[0] == "SEC-002"]
    assert not [f for f in found("web/db.js", 'const msg = "Failed to update " + err;') if f[0] == "SEC-002"]
    assert not [f for f in found("app/db.py", 'msg = "Could not delete from " + path') if f[0] == "SEC-002"]
    assert not [f for f in found("web/db.js", 'const msg = "Could not delete from " + path;') if f[0] == "SEC-002"]
    assert not [f for f in found("app/db.py", 'msg = "Nothing to insert into " + list') if f[0] == "SEC-002"]
    assert not [f for f in found("web/db.js", 'const msg = "Nothing to insert into " + list;') if f[0] == "SEC-002"]
    assert not [f for f in found("app/db.py", 'msg = "Please select one from " + choices') if f[0] == "SEC-002"]
    assert not [f for f in found("web/db.js", 'const msg = "Please select one from " + choices;') if f[0] == "SEC-002"]
    assert not [f for f in found("src/db.php", "DB::select('select * from users where id = ?', [$id])") if f[0] == "SEC-002"]
    assert not [f for f in found("src/db.php", '$db->prepare("SELECT * FROM t WHERE id = :id")') if f[0] == "SEC-002"]
    assert not [f for f in found("app/db.py", 'cur.execute("SELECT * FROM t WHERE id = %s", (uid,))') if f[0] == "SEC-002"]
    assert not [f for f in found("app/db.py", '"SELECT * FROM products WHERE name LIKE \'%apple%\'"') if f[0] == "SEC-002"]
    assert not [f for f in found("web/db.js", '"SELECT * FROM products WHERE name LIKE \'%apple%\'"') if f[0] == "SEC-002"]
    assert not [f for f in found("src/Db.java", '"SELECT * FROM products WHERE name LIKE \'%apple%\'"') if f[0] == "SEC-002"]
    assert not [f for f in found("web/db.js", '"SELECT * FROM t".trim()') if f[0] == "SEC-002"]
    assert not [f for f in found("web/db.js", 'db.query("SELECT * FROM t WHERE id = $1", [id])') if f[0] == "SEC-002"]

def test_sec_003_ruby_erb_raw_is_case_sensitive():
    # <%= raw @comment %>-style raw(user_input) in .erb fires
    assert ("SEC-003", "HIGH") in found("app/views/comment.html.erb", "<%= raw(user_input) %>")
    assert ("SEC-003", "HIGH") in found("app/views/comment.html.erb", "raw(user_input)")
    # SQL builders and non-Ruby/ERB are quiet
    assert not [f for f in found("src/db.php", "DB::raw('count(*)')") if f[0] == "SEC-003"]
    assert not [f for f in found("web/query.js", "knex.raw('?')") if f[0] == "SEC-003"]
    assert not [f for f in found("app/models.py", 'Model.objects.raw("...")') if f[0] == "SEC-003"]
    assert not [f for f in found("pkg/db.go", 'db.Raw("...")') if f[0] == "SEC-003"]
    assert not [f for f in found("app/models.rb", "DB::raw('count(*)')") if f[0] == "SEC-003"]


def test_sec_005_php_ruby_method_calls_not_shell_calls():
    # Quiet PHP method/static calls
    assert not [f for f in found("src/db.php", '$pdo->exec("CREATE TABLE t (id int)")') if f[0] == "SEC-005"]
    assert not [f for f in found("src/db.php", '$db->exec("CREATE TABLE t (id int)")') if f[0] == "SEC-005"]
    assert not [f for f in found("src/db.php", 'SQLite3::exec("CREATE TABLE t (id int)")') if f[0] == "SEC-005"]
    assert not [f for f in found("src/db.php", '$redis->exec()') if f[0] == "SEC-005"]
    assert not [f for f in found("src/db.php", '$this->system($cmd)') if f[0] == "SEC-005"]
    # Quiet Ruby method calls
    assert not [f for f in found("app/db.rb", "conn.exec(sql)") if f[0] == "SEC-005"]
    assert not [f for f in found("app/db.rb", "obj.system(x)") if f[0] == "SEC-005"]
    # Firing PHP shell calls
    assert ("SEC-005", "HIGH") in found("src/cmd.php", "exec($cmd)")
    assert ("SEC-005", "HIGH") in found("src/cmd.php", 'system("ls " . $dir)')
    assert ("SEC-005", "HIGH") in found("src/cmd.php", "shell_exec($c)")
    # Firing Ruby shell calls
    assert ("SEC-005", "HIGH") in found("app/runner.rb", 'system("ls #{dir}")')
    assert ("SEC-005", "HIGH") in found("app/runner.rb", '`ls #{dir}`')


def test_a_tagged_template_is_a_parameterised_query():
    for line in ("const rows = await sql`SELECT * FROM users WHERE id = ${id}`",
                 "await prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`",
                 "db.execute(sql`DELETE FROM t WHERE id = ${id}`)"):
        assert not [r for r in found("web/db.ts", line) if r[0] == "SEC-002"], line
    for line in ("const q = `SELECT * FROM users WHERE id = ${id}`",
                 "return `SELECT * FROM users WHERE id = ${id}`",
                 "db.query(`SELECT * FROM users WHERE id = ${id}`)"):
        assert ("SEC-002", "CRITICAL") in found("web/db.ts", line), line


def test_backticks_inside_a_string_are_not_a_shell_command():
    assert not [r for r in found("app/db.php", '$pdo->query("SELECT * FROM `users` WHERE id = ?");') if r[0] == "SEC-005"]
    assert not [r for r in found("app/db.rb", 'q = "SELECT * FROM `users` WHERE id = ?"') if r[0] == "SEC-005"]
    assert ("SEC-005", "HIGH") in found("app/x.php", "$out = `ls $dir`;")
    assert ("SEC-005", "HIGH") in found("app/x.rb", "out = `ls #{dir}`")


def test_review_finding_1_sec_004_ruby_yaml_psych():
    assert ("SEC-004", "HIGH") in found("app/loader.rb", "cfg = YAML.unsafe_load(blob)")
    assert ("SEC-004", "HIGH") in found("app/loader.rb", "cfg = Psych.unsafe_load(blob)")
    assert ("SEC-004", "HIGH") in found("app/loader.rb", "cfg = Psych.load(blob)")
    assert not [f for f in found("app/loader.rb", "cfg = Psych.safe_load(blob)") if f[0] == "SEC-004"]
    assert not [f for f in found("app/loader.rb", "cfg = YAML.safe_load(blob)") if f[0] == "SEC-004"]


def test_review_finding_2_sec_003_ruby_erb_raw_and_output():
    assert ("SEC-003", "HIGH") in found("app/views/show.html.erb", "<%= raw @content %>")
    assert ("SEC-003", "HIGH") in found("app/views/show.html.erb", "<%== @content %>")
    assert ("SEC-003", "HIGH") in found("app/views/show.html.erb", "<%= raw(@content) %>")
    assert ("SEC-003", "HIGH") in found("app/views/show.html.erb", "@content.html_safe")
    assert ("SEC-003", "HIGH") in found("app/models/post.rb", "raw(content)")
    assert ("SEC-003", "HIGH") in found("app/models/post.rb", "content.html_safe")
    assert not [f for f in found("app/views/show.html.erb", "<%= h(x) %>") if f[0] == "SEC-003"]
    assert not [f for f in found("app/views/show.html.erb", "<%= x %>") if f[0] == "SEC-003"]


def test_review_finding_3_sec_002_cs_rust_formatters():
    assert ("SEC-002", "CRITICAL") in found("src/Repo.cs", 'var q = String.Format("SELECT * FROM users WHERE id = {0}", userId);')
    assert ("SEC-002", "CRITICAL") in found("src/Repo.cs", 'var q = string.Format("SELECT * FROM users WHERE id = {0}", userId);')
    assert ("SEC-002", "CRITICAL") in found("src/db.rs", 'let q = format!("SELECT * FROM users WHERE id = {name}");')
    assert ("SEC-002", "CRITICAL") in found("src/db.rs", 'let q = format!("SELECT * FROM users WHERE id = {}", user_id);')
    assert not [f for f in found("src/Repo.cs", 'var msg = String.Format("User: {0}", name);') if f[0] == "SEC-002"]
    assert not [f for f in found("src/db.rs", 'let msg = format!("Hello, {}", name);') if f[0] == "SEC-002"]


def test_review_finding_4_sec_003_js_innerhtml_regression():
    assert ("SEC-003", "HIGH") in found("web/comp.jsx", "<div dangerouslySetInnerHTML={{__html: html}} data-x={node.innerHTML} />")
    assert not [f for f in found("web/comp.jsx", "<div data-x={node.innerHTML} />") if f[0] == "SEC-003"]


def test_review_finding_6_sec_002_prose_is_not_sql():
    assert ("SEC-002", "CRITICAL") in found("src/db.py", 'q = "DELETE FROM users WHERE id = " + id')
    assert ("SEC-002", "CRITICAL") in found("src/db.py", 'q = "SELECT name FROM users WHERE id = " + id')
    assert ("SEC-002", "CRITICAL") in found("src/db.py", 'q = "SELECT * FROM " + table')
    assert ("SEC-002", "CRITICAL") in found("src/db.py", 'q = "DELETE FROM " + table + " WHERE id = " + id')
    assert ("SEC-002", "CRITICAL") in found("src/db.py", 'q = "SELECT u.* FROM users u WHERE id = " + uid')
    assert ("SEC-002", "CRITICAL") in found("src/db.py", 'q = "SELECT COALESCE(SUM(x), 0) FROM users WHERE id = " + uid')
    assert not [f for f in found("src/msg.py", 'msg = "delete user from group: " + groupId') if f[0] == "SEC-002"]
    assert not [f for f in found("src/msg.py", 'msg = "Please select an item from the list " + name') if f[0] == "SEC-002"]
    assert not [f for f in found("src/msg.py", 'msg = "update your profile settings " + x') if f[0] == "SEC-002"]

def test_review_finding_7_sec_005_declarations_are_not_calls():
    assert not [f for f in found("src/db.php", "function exec($sql) {") if f[0] == "SEC-005"]
    assert not [f for f in found("src/db.php", "public function system($x)") if f[0] == "SEC-005"]
    assert not [f for f in found("app/runner.rb", "def system(cmd)") if f[0] == "SEC-005"]
    assert not [f for f in found("app/runner.rb", "def exec(sql)") if f[0] == "SEC-005"]
    assert ("SEC-005", "HIGH") in found("src/db.php", "system($x);")
    assert ("SEC-005", "HIGH") in found("app/runner.rb", "system(cmd)")


def test_review_finding_8_sec_008_encrypted_storage():
    assert not [f for f in found("app/Prefs.java", 'encryptedPrefs.edit().putString("auth_token", token);') if f[0] == "SEC-008"]
    assert not [f for f in found("app/Prefs.kt", 'securePrefs.edit().putString("auth_token", token)') if f[0] == "SEC-008"]
    assert not [f for f in found("app/Prefs.java", 'EncryptedSharedPreferences.create(ctx).edit().putString("token", token);') if f[0] == "SEC-008"]
    assert not [f for f in found("src/Store.swift", 'Keychain.standard.set(token, forKey: "auth_token")') if f[0] == "SEC-008"]
    assert not [f for f in found("src/Store.swift", 'KeychainWrapper.standard.set(token, forKey: "auth_token")') if f[0] == "SEC-008"]
    assert not [f for f in found("src/Store.swift", 'SecureStore.set(token, forKey: "auth_token")') if f[0] == "SEC-008"]
    assert ("SEC-008", "MEDIUM") in found("app/Prefs.java", 'editor.putString("auth_token", token);')
    assert ("SEC-008", "MEDIUM") in found("src/Store.swift", 'UserDefaults.standard.set(token, forKey: "auth_token")')
    assert ("SEC-008", "MEDIUM") in found("app/Prefs.java", 'prefs.edit().putString("token", t).apply() // not EncryptedSharedPreferences')
    assert ("SEC-008", "MEDIUM") in found("src/Store.swift", 'UserDefaults.standard.set(token, forKey: "token") // TODO Keychain')
    assert not [f for f in found("app/Prefs.java", 'encryptedPrefs.edit().putString("token", t).apply()') if f[0] == "SEC-008"]
    assert not [f for f in found("app/Prefs.java", 'EncryptedSharedPreferences.create(...).edit().putString("token", t)') if f[0] == "SEC-008"]
    assert not [f for f in found("src/Store.swift", 'KeychainWrapper.standard.set(token, forKey: "token")') if f[0] == "SEC-008"]
    assert ("SEC-008", "MEDIUM") in found("app/Prefs.kt", 'prefs?.edit()?.putString("token", t)?.apply()')
    assert ("SEC-008", "MEDIUM") in found("app/Prefs.kt", 'prefs!!.edit().putString("token", t)')
    assert ("SEC-008", "MEDIUM") in found("app/Prefs.java", '    .putString("token", t)')
    assert ("SEC-008", "MEDIUM") in found("app/Prefs.java", 'PreferenceManager.getDefaultSharedPreferences(requireContext()).edit().putString("token", t)')
    assert not [f for f in found("app/Prefs.java", 'this.securePrefs.edit().putString("token", t)') if f[0] == "SEC-008"]
    assert ("SEC-008", "MEDIUM") in found("src/Store.swift", 'defaults?.set(token, forKey: "token")')
    assert ("SEC-008", "MEDIUM") in found("src/Store.swift", 'UserDefaults(suiteName: "group")?.set(token, forKey: "token")')
    assert ("SEC-008", "MEDIUM") in found("src/Store.swift", '    .set(token, forKey: "token")')
    assert not [f for f in found("src/Store.swift", 'self.keychain.set(token, forKey: "token")') if f[0] == "SEC-008"]
    assert ("SEC-008", "MEDIUM") in found("app/Prefs.java", 'if (!prefs.edit().putString("token", t)) {')
    assert ("SEC-008", "MEDIUM") in found("app/Prefs.java", '((MyApp) getApplication()).prefs.edit().putString("token", t);')
    assert ("SEC-008", "MEDIUM") in found("app/Prefs.java", 'log(securePrefs); prefs.edit().putString("token", t);')
    assert not [f for f in found("app/Prefs.kt", 'encryptedPrefs.edit { putString("token", t) }') if f[0] == "SEC-008"]
    assert not [f for f in found("app/Prefs.kt", 'encryptedPrefs.edit().apply { putString("token", t) }') if f[0] == "SEC-008"]
    assert not [f for f in found("src/Store.swift", 'let a = UserDefaults.standard.bool(forKey: "x"); KeychainWrapper.standard.set(token, forKey: "token")') if f[0] == "SEC-008"]
    assert ("SEC-008", "MEDIUM") in found("app/Prefs.java", 'save(securePrefs, prefs.edit().putString("token", t));')
    assert ("SEC-008", "MEDIUM") in found("app/Prefs.java", '/* securePrefs */ prefs.edit().putString("token", t);')
    assert not [f for f in found("app/Prefs.kt", 'encryptedPrefs.edit { putString("a", a); putString("token", t) }') if f[0] == "SEC-008"]
    assert not [f for f in found("app/Prefs.kt", 'with(encryptedPrefs.edit()) { putString("token", t) }') if f[0] == "SEC-008"]

def test_review_finding_sec_002_insert_update_literals():
    assert ("SEC-002", "CRITICAL") in found("src/db.py", 'q = "INSERT INTO " + table + " VALUES (?)"')
    assert ("SEC-002", "CRITICAL") in found("web/db.js", 'const q = "INSERT INTO " + table + " VALUES (?)";')
    assert ("SEC-002", "CRITICAL") in found("src/db.py", 'q = "UPDATE users SET " + col + " = 1"')
    assert ("SEC-002", "CRITICAL") in found("web/db.js", 'const q = "UPDATE users SET " + col + " = 1";')
    assert ("SEC-002", "CRITICAL") in found("src/db.py", 'q = "UPDATE " + table + " SET x = 1"')
    assert ("SEC-002", "CRITICAL") in found("web/db.js", 'const q = "UPDATE " + table + " SET x = 1";')
    assert ("SEC-002", "CRITICAL") in found("src/db.py", 'q = "INSERT INTO " + table')
    assert ("SEC-002", "CRITICAL") in found("web/db.js", 'const q = "INSERT INTO " + table;')
    assert ("SEC-002", "CRITICAL") in found("src/db.py", 'q = "DELETE FROM " + table')
    assert ("SEC-002", "CRITICAL") in found("web/db.js", 'const q = "DELETE FROM " + table;')
    assert ("SEC-002", "CRITICAL") in found("src/db.py", 'q = "SELECT * FROM " + table')
    assert ("SEC-002", "CRITICAL") in found("web/db.js", 'const q = "SELECT * FROM " + table;')
    assert not [f for f in found("src/msg.py", 'msg = "update" + id') if f[0] == "SEC-002"]
    assert not [f for f in found("web/msg.js", 'const msg = "update" + id;') if f[0] == "SEC-002"]
    assert not [f for f in found("src/msg.py", 'msg = "Update " + version') if f[0] == "SEC-002"]
    assert not [f for f in found("web/msg.js", 'const msg = "Update " + version;') if f[0] == "SEC-002"]
    assert not [f for f in found("src/msg.py", 'emit("update" + name)') if f[0] == "SEC-002"]
    assert not [f for f in found("web/msg.js", 'emit("update" + name);') if f[0] == "SEC-002"]
    assert not [f for f in found("src/msg.py", 'label = "UPDATE" + suffix') if f[0] == "SEC-002"]
    assert not [f for f in found("web/msg.js", 'const label = "UPDATE" + suffix;') if f[0] == "SEC-002"]
    assert not [f for f in found("src/msg.py", 'msg = "Please update your settings"') if f[0] == "SEC-002"]
    assert not [f for f in found("web/msg.js", 'const msg = "Please update your settings";') if f[0] == "SEC-002"]
    assert not [f for f in found("src/msg.py", 'msg = "insert into the cart"') if f[0] == "SEC-002"]
    assert not [f for f in found("web/msg.js", 'const msg = "insert into the cart";') if f[0] == "SEC-002"]
    assert ("SEC-002", "CRITICAL") in found("src/db.py", 'q = "insert into " + x')
    assert ("SEC-002", "CRITICAL") in found("web/db.js", 'const q = "insert into " + x;')

def test_review_finding_sec_005_multiline_and_heredoc_backticks():
    assert not [f for f in found("src/db.php", '$sql = "SELECT `id`,', 'FROM `users`', 'WHERE id = ?";') if f[0] == "SEC-005"]
    assert not [f for f in found("src/db.php", "$sql = 'SELECT `id`,", 'FROM `users`', "WHERE id = ?';") if f[0] == "SEC-005"]
    assert not [f for f in found("app/db.rb", 'execute <<~SQL', 'ALTER TABLE `users` ADD COLUMN `age` INT', 'SQL') if f[0] == "SEC-005"]
    assert not [f for f in found("app/db.rb", "execute <<~'SQL'", 'ALTER TABLE `users` ADD COLUMN `age` INT', 'SQL') if f[0] == "SEC-005"]
    assert ("SEC-005", "HIGH") in found("src/db.php", '$sql = "SELECT `id`,', 'FROM `users`', 'WHERE id = ?";', '$out = `ls $dir`;')
    assert ("SEC-005", "HIGH") in found("app/db.rb", 'execute <<~SQL', 'ALTER TABLE `users` ADD COLUMN `age` INT', 'SQL', 'out = `ls #{dir}`')

    diff_ctx_php = (
        "+++ b/src/db.php\n"
        "@@ -10,2 +10,4 @@\n"
        " $sql = \"SELECT `id`,\n"
        "+FROM `users`\n"
        " WHERE id = ?\";\n"
        "+$out = `ls $dir`;\n"
    )
    hits_php = [v for v in OCRRulebookRunner().scan_diff(diff_ctx_php) if v.rule_id == "SEC-005"]
    assert len(hits_php) == 1 and hits_php[0].line_number == 13

    diff_ctx_rb = (
        "+++ b/app/db.rb\n"
        "@@ -20,2 +20,4 @@\n"
        " execute <<~SQL\n"
        "+ALTER TABLE `users` ADD COLUMN `age` INT\n"
        " SQL\n"
        "+out = `ls #{dir}`\n"
    )
    hits_rb = [v for v in OCRRulebookRunner().scan_diff(diff_ctx_rb) if v.rule_id == "SEC-005"]
    assert len(hits_rb) == 1 and hits_rb[0].line_number == 23


def test_review_finding_sec_005_comments_do_not_carry_strings():
    # PHPDoc block comment
    assert ("SEC-005", "HIGH") in found("src/cmd.php", "/**", " * Don't run this.", " */", "$out = `ls $dir`;")
    # PHP line comments (// and #)
    assert ("SEC-005", "HIGH") in found("src/cmd.php", "// don't do this", "$out = `ls $dir`;")
    assert ("SEC-005", "HIGH") in found("src/cmd.php", "# don't do this", "$out = `ls $dir`;")
    # Ruby line comment (#)
    assert ("SEC-005", "HIGH") in found("app/runner.rb", "# it's fine", "out = `ls #{dir}`")
    # Ruby block comment (=begin ... =end)
    assert ("SEC-005", "HIGH") in found("app/runner.rb", "=begin", "Don't run this.", "=end", "out = `ls #{dir}`")


def test_fix7_sec_002_sql_split_across_literals():
    # Python & JS positive cases: chain of literals followed by variable
    assert ("SEC-002", "CRITICAL") in found("app/db.py", 'q = "SELECT a FROM t " + "WHERE id = " + uid')
    assert ("SEC-002", "CRITICAL") in found("web/db.js", 'const q = "SELECT a FROM t " + "WHERE id = " + uid;')
    assert ("SEC-002", "CRITICAL") in found("app/db.py", 'q = "SELECT * FROM t WHERE name = " + "\'" + name + "\'"')
    assert ("SEC-002", "CRITICAL") in found("web/db.js", 'const q = "SELECT * FROM t WHERE name = " + "\'" + name + "\'";')

    # Quiet cases: only literals
    assert not [f for f in found("app/db.py", '"SELECT a FROM t " + "WHERE id = 1"') if f[0] == "SEC-002"]
    assert not [f for f in found("web/db.js", 'const q = "SELECT a FROM t " + "WHERE id = 1";') if f[0] == "SEC-002"]
    assert not [f for f in found("app/db.py", 'q = "SELECT a FROM t " + "WHERE id = " + "1"') if f[0] == "SEC-002"]
    assert not [f for f in found("src/db.php", '$q = "SELECT a FROM t " . "WHERE id = 1";') if f[0] == "SEC-002"]


def test_fix7_sec_004_php_unserialize():
    # Skip declarations
    assert not [f for f in found("src/User.php", "function unserialize($str) {") if f[0] == "SEC-004"]
    assert not [f for f in found("src/User.php", "public function unserialize($str) {") if f[0] == "SEC-004"]
    assert not [f for f in found("src/User.php", "public static function unserialize($str) {") if f[0] == "SEC-004"]
    assert not [f for f in found("src/User.php", "protected function unserialize($str) {") if f[0] == "SEC-004"]
    assert not [f for f in found("src/User.php", "private function unserialize($str) {") if f[0] == "SEC-004"]
    # Skip calls with allowed_classes => false
    assert not [f for f in found("src/User.php", "$data = unserialize($str, ['allowed_classes' => false]);") if f[0] == "SEC-004"]
    assert not [f for f in found("src/User.php", '$data = unserialize($str, ["allowed_classes" => false]);') if f[0] == "SEC-004"]
    assert not [f for f in found("src/User.php", "$data = unserialize($str, ['allowed_classes'=>false]);") if f[0] == "SEC-004"]
    assert not [f for f in found("src/User.php", "$data = unserialize($str, [ 'allowed_classes'  =>  false ]);") if f[0] == "SEC-004"]
    # Still fires:
    assert ("SEC-004", "HIGH") in found("src/User.php", "$o = unserialize($data);")
    assert ("SEC-004", "HIGH") in found("src/User.php", "unserialize($blob, ['allowed_classes' => true])")


def test_fix7_sec_004_java_kotlin():
    # Quiet: imports, type positions, jsonReader.readObject()
    assert not [f for f in found("src/Loader.java", "import java.io.ObjectInputStream;") if f[0] == "SEC-004"]
    assert not [f for f in found("src/Loader.kt", "import java.io.ObjectInputStream") if f[0] == "SEC-004"]
    assert not [f for f in found("src/Loader.java", "private void readObject(ObjectInputStream in) {") if f[0] == "SEC-004"]
    assert not [f for f in found("src/Loader.kt", "fun readObject(in: ObjectInputStream) {") if f[0] == "SEC-004"]
    assert not [f for f in found("src/Loader.java", "jsonReader.readObject();") if f[0] == "SEC-004"]
    assert not [f for f in found("src/Loader.kt", "val stream: ObjectInputStream") if f[0] == "SEC-004"]
    # Still fires: stream construction and enableDefaultTyping/activateDefaultTyping
    assert ("SEC-004", "HIGH") in found("src/Loader.java", "new ObjectInputStream(stream);")
    assert ("SEC-004", "HIGH") in found("src/Loader.kt", "val ois = ObjectInputStream(input)")
    assert ("SEC-004", "HIGH") in found("src/Loader.kt", "mapper.enableDefaultTyping();")
    assert ("SEC-004", "HIGH") in found("src/Loader.java", "mapper.activateDefaultTyping(ptv);")


def test_fix7_sec_005_go_command_context():
    # exec.CommandContext positive test
    assert ("SEC-005", "HIGH") in found("pkg/exec.go", 'exec.CommandContext(ctx, "sh", "-c", cmd)')
    assert ("SEC-005", "HIGH") in found("pkg/exec.go", 'exec.CommandContext(r.Context(), "bash", "-c", cmd)')
    assert ("SEC-005", "HIGH") in found("pkg/exec.go", 'exec.CommandContext(context.Background(), "/bin/sh", "-c", cmd)')
    assert not [f for f in found("pkg/exec.go", 'exec.CommandContext(ctx, "git", "status")') if f[0] == "SEC-005"]


def test_fix7_sec_005_ruby():
    # Positive tests: system/exec without parens, %x{}, %x[], IO.popen, Kernel.system
    assert ("SEC-005", "HIGH") in found("app/runner.rb", 'system "rm -rf #{dir}"')
    assert ("SEC-005", "HIGH") in found("app/runner.rb", 'exec "ls -la"')
    assert ("SEC-005", "HIGH") in found("app/runner.rb", '%x{echo test}')
    assert ("SEC-005", "HIGH") in found("app/runner.rb", '%x[echo test]')
    assert ("SEC-005", "HIGH") in found("app/runner.rb", 'IO.popen("ls")')
    assert ("SEC-005", "HIGH") in found("app/runner.rb", 'IO.popen(["ls", "-l"])')
    assert ("SEC-005", "HIGH") in found("app/runner.rb", 'Kernel.system("rm -rf #{dir}")')
    assert ("SEC-005", "HIGH") in found("app/runner.rb", 'Kernel.system "rm -rf #{dir}"')
    # Skipping receivers other than Kernel/IO and def declarations
    assert not [f for f in found("app/runner.rb", "def system(cmd)") if f[0] == "SEC-005"]
    assert not [f for f in found("app/runner.rb", "def exec(cmd)") if f[0] == "SEC-005"]
    assert not [f for f in found("app/runner.rb", 'obj.system("ls")') if f[0] == "SEC-005"]
    assert not [f for f in found("app/runner.rb", 'MyClass.system("ls")') if f[0] == "SEC-005"]
    assert not [f for f in found("app/runner.rb", 'sub::system("ls")') if f[0] == "SEC-005"]
    assert not [f for f in found("app/runner.rb", 'foo->system("ls")') if f[0] == "SEC-005"]
    assert not [f for f in found("app/runner.rb", 'obj.popen("ls")') if f[0] == "SEC-005"]


def test_fix7_sec_005_csharp():
    # ProcessStartInfo constructors and FileName initializers
    assert ("SEC-005", "HIGH") in found("src/Proc.cs", 'new ProcessStartInfo("cmd.exe");')
    assert ("SEC-005", "HIGH") in found("src/Proc.cs", 'new ProcessStartInfo("/bin/sh");')
    assert ("SEC-005", "HIGH") in found("src/Proc.cs", 'new ProcessStartInfo("bash");')
    assert ("SEC-005", "HIGH") in found("src/Proc.cs", 'new ProcessStartInfo("powershell");')
    assert ("SEC-005", "HIGH") in found("src/Proc.cs", 'new ProcessStartInfo { FileName = "cmd.exe" };')
    assert ("SEC-005", "HIGH") in found("src/Proc.cs", 'info.FileName = "/bin/sh";')
    assert ("SEC-005", "HIGH") in found("src/Proc.cs", 'FileName = "bash"')
    assert ("SEC-005", "HIGH") in found("src/Proc.cs", 'FileName = "powershell"')
    assert not [f for f in found("src/Proc.cs", 'new ProcessStartInfo("git");') if f[0] == "SEC-005"]
    assert not [f for f in found("src/Proc.cs", 'FileName = "myapp.exe"') if f[0] == "SEC-005"]


def test_fix7_ruby_xss():
    # Quiet: str.html_safe? and def raw(value)
    assert not [f for f in found("app/views.rb", "str.html_safe?") if f[0] == "SEC-003"]
    assert not [f for f in found("app/views.rb", "if str.html_safe? then") if f[0] == "SEC-003"]
    assert not [f for f in found("app/views.rb", "def raw(value)") if f[0] == "SEC-003"]
    assert not [f for f in found("app/views.rb", "def raw(value); end") if f[0] == "SEC-003"]
    # Still fires: raw(user_input) and x.html_safe
    assert ("SEC-003", "HIGH") in found("app/views.rb", "raw(user_input)")
    assert ("SEC-003", "HIGH") in found("app/views.rb", "x.html_safe")


def test_fix7_sec_005_swift_and_rust_multiline_builders():
    # Swift multiline builder
    swift_lines = [
        "let process = Process()",
        'process.launchPath = "/bin/sh"',
        'process.arguments = ["-c", userCmd]',
        "process.launch()",
    ]
    swift_diff = "+++ b/src/Proc.swift\n@@ -0,0 +1,4 @@\n" + "".join(f"+{l}\n" for l in swift_lines)
    swift_hits = [v for v in OCRRulebookRunner().scan_diff(swift_diff) if v.rule_id == "SEC-005"]
    assert len(swift_hits) >= 1
    assert swift_hits[0].line_number == 2

    # Swift executableURL
    swift_url_lines = [
        "let process = Process()",
        'process.executableURL = URL(fileURLWithPath: "/bin/bash")',
        "try process.run()",
    ]
    swift_url_diff = "+++ b/src/Proc.swift\n@@ -0,0 +1,3 @@\n" + "".join(f"+{l}\n" for l in swift_url_lines)
    swift_url_hits = [v for v in OCRRulebookRunner().scan_diff(swift_url_diff) if v.rule_id == "SEC-005"]
    assert len(swift_url_hits) >= 1
    assert swift_url_hits[0].line_number == 2

    # Swift quiet
    assert not [f for f in found("src/Proc.swift", 'process.launchPath = "/usr/bin/git"') if f[0] == "SEC-005"]

    # Rust multiline builder
    rust_lines = [
        'let output = Command::new("sh")',
        '    .arg("-c")',
        "    .arg(user_input)",
        "    .output()?;",
    ]
    rust_diff = "+++ b/src/proc.rs\n@@ -0,0 +1,4 @@\n" + "".join(f"+{l}\n" for l in rust_lines)
    rust_hits = [v for v in OCRRulebookRunner().scan_diff(rust_diff) if v.rule_id == "SEC-005"]
    # Both lines 1 and 2 match on their own
    assert any(h.line_number == 1 for h in rust_hits)
    assert any(h.line_number == 2 for h in rust_hits)

    # Rust with .args(["-c", ...]) and cmd /C
    assert ("SEC-005", "HIGH") in found("src/proc.rs", '    .args(["-c", &user_input])')
    assert ("SEC-005", "HIGH") in found("src/proc.rs", 'Command::new("cmd")')
    assert ("SEC-005", "HIGH") in found("src/proc.rs", '    .arg("/C")')

    # Rust quiet
    assert not [f for f in found("src/proc.rs", 'Command::new("git")') if f[0] == "SEC-005"]
    assert not [f for f in found("src/proc.rs", 'Command::new("git").arg("-C")') if f[0] == "SEC-005"]
    assert not [f for f in found("src/proc.rs", '    .arg("-C")') if f[0] == "SEC-005"]
    assert not [f for f in found("src/proc.rs", '    .arg("status")') if f[0] == "SEC-005"]


def test_fix8b_review_findings():
    # 1. JS tagged templates
    assert not [f for f in found("web/db.ts", "const rows = await sql`SELECT * FROM t WHERE id = ${id}`;") if f[0] == "SEC-002"]
    assert not [f for f in found("web/db.ts", "const rows = await prisma.$queryRaw`SELECT * FROM t WHERE id = ${id}`;") if f[0] == "SEC-002"]
    assert ("SEC-002", "CRITICAL") in found("web/db.ts", "const rows = await unsafeSql`SELECT * FROM t WHERE id = ${id}`;")
    assert ("SEC-002", "CRITICAL") in found("web/db.ts", "const rows = await fn()`SELECT * FROM t WHERE id = ${id}`;")

    # 2. SELECT split around a column variable
    assert ("SEC-002", "CRITICAL") in found("app/db.py", 'query = "SELECT " + cols + " FROM users WHERE id = " + uid')
    assert ("SEC-002", "CRITICAL") in found("web/db.js", 'const query = "SELECT " + cols + " FROM users WHERE id = " + uid;')
    # Quiet stays quiet
    assert not [f for f in found("app/ui.py", 'msg = "Select " + item') if f[0] == "SEC-002"]
    assert not [f for f in found("app/ui.py", 'label = "From " + name') if f[0] == "SEC-002"]
    assert not [f for f in found("web/ui.js", 'const msg = "Select " + item;') if f[0] == "SEC-002"]
    assert not [f for f in found("web/ui.js", 'const label = "From " + name;') if f[0] == "SEC-002"]

    # 3. Ruby =begin/=end block comments only at column zero
    assert ("SEC-005", "HIGH") in found("app/runner.rb", 'x = "=begin"', 'out = `ls #{dir}`')
    # Real column-zero =begin ... =end hides its content
    assert not [f for f in found("app/runner.rb", "=begin", 'out = `ls #{dir}`', "=end") if f[0] == "SEC-005"]

    # 4. Rust -C is not a shell flag
    assert not [f for f in found("src/proc.rs", 'Command::new("git").arg("-C").spawn();') if f[0] == "SEC-005"]

    # 5. SEC-003 Markup( case-sensitively in Python only
    assert not [f for f in found("web/view.js", "const html = markup(x);") if f[0] == "SEC-003"]
    assert not [f for f in found("app/view.py", "html = markup(x)") if f[0] == "SEC-003"]
    assert ("SEC-003", "HIGH") in found("app/view.py", "html = Markup(user)")
