"""
The quality matrix's line rules: each finds the risky line in the files it is about, leaves the safe
form, comments, docs and tests alone, and turns into a LOW note with `guard-allow <rule>: <reason>`.
"""

import pytest

from guard.core.rulebook import LINE_RULES, OCRRulebookRunner


def found(path: str, *lines: str) -> list:
    diff = f"+++ b/{path}\n@@ -0,0 +1,{len(lines)} @@\n" + "".join(f"+{line}\n" for line in lines)
    ids = {r[0] for r in LINE_RULES}
    return [(v.rule_id, v.severity) for v in OCRRulebookRunner().scan_diff(diff) if v.rule_id in ids]


@pytest.mark.parametrize("path, risky, safe, rule, severity", [
    ("app/load.py", "cfg = yaml.load(stream)", "cfg = yaml.load(stream, Loader=yaml.SafeLoader)", "SEC-004", "HIGH"),
    ("app/load.py", "obj = pickle.loads(blob)", "obj = json.loads(blob)", "SEC-004", "HIGH"),
    ("app/run.py", "subprocess.run(cmd, shell=True)", "subprocess.run([\"git\", \"status\"])", "SEC-005", "HIGH"),
    ("app/run.py", "value = eval(text)", "value = ast.literal_eval(text)", "SEC-005", "HIGH"),
    ("web/app.ts", "const f = new Function(body)", "const f = () => body", "SEC-005", "HIGH"),
    ("app/http.py", "requests.get(url, verify=False)", "requests.get(url, verify=ca_bundle)", "SEC-006", "HIGH"),
    ("web/https.js", "const agent = new Agent({ rejectUnauthorized: false })", "const agent = new Agent({ ca })", "SEC-006", "HIGH"),
    ("api/main.py", "app.add_middleware(CORSMiddleware, allow_origins=[\"*\"])",
     "app.add_middleware(CORSMiddleware, allow_origins=[\"https://app.example.com\"])", "SEC-007", "MEDIUM"),
    ("web/auth.ts", "localStorage.setItem('access_token', token)", "localStorage.setItem('theme', 'dark')", "SEC-008", "MEDIUM"),
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


def interval(*lines: str) -> list:
    diff = "+++ b/web/clock.ts\n@@ -0,0 +1,3 @@\n" + "".join(f"+{line}\n" for line in lines)
    return [v.rule_id for v in OCRRulebookRunner().scan_diff(diff) if v.rule_id == "PERF-003"]


def test_an_interval_needs_its_clear_in_the_same_change():
    assert interval("const id = setInterval(tick, 1000)") == ["PERF-003"]
    assert interval("const id = setInterval(tick, 1000)", "return () => clearInterval(id)") == []
    assert interval("// setInterval(tick) is not used here") == []


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


def test_an_interval_cleared_in_another_file_or_on_a_removed_line_does_not_count():
    diff = ("+++ b/web/a.ts\n@@ -1,2 +1,1 @@\n-clearInterval(id)\n+const id = setInterval(tick, 1000)\n"
            "+++ b/web/b.ts\n@@ -0,0 +1,1 @@\n+clearInterval(other)\n")
    assert [v.rule_id for v in OCRRulebookRunner().scan_diff(diff) if v.rule_id == "PERF-003"] == ["PERF-003"]


def test_a_very_long_line_is_skipped_quickly():
    import time
    start = time.monotonic()
    assert not found("web/bundle.html", "<img src=x " * 20000)
    assert time.monotonic() - start < 2


DEPLOYMENT = ["apiVersion: apps/v1", "kind: Deployment", "metadata:", "  name: api", "spec:", "  template:",
              "    spec:", "      containers:", "        - name: api", "          image: registry.example.com/api:1.4.2"]


def workload(path: str, lines: list) -> list:
    diff = f"+++ b/{path}\n@@ -0,0 +1,{len(lines)} @@\n" + "".join(f"+{line}\n" for line in lines)
    return sorted((v.rule_id, v.severity) for v in OCRRulebookRunner().scan_diff(diff) if v.rule_id.startswith("INFRA-00"))


def test_a_new_workload_needs_limits_and_probes():
    assert workload("k8s/api.yaml", DEPLOYMENT) == [("INFRA-004", "MEDIUM"), ("INFRA-005", "LOW")]
    ready = DEPLOYMENT + ["          resources:", "            limits:", "              memory: 256Mi",
                          "          readinessProbe:", "            httpGet: {path: /health, port: 8080}"]
    assert workload("k8s/api.yaml", ready) == []


def test_a_job_needs_limits_but_no_probe():
    job = [line.replace("Deployment", "Job") for line in DEPLOYMENT]
    assert workload("k8s/migrate.yaml", job) == [("INFRA-004", "MEDIUM")]


def test_an_edited_manifest_is_not_judged_on_the_lines_it_shows():
    diff = ("+++ b/k8s/api.yaml\n@@ -20,3 +20,4 @@\n       containers:\n+        - name: sidecar\n"
            "+          image: registry.example.com/proxy:2.1.0\n")
    assert [v.rule_id for v in OCRRulebookRunner().scan_diff(diff) if v.rule_id in ("INFRA-004", "INFRA-005")] == []


def test_yaml_that_is_not_a_workload_is_left_alone():
    assert workload(".github/workflows/ci.yml", ["jobs:", "  test:", "    container:", "      image: python:3.12"]) == []


def test_a_helm_template_is_left_to_its_values():
    templated = DEPLOYMENT + ["          resources: {{- toYaml .Values.resources | nindent 12 }}"]
    assert workload("chart/templates/deployment.yaml", templated) == []


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
    diff = "+++ b/web/a.ts\n@@ -0,0 +1,2 @@\n+const t = setInterval(tick, 10)\n+// clearInterval(t) later\n"
    assert [v.rule_id for v in OCRRulebookRunner().scan_diff(diff) if v.rule_id == "PERF-003"] == ["PERF-003"]


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


def test_a_clear_interval_in_a_string_or_comment_does_not_count():
    diff = ('+++ b/web/a.ts\n@@ -0,0 +1,3 @@\n+const id = setInterval(tick, 1000)\n'
            '+const note = "clearInterval(id)"\n+log(x) // clearInterval(id) later\n')
    assert [v.rule_id for v in OCRRulebookRunner().scan_diff(diff) if v.rule_id == "PERF-003"] == ["PERF-003"]


def test_each_yaml_document_is_judged_on_its_own_limits():
    limited = DEPLOYMENT + ["          resources:", "            limits: {memory: 256Mi}",
                            "          readinessProbe: {httpGet: {path: /h, port: 80}}"]
    second = [line.replace("name: api", "name: worker") for line in DEPLOYMENT]
    assert workload("k8s/all.yaml", limited + ["---"] + second) == [("INFRA-004", "MEDIUM"), ("INFRA-005", "LOW")]


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


def test_intervals_in_docs_and_comments_are_not_code():
    for diff in ("+++ b/docs/guide.js\n@@ -0,0 +1,1 @@\n+setInterval(tick, 10)\n",
                 "+++ b/web/a.ts\n@@ -0,0 +1,1 @@\n+run() // setInterval(tick) is gone\n"):
        assert [v.rule_id for v in OCRRulebookRunner().scan_diff(diff) if v.rule_id == "PERF-003"] == []
    assert workload("docs/examples/api.yaml", DEPLOYMENT) == []


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


def test_workload_limits_in_flow_style_and_guard_allow():
    flow = DEPLOYMENT + ["          resources: {limits: {memory: 1Gi}}"]
    assert ("INFRA-004", "MEDIUM") not in workload("k8s/api.yaml", flow)
    allowed = [line + "  # guard-allow INFRA-004: limits come from a LimitRange" if line.strip() == "containers:" else line
               for line in DEPLOYMENT]
    assert ("INFRA-004", "LOW") in workload("k8s/api.yaml", allowed)
