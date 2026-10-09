from guard.core.diff_inspector import GitDiffInspector
from guard.core.invariant_eval import _removed_lines
from guard.core.rulebook import OCRRulebookRunner
from guard.core.unified_diff import (
    chunk_paths,
    decode_git_path,
    parse_file_header,
    parse_git_header,
    parse_hunk_header,
    split_file_chunks,
    walk_diff,
)


def kinds(diff):
    return [(d.kind, d.raw) for d in walk_diff(diff)]


def test_git_header_reads_plain_spaced_quoted_and_escaped_paths():
    assert parse_git_header("diff --git a/src/a.py b/src/a.py") == ("src/a.py", "src/a.py")
    assert parse_git_header("diff --git a/my file.py b/my file.py") == ("my file.py", "my file.py")
    assert parse_git_header('diff --git "a/say \\"hi\\".py" "b/say \\"hi\\".py"') == ('say "hi".py', 'say "hi".py')
    assert parse_git_header('diff --git "a/caf\\303\\251.py" "b/caf\\303\\251.py"') == ("café.py", "café.py")
    assert parse_git_header("diff --git a/bánh mì.py b/bánh mì.py") == ("bánh mì.py", "bánh mì.py")
    assert parse_git_header('diff --git a/x.py "b/tab\\there.py"') == ("x.py", "tab\there.py")
    assert parse_git_header("index 123..456") is None


def test_git_header_with_b_slash_inside_the_path():
    # the same path on both sides: the split that gives two equal paths wins over the last ` b/`
    assert parse_git_header("diff --git a/x b/y.py b/x b/y.py") == ("x b/y.py", "x b/y.py")
    assert parse_git_header("diff --git a/old.py b/new.py") == ("old.py", "new.py")


def test_file_and_hunk_headers():
    assert parse_file_header("--- a/src/a.py") == "src/a.py"
    assert parse_file_header("+++ b/src/a.py") == "src/a.py"
    assert parse_file_header("--- /dev/null") == ""
    assert parse_file_header('+++ "b/caf\\303\\251.py"') == "café.py"
    assert parse_file_header("--- a/old.py\t2026-01-01 10:00:00") == "old.py"
    assert parse_file_header("-- x") is None
    assert parse_hunk_header("@@ -1 +1 @@") == (1, 1, 1, 1)
    assert parse_hunk_header("@@ -10,3 +12,0 @@ def f():") == (10, 3, 12, 0)
    assert parse_hunk_header("@@  -1,2  +1,3  @@") == (1, 2, 1, 3)
    assert parse_hunk_header("@@@ -1 -1 +1 @@@") is None


def test_decode_git_path_leaves_unquoted_paths_alone():
    assert decode_git_path("plain/path.py") == "plain/path.py"
    assert decode_git_path('"a\\\\b"') == "a\\b"


def test_walk_numbers_lines_and_reads_a_removed_sql_comment_as_content():
    diff = (
        "diff --git a/q.sql b/q.sql\n"
        "index 1..2 100644\n"
        "--- a/q.sql\n"
        "+++ b/q.sql\n"
        "@@ -1,3 +1,3 @@\n"
        " select 1;\n"
        "--- old comment\n"
        "+++ new comment\n"
        " select 2;\n"
    )
    lines = list(walk_diff(diff))
    assert [d.kind for d in lines] == ["file", "meta", "header", "header", "hunk", " ", "-", "+", " "]
    removed = lines[6]
    assert removed.text == "-- old comment" and removed.old_no == 2 and removed.path == "q.sql"
    added = lines[7]
    assert added.text == "++ new comment" and added.new_no == 2
    assert lines[8].old_no == 3 and lines[8].new_no == 3


def test_walk_marks_new_deleted_renamed_and_binary_files():
    diff = (
        "diff --git a/new.py b/new.py\nnew file mode 100644\n--- /dev/null\n+++ b/new.py\n@@ -0,0 +1 @@\n+x\n"
        "diff --git a/gone.py b/gone.py\ndeleted file mode 100644\n--- a/gone.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-y\n"
        "diff --git a/old name.py b/new name.py\nsimilarity index 90%\nrename from old name.py\n"
        "rename to new name.py\n--- a/old name.py\n+++ b/new name.py\n@@ -1 +1 @@\n-a\n+b\n"
        "diff --git a/logo.png b/logo.png\nBinary files a/logo.png and b/logo.png differ\n"
    )
    content = [d for d in walk_diff(diff) if d.kind in "+-"]
    assert [(d.path, d.added, d.deleted) for d in content] == [
        ("new.py", True, False),
        ("gone.py", False, True),
        ("new name.py", False, False),
        ("new name.py", False, False),
    ]
    assert content[2].old_path == "old name.py"
    binary = [d for d in walk_diff(diff) if d.raw.startswith("Binary")]
    assert binary[0].kind == "meta" and binary[0].path == "logo.png"


def test_walk_handles_no_newline_marker_crlf_and_blank_context():
    diff = "diff --git a/a.py b/a.py\r\n--- a/a.py\r\n+++ b/a.py\r\n@@ -1,3 +1,3 @@\r\n a\r\n\r\n-b\r\n\\ No newline at end of file\r\n+c\r\n"
    lines = [d for d in walk_diff(diff) if d.kind not in ("file", "header", "meta")]
    assert [d.kind for d in lines] == ["hunk", " ", " ", "-", "\\", "+"]
    assert [d.raw for d in lines][1:3] == [" a", " "]  # an empty line inside a hunk is empty context
    assert lines[5].new_no == 3


def test_walk_keeps_reading_content_of_a_miscounted_hunk_but_stops_at_the_next_file():
    diff = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-a\n+b\n+c\ndiff --git a/b.py b/b.py\n"
    assert [d.kind for d in walk_diff(diff)][-4:] == ["-", "+", "+", "file"]
    after_count = "@@ -1 +1 @@\n-a\n+b\n--- a/next.py\n+++ b/next.py\n"
    assert [d.kind for d in walk_diff(after_count)][-2:] == ["header", "header"]
    assert list(walk_diff(after_count))[-1].path == "next.py"


def test_walk_starts_a_new_file_inside_a_hunk_cut_short():
    diff = "diff --git a/a.py b/a.py\n@@ -1,9 +1,9 @@\n a\ndiff --git a/b.py b/b.py\n@@ -1 +1 @@\n-x\n+y\n"
    assert [(d.kind, d.path) for d in walk_diff(diff) if d.kind in "+-file"] == [
        ("file", "a.py"), ("file", "b.py"), ("-", "b.py"), ("+", "b.py")
    ]


def test_walk_does_not_split_on_form_feed():
    diff = "diff --git a/a.py b/a.py\n@@ -1 +1 @@\n-a\x0cb\n+c\n"
    assert [d.text for d in walk_diff(diff) if d.kind == "-"] == ["a\x0cb"]


def test_split_file_chunks_keeps_text_and_ignores_diff_git_in_content():
    raw = "# [ERROR: x]\ndiff --git a/a.py b/a.py\n@@ -1 +1 @@\n+diff --git a/z b/z\ndiff --git a/b.py b/b.py\n"
    head, chunks = split_file_chunks(raw)
    assert head == "# [ERROR: x]\n" and len(chunks) == 2
    assert head + "".join(chunks) == raw
    assert chunk_paths(chunks[0]) == ("a.py", "a.py")
    assert split_file_chunks("") == ("", [])
    assert split_file_chunks("diff --git a/a b/a\n") == ("", ["diff --git a/a b/a\n"])


def test_chunk_paths_prefers_file_headers():
    chunk = "diff --git a/x b/y.py b/z.py\nrename from x b/y.py\n--- a/x b/y.py\n+++ b/z.py\n@@ -1 +1 @@\n-a\n+b\n"
    assert chunk_paths(chunk) == ("x b/y.py", "z.py")


def test_walk_reads_a_fragment_without_headers_as_content():
    lines = [(d.kind, d.text) for d in walk_diff("-a\n+b\n--- a/x.py\n")]
    assert lines == [("-", "a"), ("+", "b"), ("header", "-- a/x.py")]


# The modules that read diffs through walk_diff


def test_drop_diff_files_goes_by_the_old_path():
    from guard.task_flow import _drop_diff_files

    untracked = "diff --git a/old.txt b/old.txt\nnew file mode 100644\n--- /dev/null\n+++ b/old.txt\n@@ -0,0 +1 @@\n+x\n"
    renamed_onto = "diff --git a/task.py b/old.txt\nrename from task.py\nrename to old.txt\n"
    assert _drop_diff_files(untracked + renamed_onto, {"old.txt"}) == renamed_onto
    assert _drop_diff_files(untracked, {"old.txt"}) == ""
    assert _drop_diff_files("# [ERROR: git failed]\n" + untracked, {"old.txt"}) == "# [ERROR: git failed]\n"


def test_removed_lines_skip_file_headers_but_keep_a_removed_sql_comment():
    diff = "diff --git a/q.sql b/q.sql\n--- a/q.sql\n+++ b/q.sql\n@@ -1,2 +1 @@\n--- keep the index\n select 1;\n"
    assert _removed_lines(diff) == ["-- keep the index"]
    gone = "diff --git a/g.sql b/g.sql\ndeleted file mode 100644\n--- a/g.sql\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n"
    assert _removed_lines(gone) == []


def test_rulebook_does_not_switch_file_on_an_added_plus_plus_line():
    real = "+++ b/Dockerfile\n@@ -0,0 +1 @@\n+FROM python\n"
    assert any(v.rule_id == "INFRA-002" for v in OCRRulebookRunner().scan_diff(real))
    fake = "+++ b/notes.md\n@@ -0,0 +1,2 @@\n+++ b/Dockerfile\n+FROM python\n"
    assert not any(v.rule_id == "INFRA-002" for v in OCRRulebookRunner().scan_diff(fake))


def test_diff_inspector_reads_a_path_holding_b_slash(tmp_path):
    diff = "diff --git a/x b/y.py b/x b/y.py\n--- a/x b/y.py\n+++ b/x b/y.py\n@@ -1 +1 @@\n-a\n+b\n"
    summary = GitDiffInspector(tmp_path).parse_diff(diff)
    assert [(f.path, f.insertions, f.deletions) for f in summary.files] == [("x b/y.py", 1, 1)]


def test_dependency_scan_does_not_switch_file_on_an_added_plus_plus_line():
    from guard.core.simplicity_engine import SimplicityEngine

    real = 'diff --git a/package.json b/package.json\n--- a/package.json\n+++ b/package.json\n@@ -1 +1,2 @@\n+  "is-odd": "^3.0.1",\n {\n'
    assert [v.rule_id for v in SimplicityEngine().scan_dependency_bloat(real)] == ["LAZY-001"]
    fake = 'diff --git a/notes.md b/notes.md\n--- a/notes.md\n+++ b/notes.md\n@@ -0,0 +1,2 @@\n+++ b/package.json\n+  "is-odd": "^3.0.1",\n'
    assert SimplicityEngine().scan_dependency_bloat(fake) == []


def test_bench_reads_whole_paths_with_spaces():
    from bench.metrics import _extract_diff_files

    diff = 'diff --git a/my file.py b/my file.py\n@@ -1 +1 @@\n-a\n+b\ndiff --git "a/caf\\303\\251.py" "b/caf\\303\\251.py"\n'
    assert _extract_diff_files(diff) == {"my file.py", "café.py"}
    assert _extract_diff_files("") == set()
