#!/usr/bin/env python3
"""Checks the documentation of the project for what can be checked cheaply.

- every relative link of a Markdown file points to a file that exists, and its anchor to a heading there;
- every document has its pair in the other language: docs/en/X.md and docs/ru/X.md, README.md and
  docs/ru/README.md (once docs/ru holds any Markdown file);
- every mermaid block parses, with the mermaid CLI through npx (skipped with --no-mermaid).

The rest, that the documents say the same as the code and as each other, is checked by hand before a commit.
Runs on the host, from anywhere in the repository; exits with 1 if anything is wrong.
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile
import unicodedata

MERMAID_CLI = "@mermaid-js/mermaid-cli@11.4.2"
LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
REFERENCE = re.compile(r"^\s*\[[^\]]+\]:\s*(\S+)", re.M)
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
FENCE = re.compile(r"^\s*(```|~~~)(.*)$")


def repository_root():
    return subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True
    ).stdout.strip()


def markdown_files(root):
    """The Markdown files of the repository, tracked or new, without the ignored and local ones."""
    out = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "*.md"],
        cwd=root, capture_output=True, text=True, check=True,
    ).stdout
    return sorted(path for path in out.splitlines() if os.path.exists(os.path.join(root, path)))


def split_fences(text):
    """The lines outside code blocks, with their numbers, and the mermaid blocks with their first line."""
    prose, mermaid = [], []
    fence, kind, block, start = None, None, [], 0
    for number, line in enumerate(text.splitlines(), 1):
        match = FENCE.match(line)
        if fence is None and match:
            fence, kind, block, start = match.group(1), match.group(2).strip(), [], number
            continue
        if fence is not None:
            if line.strip().startswith(fence):
                if kind == "mermaid":
                    mermaid.append((start, "\n".join(block)))
                fence = None
            else:
                block.append(line)
            continue
        prose.append((number, line))
    return prose, mermaid


def slug(heading):
    """The anchor GitHub gives a heading."""
    text = re.sub(r"`([^`]*)`", r"\1", heading)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = text.lower()
    kept = []
    for char in text:
        if char in " -_" or unicodedata.category(char)[0] in "LN":
            kept.append(char)
    return "".join(kept).replace(" ", "-")


def anchors(path, cache={}):
    if path not in cache:
        with open(path, encoding="utf-8") as file:
            prose, _ = split_fences(file.read())
        seen, result = {}, set()
        for _, line in prose:
            match = HEADING.match(line)
            if not match:
                continue
            base = slug(match.group(2))
            count = seen.get(base, 0)
            seen[base] = count + 1
            result.add(base if count == 0 else f"{base}-{count}")
        cache[path] = result
    return cache[path]


def check_links(root, path, prose):
    errors = []
    directory = os.path.dirname(os.path.join(root, path))
    for number, line in prose:
        line = re.sub(r"`[^`]*`", "", line)
        targets = LINK.findall(line) + REFERENCE.findall(line)
        for target in targets:
            if re.match(r"^[a-z]+:", target) or target.startswith("//"):
                continue
            file_part, _, anchor = target.partition("#")
            target_path = os.path.normpath(os.path.join(directory, file_part)) if file_part else os.path.join(root, path)
            if not os.path.exists(target_path):
                errors.append(f"{path}:{number}: no such file: {target}")
                continue
            if anchor and target_path.endswith(".md") and anchor not in anchors(target_path):
                errors.append(f"{path}:{number}: no heading for #{anchor} in {os.path.relpath(target_path, root)}")
    return errors


def check_pairs(files):
    russian = [path for path in files if path.startswith("docs/ru/") and "/archive/" not in path]
    if not russian:
        return [], "no Russian documents yet, pairs not checked"
    english = [path for path in files if path.startswith("docs/en/")]
    errors = []
    for path in english:
        if path.replace("docs/en/", "docs/ru/", 1) not in files:
            errors.append(f"{path}: no Russian version")
    for path in russian:
        name = path.replace("docs/ru/", "", 1)
        if name == "README.md":
            continue
        if f"docs/en/{name}" not in files:
            errors.append(f"{path}: no English version")
    if "README.md" in files and "docs/ru/README.md" not in files:
        errors.append("README.md: no Russian version at docs/ru/README.md")
    return errors, None


def check_mermaid(blocks):
    errors = []
    if not blocks:
        return errors
    with tempfile.TemporaryDirectory() as directory:
        for path, start, text in blocks:
            source = os.path.join(directory, "diagram.mmd")
            with open(source, "w", encoding="utf-8") as file:
                file.write(text)
            result = subprocess.run(
                ["npx", "-y", MERMAID_CLI, "-q", "-i", source, "-o", os.path.join(directory, "diagram.svg")],
                capture_output=True, text=True,
            )
            if result.returncode:
                message = (result.stderr or result.stdout).strip().splitlines()
                errors.append(f"{path}:{start}: mermaid does not parse: {' '.join(message[:3])}")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--no-mermaid", action="store_true", help="do not run the mermaid CLI")
    args = parser.parse_args()

    root = repository_root()
    files = markdown_files(root)
    errors, blocks = [], []
    for path in files:
        with open(os.path.join(root, path), encoding="utf-8") as file:
            prose, mermaid = split_fences(file.read())
        errors += check_links(root, path, prose)
        blocks += [(path, start, text) for start, text in mermaid]

    pair_errors, note = check_pairs(files)
    errors += pair_errors
    if note:
        print(f"note: {note}")
    if args.no_mermaid:
        print(f"note: {len(blocks)} mermaid blocks not checked")
    else:
        errors += check_mermaid(blocks)

    for error in errors:
        print(error)
    print(f"{len(files)} files, {len(blocks)} mermaid blocks, {len(errors)} problems")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
