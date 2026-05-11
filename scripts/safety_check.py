from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent

EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "__pycache__",
    "data",
    ".pytest_cache",
}

EXCLUDED_FILES = {
    ".env",
}

SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"OPENAI_API_KEY\s*=\s*sk-[A-Za-z0-9_\-]{20,}"),
]

issues = []

for path in ROOT.rglob("*"):
    if path.is_dir():
        continue

    parts = set(path.parts)

    if parts & EXCLUDED_DIRS:
        continue

    if path.name in EXCLUDED_FILES:
        continue

    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        continue

    for pattern in SECRET_PATTERNS:
        if pattern.search(text):
            issues.append(str(path.relative_to(ROOT)))

env_example = ROOT / ".env.example"
if env_example.exists():
    text = env_example.read_text(encoding="utf-8")
    if "sk-" in text:
        issues.append(".env.example contains what looks like a real key")

if issues:
    print("Potential secret exposure found:")
    for issue in issues:
        print(f"- {issue}")
    raise SystemExit(1)

print("Safety check passed. No obvious API keys found in shareable files.")
