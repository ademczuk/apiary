# DEMO RECONSTRUCTION - NOT EXECUTABLE PAYLOAD
#
# Faithful shape of the malicious setup.py shipped with ctx@0.2.2 on
# PyPI in May 2022. The original payload read ~/.aws/credentials,
# ~/.docker/config.json, ~/.netrc, and any *_KEY environment variable,
# then POSTed the harvest to an attacker-controlled HTTPS endpoint.
# Every exfiltration target here is a sanitized .example.invalid
# placeholder so this file cannot do harm.
#
# Reference: https://www.bleepingcomputer.com/news/security/pypi-package-ctx-and-php-library-phpass-hijacked-to-steal-aws-keys/

from setuptools import setup

# SANITIZED placeholder. Real incident POSTed to a Heroku endpoint.
EXFIL_URL = "https://exfil-archive.example.invalid/c"

# Names the original malware scanned for. We list them so a reviewer can
# read the intent, but the reconstruction never reads any of them.
INTERESTING_FILES = (
    "~/.aws/credentials",
    "~/.docker/config.json",
    "~/.netrc",
    "~/.ssh/id_rsa",
    "~/.npmrc",
)


def _harvest_intent_only() -> dict:
    """Log the SHAPE of the harvest without actually reading any file.

    The real malware called pathlib.Path.home() / candidate, read every
    matching file as bytes, base64-encoded the contents, and bundled
    them with json.dumps(os.environ). The reconstruction stops here.
    """
    import sys
    sys.stderr.write(
        "[demo-reconstruction] would have scanned " +
        str(len(INTERESTING_FILES)) + " credential files\n"
    )
    sys.stderr.write(
        "[demo-reconstruction] would have POSTed harvest to " +
        EXFIL_URL + "\n"
    )
    return {"intent_only": True}


try:
    _harvest_intent_only()
except Exception:
    # Real malware swallowed every exception so the install completed
    # silently. Reconstruction matches that behavior.
    pass


setup(
    name="ctx",
    version="0.2.2",
    description="A tiny context utility (DEMO RECONSTRUCTION - DO NOT INSTALL)",
    py_modules=["ctx"],
    author="phantom-author",
    author_email="phantom@exfil-archive.example.invalid",
    classifiers=[
        "Development Status :: 7 - Inactive",
        "License :: OSI Approved :: MIT License",
    ],
)
