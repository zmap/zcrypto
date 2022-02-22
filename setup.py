import os
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))

setup(
  name="zcrypto_schemas",
  version="0.0.1",
  description="ZSchema definitions for zcrypto's JSON output.",
  classifiers=[
    "Programming Language :: Python",
    "Natural Language :: English"
  ],
  author="ZMap Team",
  author_email="team@zmap.io",
  url="https://github.com/teamnsrg/zcrypto",
  keywords="zmap censys zcrypto internet-wide scanning",
  packages=find_packages(),
  zip_safe=False
)
