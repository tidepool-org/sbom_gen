#!/usr/bin/env python3
"""
SBOM Generator

This Python script reads all dependencies of a project and produces a
software bill-of-materials (SBOM) artifacts from them.

Copyright (c) 2020, Tidepool Project
All rights reserved.
"""
import sys
import os
import logging
import logging.config
import argparse
import subprocess
import requests
import hashlib
import uuid
import re
import json
from enum import Enum, unique
from functools import cached_property
from dotenv import load_dotenv
from typing import List

# from https://pypi.org/project/spdx-tools/
from spdx.document import Document, License, LicenseConjunction, ExtractedLicense
from spdx.version import Version
from spdx.creationinfo import Person, Organization, Tool
from spdx.review import Review
from spdx.package import Package, ExternalPackageRef
from spdx.file import File, FileType
from spdx.checksum import Algorithm
from spdx.utils import SPDXNone, NoAssert, UnKnown
from spdx.writers.tagvalue import write_document as WriteTagValue
from spdx.writers.rdf import write_document as WriteRdf
from spdx.writers.json import write_document as WriteJson
from spdx.writers.yaml import write_document as WriteYaml

VERSION = '1.0'

load_dotenv()
logging.basicConfig(format = "%(asctime)s %(levelname)s [%(module)s] %(message)s", datefmt = "%Y-%m-%dT%H:%M:%S", encoding = "utf-8", level = logging.INFO)
logger = logging.getLogger('sbom')

def exec(cmd: str, cwd: str = None) -> str:
    """
    Execute a shell command and capture stdout and stderr as string
    """
    # logger.debug(f"executing [{cmd}] in [{cwd}]")
    return subprocess.check_output(cmd, encoding = "utf-8", stderr = subprocess.STDOUT, shell = True, text = True, cwd = cwd)

class SPDX():
    """
    SPDX helper methods
    """

    @staticmethod
    def id(tag: str) -> str:
        """
        Generate a SPDX identifier "SPDXRef-{tag}"
        """
        return f"SPDXRef-{tag}"

    @staticmethod
    def hash_id(tag: str) -> str:
        """
        Generate a unique SPDX identifier "SPDXRef-{tag}" by taking the first 10 digits of a hashed tag
        """
        return SPDX.id(SPDX.sha256(tag).value[:10])

    @staticmethod
    def document_id() -> str:
        """
        Return the SPDX identifier for a document: "SPDXRef-DOCUMENT"
        """
        return SPDX.id("DOCUMENT")

    @staticmethod
    def document_namespace(name: str) -> str:
        """
        Return the SPDX document namespace for a document: "http://[CreatorWebsite]/[pathToSpdx]/[DocumentName]-[UUID]"
        """
        return f"http://tidepool.org/spdx/spdxdocs/{name}-{uuid.uuid4()}"

    @staticmethod
    def package_id(name: str) -> str:
        """
        Return the unique SPDX identifier for a package: "SPDXRef-{package_name}"
        """
        return SPDX.hash_id(name)

    @staticmethod
    def file_id(filename: str) -> str:
        """
        Return the unique SPDX identifier for a file: "SPDXRef-{filename}"
        """
        return SPDX.hash_id(filename)

    @staticmethod
    def file_type(abs_path: str) -> FileType:
        """
        Determine SPDX file type
        """
        type = exec(f"file --brief --mime-type '{abs_path}'")
        if type.startswith("text") or type.startswith("application"):
            return FileType.SOURCE
        elif type.startswith("image"):
            return FileType.BINARY
        return FileType.OTHER

    @staticmethod
    def file_checksum(abs_path: str) -> Algorithm:
        """
        Calculate the checksum (SHA1) of a file
        """
        sha1 = hashlib.sha1()
        with open(abs_path, "rb") as file:
            while True:
                chunk = file.read(32 * 1024)
                if not chunk:
                    break
                sha1.update(chunk)
        return Algorithm("SHA1", sha1.hexdigest())

    @staticmethod
    def file_copyright(abs_path: str) -> str:
        try:
            with open(abs_path, "r") as file:
                pattern = re.compile(r"\s*(Copyright.+\d+.+)\s*")
                for line in file:
                    match = pattern.match(line)
                    if match:
                        return match.group(1).strip()
        except IOError:
            return None

    @staticmethod
    def sha1(data: str) -> Algorithm:
        """
        Calculate SHA1 hash over a string
        """
        hasher = hashlib.sha1()
        hasher.update(data.encode("utf-8"))
        return Algorithm("SHA1", hasher.hexdigest())

    @staticmethod
    def sha256(data: str) -> Algorithm:
        """
        Calculate SHA256 hash over a string
        """
        hasher = hashlib.sha256()
        hasher.update(data.encode("utf-8"))
        return Algorithm("SHA256", hasher.hexdigest())

class SubModule:
    def __init__(self, source_root: str, rel_path: str, version: str, commit: str, status: str, repo_url: str):
        self.source_root = source_root
        self.rel_path = rel_path
        self.version = version
        self.commit = commit
        self.status = status
        self.repo_url = repo_url.replace("git@github.com:", "").replace("https://github.com/", "").replace(".git", "")

    @property
    def org(self) -> str:
        """
        Return the organization part of a repo name (e.g. "tidepool-org" from "tidepool-org/LoopWorkspace")
        """
        return self.repo_url.split('/')[0]

    @property
    def repo(self) -> str:
        """
        Return the repo part of a repo name (e.g. "LoopWorkspace" from "tidepool-org/LoopWorkspace")
        """
        return self.repo_url.split('/')[1]

    @property
    def name(self) -> str:
        """
        Return the name of a repo from a submodule name (e.g. "TrueTime" from "Common/TrueTime")
        """
        return os.path.basename(self.rel_path)

    @property
    def abs_path(self) -> str:
        """
        Return the absolute file path of he repo
        """
        return os.path.join(self.source_root, self.rel_path)

    @property
    def description(self) -> str:
        """
        Return the description of a repo
        """
        return self.info.get('description')

    @cached_property
    def copyright(self) -> str:
        """
        Return the copyright text of a repo
        Read the LICENSE or LICENSE.md file
        """
        logger.debug(f"scanning {self.name} for copyright text")
        for license_file in [ "LICENSE", "LICENSE.md" ]:
            match = SPDX.file_copyright(os.path.join(self.abs_path, license_file))
            if match:
                return match
        return ''

    @property
    def license(self) -> str:
        """
        Return the license of a repo
        """
        return (self.info.get('license') or { }).get('spdx_id')

    @property
    def homepage_url(self) -> str:
        """
        Return the homepage URL of a repo
        """
        return self.info.get('homepage') or self.info.get('html_url')

    @property
    def commit_url(self) -> str:
        """
        Return the commit URL of a repo
        """
        return f"{self.info.get('html_url')}/tree/{self.commit}"

    @cached_property
    def info(self, auth = None) -> dict:
        """
        Fetch the information of a repo

        Requires authentication credentials (username, personal access token) for private repos,
        and to avoid rate-limiting.
        """
        if not auth:
            auth = (os.environ.get('GITHUB_USERNAME'), os.environ.get('GITHUB_TOKEN'))
        if auth == (None, None):
            auth = None
        url = f"https://api.github.com/repos/{self.org}/{self.repo}"
        logger.debug(f"fetching repo information from {url}")
        res = requests.get(url, auth = auth)
        if res.ok:
            return res.json()
        return { }

    def __repr__(self) -> str:
        """
        Dump the details of this repo
        """
        return "\n".join([
            f"submodule: {self.name}",
            f"    path: {self.rel_path}",
            f"    description: {self.description}",
            f"    copyright: {self.copyright}",
            f"    version: {self.version}",
            f"    license: {self.license}",
            f"    commit: {self.commit}",
            f"    status: {self.status}",
            f"    homepage_url: {self.homepage_url}",
            f"    commit_url: {self.commit_url}",
        ])

    def scan(self) -> Document:
        """
        Scan the submodule to produce a SPDX document
        """
        logger.info(f"scanning {self.abs_path}")

        doc = Document(name = self.name, spdx_id = SPDX.document_id(), version = Version(1, 2))
        doc.namespace = SPDX.document_namespace(self.name)
        doc.data_license = License.from_identifier("CC0-1.0")
        doc.creation_info.add_creator(Organization("Tidepool Project", "security@tidepool.org"))
        doc.creation_info.add_creator(Tool(f"Tidepool SBOM Generator v{VERSION}"))
        doc.creation_info.set_created_now()
        doc.creation_info.comment = f"This SPDX file was generated automatically using a Python script and the 'spdx-tools' package (https://github.com/spdx/tools-python)"

        package = Package(name = self.name, spdx_id = SPDX.package_id(self.name), version = self.version, download_location = self.commit_url)
        package.description = self.description
        package.homepage = self.homepage_url
        package.supplier = NoAssert()
        package.originator = NoAssert()
        package.source_info = f"Scanned from {self.rel_path} and {self.homepage_url}"
        package.conc_lics = License.from_identifier(self.license)
        package.license_declared = License.from_identifier(self.license)
        package.cr_text = self.copyright or NoAssert()
        package.files_analyzed = True
        package.licenses_from_files = [ NoAssert() ]

        total_size = 0
        for root, dirs, files in os.walk(self.abs_path, topdown = True):
            for filename in files:
                abs_path = os.path.join(root, filename)
                rel_path = os.path.join(".", os.path.relpath(abs_path, start = self.abs_path))
                logger.debug(f"scanning {rel_path}")
                file = File(rel_path, spdx_id = SPDX.file_id(abs_path))
                file.type = SPDX.file_type(abs_path)
                file.chk_sum = SPDX.file_checksum(abs_path)
                total_size += os.path.getsize(abs_path)
                file.conc_lics = NoAssert()
                file.add_lics(NoAssert())
                if file.type == FileType.SOURCE:
                    copyright = SPDX.file_copyright(abs_path)
                    file.copyright = copyright or SPDXNone()
                else:
                    file.copyright = NoAssert()
                package.add_file(file)

        package.verif_code = package.calc_verif_code()
        package.check_sum = Algorithm("SHA1", package.verif_code)
        package.comment = f"{len(package.files)} files, {total_size} bytes"
        package.add_pkg_ext_refs(ExternalPackageRef(category = "PERSISTENT-ID", pkg_ext_ref_type = "swh", locator = f"swh:1:rev:{self.commit}", comment = "GitHub commit ID"))

        doc.package = package
        return doc

    def write(self, target_root: str) -> None:
        """
        Write the SPDX file(s) for this submodule
        """
        def __write(doc: Document, writer, filename: str, mode: str = "wt"):
            """
            Internal helper method that write a single output file of desired type
            """
            logger.info(f"writing output to {filename}")
            with open(filename, mode) as file:
                writer(doc, file)

        doc = self.scan()
        target_base = os.path.join(target_root, self.name)
        __write(doc, WriteTagValue, f"{target_base}.spdx_tv")
        __write(doc, WriteJson, f"{target_base}.json")
        __write(doc, WriteYaml, f"{target_base}.yaml")
        __write(doc, WriteRdf, f"{target_base}.spdx", "wb")

@unique
class SubModuleStatus(Enum):
    NO_INIT = "-"
    IN_SYNC = " "
    NO_SYNC = "+"
    MERGE_CONFLICTS = "U"

class SubModules():
    def __init__(self, args):
        self.source_root = args.source_root

        logger.info(f"fetching submodule status from git")
        module_statuses = exec("git submodule status", cwd = self.source_root)
        logger.debug("found submodules:")
        self.modules = { }
        for module_status in module_statuses.split("\n"):
            if module_status:
                status, commit, rel_path, version = [ module_status[:1], *module_status[1:].split(" ") ]
                url = exec(f"git config --get submodule.{rel_path}.url", cwd = self.source_root).strip()
                status = SubModuleStatus(status)
                version = version.strip("()")
                module = SubModule(self.source_root, rel_path, version, commit, status, url)
                logger.debug(module)
                self.modules[rel_path] = module

    def write(self, module: str, args):
        self.modules[module].write(args.target_root)

class VersionAction(argparse.Action):
    """
    Show version information
    """
    def __call__(self, parser, ns, values, option = None):
        print(VERSION)
        exit(1)

class HelpAction(argparse.Action):
    """
    Show argument help
    """
    def __call__(self, parser, ns, values, option = None):
        parser.print_help()
        exit(1)

class NegateAction(argparse.Action):
    """
    Creates a negated version of a command line flag: "--foo" --> "--no-foo"
    """
    def __call__(self, parser, ns, values, option = None):
        setattr(ns, self.dest, option[2:4] != 'no')

def main():
    """
    Main function
    """
    default_source_root = os.environ.get("SBOM_SOURCE_ROOT") or "~/src/tidepool/LoopWorkspace"
    default_target_root = os.environ.get("SBOM_TARGET_ROOT") or "./output"
    parser = argparse.ArgumentParser(description = 'Generate SBOM from a project folder and GitHub', add_help = False)
    parser.add_argument('--version', action = VersionAction, nargs = 0, help = 'show version information')
    parser.add_argument('-h', '--help', action = HelpAction, nargs = 0, help = 'show this help message and exit')
    parser.add_argument('--verbose', '--no-verbose', dest = 'verbose', default = False, action = NegateAction, nargs = 0, help = 'enable verbose mode (default: off)')
    parser.add_argument('--source', default = default_source_root, dest = 'source_root', action = 'store', help = f'set source folder (default: {default_source_root})')
    parser.add_argument('--target', default = default_target_root, dest = 'target_root', action = 'store', help = f'set target folder (default: {default_target_root})')
    parser.add_argument('--tag', default = '', action = 'store', help = 'set arbitrary tag for use by templates (default: none)')
    parser.add_argument('--build', default = '', action = 'store', help = 'set build number (default: none)')

    args = parser.parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    args.source_root = os.path.abspath(os.path.expanduser(args.source_root))
    args.target_root = os.path.abspath(os.path.expanduser(args.target_root))

    logger.info(f"Tidepool SBOM Generator v{VERSION}")
    modules = SubModules(args)
    modules.write("Common/TrueTime", args)
    modules.write("Common/MKRingProgressView", args)
    modules.write("Common/Minizip", args)
    modules.write("Common/SwiftCharts", args)
    logger.info("done")

if __name__ == "__main__":
    main()
