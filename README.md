# README

This repo contains a Python script that can generate SBOM files for dependencies.
This is primarily useful for the Tidepool Loop project, which uses a handful of open-source projects that are not available via a public package manager.

## Installation

This tool uses some features available in Python 3.8 or later.

```shell
$ git clone https://github.com/tidepool-org/sbom_gen.git
$ cd sbom_gen
$ pip3 install -r requirements.txt
```

## Usage

This tool uses environment variables `GITHUB_USERNAME`, `GITHUB_TOKEN` to configure the GitHub API access. You can either set the variables in shell, or add them to the local `.env` file in the same folder as the tool. Do not add credentials to this repository.

Go to [GitHub](https://github.com) to create a new Personal Access Token (PAT).

This tool can also use environment variable `SBOM_SOURCE_ROOT` as the default source folder to scan.

```shell
$ git clone https://github.com/tidepool-org/sbom_gen.git
$ cd sbom_gen
$ export GITHUB_USERNAME={username}
$ export GITHUB_TOKEN={token}
$ ./sbom_gen.py --help
usage: sbom_gen.py [--version] [-h] [--verbose] [--source SOURCE_ROOT] [--target TARGET_ROOT] [--tag TAG] [--build BUILD]

Generate SBOM from a project folder and GitHub

optional arguments:
  --version             show version information
  -h, --help            show this help message and exit
  --verbose, --no-verbose
                        enable verbose mode (default: off)
  --source SOURCE_ROOT  set source folder (default: ~/src/tidepool/LoopWorkspace)
  --target TARGET_ROOT  set target folder (default: ./output)
  --tag TAG             set arbitrary tag for use by templates (default: none)
  --build BUILD         set build number (default: none)
```
