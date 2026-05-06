alias r := run
alias c := clean

python_version_requirement := ">=3.10.0"

python_command := if shell("which python3") != "" { shell("which python3") } else if shell("which python") != "" { shell("which python") } else { "echo" }
python_version := shell(python_command + ' -c "import sys; print(sys.version.split()[0]); sys.exit(0)"')

default:
    {{ just_executable() }} --choose

[arg("verbose", long="verbose", short="v", value="x", help="Shows every command ran (Makefile like)")]
run verbose="":
    #!/usr/bin/env bash

    set -eu{{ verbose }}o pipefail

    if [ ! -d .venv ]; then
        {{ just_executable() }} requirements {{ if verbose == "x" { "-v" } else { "" } }}
    fi

    source .venv/bin/activate

    python run.py

[arg("verbose", long="verbose", short="v", value="x", help="Shows every command ran (Makefile like)")]
clean verbose="":
    #!/usr/bin/env bash

    set -eu{{ verbose }}o pipefail

    rm -rf .venv

venv:
    #!/usr/bin/env bash

    set -euo pipefail

    if [[ "{{ python_command }}" == "echo" ]]; then
        (
            echo "{{ style("error") }}error{{ NORMAL }}: no valid python command found"
            echo "       tried python3 and python"
            echo "       both are not found"
            echo "       please install one of em"
        ) >&2
        exit 1
    fi

    if [[ "{{ semver_matches(python_version, python_version_requirement) }}" == "false" ]]; then
        (
            echo "{{ style("error") }}error{{ NORMAL }}: python version is invalid"
            echo "       expected semver {{ style("warning") }}{{ python_version_requirement }}{{ NORMAL }} but got version {{ style("warning") }}{{ python_version }}{{ NORMAL }}"
        ) >&2
        exit 1
    fi

    if [ ! -d .venv ]; then
        {{ python_command }} -m venv .venv
    fi

[arg("verbose", long="verbose", short="v", value="x", help="Shows every command ran (Makefile like)")]
requirements verbose="": venv
    #!/usr/bin/env bash

    set -eu{{ verbose }}o pipefail

    source .venv/bin/activate

    pip install -r requirements.txt
