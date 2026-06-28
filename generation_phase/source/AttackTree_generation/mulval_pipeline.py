#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run MulVAL for every input case directory."
    )
    parser.add_argument(
        "mulval_dir",
        nargs="?",
        default="mulval-inputs",
        help="Directory containing MulVAL case folders.",
    )
    parser.add_argument(
        "--case",
        action="append",
        help="Specific case folder to run. May be passed multiple times.",
    )
    parser.add_argument("--timeout", type=int, default=120, help="Timeout per case in seconds.")
    parser.add_argument(
        "--runner",
        choices=["auto", "docker", "function"],
        default="auto",
        help=(
            "How to run MulVAL. 'docker' runs the container directly. "
            "'function' uses a shell function named mulval_exec. "
            "'auto' prefers Docker and falls back to the shell function."
        ),
    )
    parser.add_argument(
        "--docker-image",
        default="wilbercui/mulval",
        help="Docker image used when --runner is docker or auto.",
    )
    return parser.parse_args()


def validate_case_dir(case_dir: Path) -> None:
    if not (case_dir / "input.P").exists():
        raise FileNotFoundError(f"Missing input.P in {case_dir}")
    if not (case_dir / "rules.P").exists():
        raise FileNotFoundError(f"Missing rules.P in {case_dir}")


def run_with_docker(case_dir: Path, docker_image: str, timeout: int) -> str:
    if shutil.which("docker") is None:
        raise RuntimeError("Docker was not found on PATH.")

    command = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{case_dir.resolve()}:/graphs",
        "-w",
        "/graphs",
        docker_image,
        "graph_gen.sh",
        "/graphs/input.P",
        "-r",
        "/graphs/rules.P",
        "-v",
        "-p",
    ]
    result = subprocess.run(
        command,
        check=True,
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    return result.stdout + result.stderr


def run_with_shell_function(case_dir: Path, timeout: int) -> str:
    command = (
        'type mulval_exec >/dev/null 2>&1 && '
        f'mulval_exec "{case_dir.resolve()}" '
        "graph_gen.sh /graphs/input.P -r /graphs/rules.P -v -p"
    )
    result = subprocess.run(
        ["bash", "-ic", command],
        check=True,
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    return result.stdout + result.stderr


def mulval_exec(case_dir: Path, runner: str, docker_image: str, timeout: int) -> str:
    validate_case_dir(case_dir)

    if runner == "docker":
        return run_with_docker(case_dir, docker_image, timeout)
    if runner == "function":
        return run_with_shell_function(case_dir, timeout)

    docker_error = None
    try:
        return run_with_docker(case_dir, docker_image, timeout)
    except Exception as exc:
        docker_error = exc

    try:
        return run_with_shell_function(case_dir, timeout)
    except Exception as function_error:
        raise RuntimeError(
            "Could not run MulVAL. Docker failed and no usable mulval_exec shell "
            "function was found. Start Docker and pull the image with "
            f"`docker pull {docker_image}`, or run with `--runner function` after "
            "defining mulval_exec in your shell startup file.\n"
            f"Docker error: {docker_error}\n"
            f"Function error: {function_error}"
        ) from function_error


def main() -> None:
    args = parse_args()
    mulval_root = Path(args.mulval_dir)
    if not mulval_root.exists():
        raise FileNotFoundError(f"MulVAL input directory not found: {mulval_root}")

    case_dirs = [mulval_root / case for case in args.case] if args.case else sorted(
        path for path in mulval_root.iterdir() if path.is_dir()
    )

    for case_dir in case_dirs:
        print(f"Running MulVAL for {case_dir}")
        try:
            output = mulval_exec(case_dir, args.runner, args.docker_image, args.timeout)
        except subprocess.CalledProcessError as exc:
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
            raise RuntimeError(
                f"MulVAL failed for {case_dir} with exit code {exc.returncode}.\n"
                f"stdout:\n{stdout}\n"
                f"stderr:\n{stderr}"
            ) from exc
        if output.strip():
            print(output)


if __name__ == "__main__":
    main()
