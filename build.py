#!/usr/bin/env python3
"""
Build script for OhMyKeymint Android targets.
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import zipfile

try:
    import tomllib as toml
except ModuleNotFoundError:
    import toml


REPO_ROOT = Path(__file__).resolve().parent
TARGET_ROOT = REPO_ROOT / "target"
DEFAULT_PLATFORM = 24

ABI_TO_TARGET = {
    "arm64-v8a": "aarch64-linux-android",
    "x86_64": "x86_64-linux-android",
}

ABI_TO_MODULE_ARCHES = {
    "arm64-v8a": "arm64 arm64-v8a",
    "x86_64": "x64 x86_64",
}

BORINGSSL_BUILD_DIRS = {
    "aarch64-linux-android": Path.home() / ".cargo" / "boringssl" / "build",
    "x86_64-linux-android": Path.home() / ".cargo" / "boringssl" / "build-x86_64",
}

BINARY_SPECS = (
    {"package": None, "bin": "keymint", "output_name": "keymint"},
    {"package": "injector", "bin": "inject", "output_name": "inject"},
)

# The PIF Zygisk payload is vendored from KOWX712/PlayIntegrityFix (pinned
# submodule) and compiled from source by this script. The upstream sources
# hardcode the module id `playintegrityfix` and hardcode a module.prop CRC32
# self-check; both are rewritten for this distribution at build time.
PIF_VENDOR_DIR = REPO_ROOT / "third_party" / "PlayIntegrityFix"
PIF_CPP_SUBDIR = Path("zygisk") / "src" / "main" / "cpp"
PIF_ANDROID_API = 26
ABI_TO_NDK_TRIPLE = {
    "arm64-v8a": "aarch64-linux-android",
    "x86_64": "x86_64-linux-android",
}

# The optional Java payload is compiled to `classes.dex` by CI (see
# .github/workflows/ci.yml) because the build host has no JDK/d8. A local
# build ships the module without dex; only spoofProvider/spoofSignature need it.
PIF_CLASSES_DEX_ENV = "OMK_PIF_CLASSES_DEX"
PIF_CLASSES_DEX_DEFAULT = REPO_ROOT / "build" / "pif" / "classes.dex"

# Distribution identity for this fork. Packages are named
# `OhMyKeymint-R1-<version>-<versionCode>-<hash7>[-<abi>][-debug].zip`.
# MODULE_ID is the `id` in module.prop, which is also the runtime directory
# name under /data/adb/modules and therefore part of the payload's file paths.
MODULE_NAME = "OhMyKeymint-R1"
MODULE_ID = "oh_my_keymint"
MODULE_VERSION_CODE = "102"

REQUIRED_TEMPLATE_FILES = (
    "customize.sh",
    "daemon",
    "daemon-injector",
    "injector.toml",
    "module.prop",
    "uninstall.sh",
    "post-fs-data.sh",
    "service.sh",
    "status.sh",
    "verify.sh",
    "webroot",
)

MODULE_TEXT_FILES = (
    "AOSP.Apache-license-2.0.txt",
    "LICENSE-2",
    "LICENSE.md",
    "README.md",
    "THIRD_PARTY_LICENSES/Tricky-Addon-Update-Target-List.txt",
    "THIRD_PARTY_LICENSES/zygisk-api-0BSD.txt",
    "THIRD_PARTY_LICENSES/PlayIntegrityFix-GPL-3.0.txt",
    "customize.sh",
    "daemon",
    "daemon-injector",
    "injector.toml",
    "google_attestation_status.json",
    "module.prop",
    "uninstall.sh",
    "post-fs-data.sh",
    "sepolicy.rule",
    "service.sh",
    "status.sh",
    "verify.sh",
    "META-INF/com/google/android/update-binary",
    "META-INF/com/google/android/updater-script",
)


def run(cmd: list[str], *, env: dict[str, str] | None = None) -> None:
    print("+", " ".join(cmd))
    result = subprocess.run(cmd, cwd=REPO_ROOT, env=env)
    if result.returncode != 0:
        raise RuntimeError(f"command failed: {' '.join(cmd)}")


def get_version_from_cargo_toml() -> str:
    with (REPO_ROOT / "Cargo.toml").open("r", encoding="utf-8") as fh:
        cargo_toml = toml.loads(fh.read())
    return cargo_toml["package"]["version"]


def get_git_commit_hash() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError("Failed to get git commit hash")
    return result.stdout.strip()[-7:]


def cargo_context_for_target(target: str) -> tuple[dict[str, str], str]:
    env = os.environ.copy()
    configured_dir = env.get("BORINGSSL_BUILD_DIR")
    if configured_dir:
        build_dir = Path(configured_dir).expanduser()
        if not build_dir.is_absolute():
            build_dir = REPO_ROOT / build_dir
    else:
        build_dir = BORINGSSL_BUILD_DIRS.get(target)
        if build_dir is None:
            raise ValueError(f"No default BoringSSL build directory for target {target}")

    build_dir = build_dir.resolve()
    source_dir = build_dir.parent
    bssl_sys_dir = source_dir / "rust" / "bssl-sys"
    required_paths = (
        bssl_sys_dir / "Cargo.toml",
        build_dir / "libcrypto.a",
        build_dir / "libssl.a",
        build_dir / "rust" / "bssl-sys" / "librust_wrapper.a",
        build_dir / "rust" / "bssl-sys" / f"wrapper_{target}.rs",
    )
    missing = [path for path in required_paths if not path.is_file()]
    if missing:
        missing_text = ", ".join(os.fspath(path) for path in missing)
        raise FileNotFoundError(
            f"BoringSSL is not built for {target}; missing: {missing_text}. "
            f"Build it with -DRUST_BINDINGS={target}, or set BORINGSSL_BUILD_DIR "
            "to the matching build directory."
        )

    env["BORINGSSL_BUILD_DIR"] = os.fspath(build_dir)
    bssl_sys_path = json.dumps(bssl_sys_dir.as_posix())
    cargo_patch = f"patch.crates-io.bssl-sys.path={bssl_sys_path}"
    return env, cargo_patch


def build_binary(
    *,
    abi: str,
    target: str,
    release: bool,
    package: str | None,
    bin_name: str,
) -> Path:
    build_type = "release" if release else "debug"
    print(f"Building {bin_name} for {abi} ({target}, {build_type})...")

    env, cargo_patch = cargo_context_for_target(target)
    cmd = ["cargo", "--config", cargo_patch, "build", "--target", target]
    if package:
        cmd.extend(["-p", package, "--bin", bin_name])
    else:
        cmd.extend(["--bin", bin_name])
    if release:
        cmd.append("--release")

    run(cmd, env=env)

    binary_path = TARGET_ROOT / target / build_type / bin_name
    if not binary_path.exists():
        raise FileNotFoundError(f"Built binary not found at {binary_path}")
    return binary_path


def copy_binary(binary: Path, output_name: str, abi: str, stage_dir: Path) -> None:
    dest_dir = stage_dir / "libs" / abi
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_path = dest_dir / output_name
    shutil.copy2(binary, dest_path)
    print(f"Copied {binary} to {dest_path}")


def resolve_ndk_root() -> Path:
    for name in ("ANDROID_NDK_ROOT", "ANDROID_NDK_HOME"):
        value = os.environ.get(name)
        if value and Path(value).is_dir():
            return Path(value)

    # scripts/setup_cargo_config.py records the NDK root inside .cargo/config.toml.
    cargo_config = REPO_ROOT / ".cargo" / "config.toml"
    if cargo_config.is_file():
        for line in cargo_config.read_text(encoding="utf-8").splitlines():
            if line.strip().startswith("ANDROID_NDK_ROOT"):
                match = re.search(r'value\s*=\s*"([^"]+)"', line)
                if match and Path(match.group(1)).is_dir():
                    return Path(match.group(1))

    sdk_root = os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME")
    if sdk_root:
        ndk_dir = Path(sdk_root) / "ndk"
        if ndk_dir.is_dir():
            versions = sorted((path for path in ndk_dir.iterdir() if path.is_dir()), reverse=True)
            if versions:
                return versions[0]

    raise FileNotFoundError(
        "Android NDK not found; set ANDROID_NDK_ROOT/ANDROID_NDK_HOME or install an NDK"
    )


def detect_ndk_host_tag(ndk_root: Path) -> str:
    prebuilt_dir = ndk_root / "toolchains" / "llvm" / "prebuilt"
    candidates = sorted(path.name for path in prebuilt_dir.iterdir() if path.is_dir())
    if not candidates:
        raise FileNotFoundError(f"NDK has no prebuilt toolchain: {prebuilt_dir}")
    for preferred in ("linux-x86_64", "darwin-x86_64", "darwin-arm64"):
        if preferred in candidates:
            return preferred
    return candidates[0]


def build_pif_payload(*, abi: str, release: bool) -> Path:
    if not PIF_VENDOR_DIR.is_dir():
        raise FileNotFoundError(
            f"Vendored PIF sources not found at {PIF_VENDOR_DIR}; "
            "run `git submodule update --init --recursive`"
        )

    ndk_root = resolve_ndk_root()
    host_tag = detect_ndk_host_tag(ndk_root)
    triple = ABI_TO_NDK_TRIPLE[abi]
    clangxx = (
        ndk_root
        / "toolchains"
        / "llvm"
        / "prebuilt"
        / host_tag
        / "bin"
        / f"{triple}{PIF_ANDROID_API}-clang++"
    )
    if not clangxx.is_file():
        raise FileNotFoundError(f"NDK C++ compiler not found: {clangxx}")

    cpp_src = PIF_VENDOR_DIR / PIF_CPP_SUBDIR
    module_dir = f"/data/adb/modules/{MODULE_ID}"

    build_dir = TARGET_ROOT / "temp" / f"pif-{abi}"
    if build_dir.exists():
        shutil.rmtree(build_dir)
    (build_dir / "local_cxa_atexit_finalize_impl").mkdir(parents=True)

    print(f"Building PIF Zygisk payload for {abi} from vendored sources...")
    for name in (
        "zygisk.cpp",
        "zygisk.hpp",
        "pif_config.cpp",
        "pif_config.hpp",
        "property_virtualizer.cpp",
        "property_virtualizer.hpp",
    ):
        shutil.copy2(cpp_src / name, build_dir / name)
    shutil.copy2(
        cpp_src / "local_cxa_atexit_finalize_impl" / "atexit.cpp",
        build_dir / "local_cxa_atexit_finalize_impl" / "atexit.cpp",
    )

    zygisk_source = (build_dir / "zygisk.cpp").read_text(encoding="utf-8")
    zygisk_source = zygisk_source.replace(
        "/data/adb/modules/playintegrityfix/", f"{module_dir}/"
    )
    # OMK's status.sh rewrites the module.prop description at runtime, so the
    # upstream build-time CRC32 self-check can never match. Install-time file
    # hashes already protect the package, so the self-check is bypassed.
    zygisk_source = zygisk_source.replace(
        f'const bool update = access("{module_dir}/update", F_OK) == 0;',
        "const bool update = true;",
    )
    zygisk_source = zygisk_source.replace('"PIF"', '"OhMyKeymint-PIF"')
    write_text_lf(build_dir / "zygisk.cpp", zygisk_source)

    # verifyModule still references this macro; provide a stub because the
    # self-check is bypassed above.
    write_text_lf(
        build_dir / "checksum.h",
        '#pragma once\n#define MODULE_PROP_CHECKSUM_HEX "0"\n',
    )

    output = build_dir / "libzygisk.so"
    sources = [
        build_dir / "zygisk.cpp",
        build_dir / "pif_config.cpp",
        build_dir / "property_virtualizer.cpp",
        build_dir / "local_cxa_atexit_finalize_impl" / "atexit.cpp",
    ]
    cmd = [
        os.fspath(clangxx),
        "-std=c++20",
        "-O2",
        "-fPIC",
        "-shared",
        "-fno-exceptions",
        "-fno-rtti",
        "-fvisibility=hidden",
        "-fvisibility-inlines-hidden",
        "-ffunction-sections",
        "-fdata-sections",
        "-w",
        "-static-libstdc++",
        "-o",
        os.fspath(output),
        *(os.fspath(path) for path in sources),
        "-llog",
    ]
    run(cmd)
    if not output.exists():
        raise FileNotFoundError(f"PIF payload not produced at {output}")
    return output


def copy_classes_dex(stage_dir: Path) -> None:
    candidates = []
    env_path = os.environ.get(PIF_CLASSES_DEX_ENV)
    if env_path:
        candidates.append(Path(env_path))
    candidates.append(PIF_CLASSES_DEX_DEFAULT)

    for candidate in candidates:
        if candidate.is_file():
            destination = stage_dir / "classes.dex"
            shutil.copy2(candidate, destination)
            print(f"Copied {candidate} to {destination}")
            return
    print(
        "WARNING: classes.dex not found; spoofProvider/spoofSignature will be "
        "unavailable until a package with the Java payload is installed"
    )


def copy_zygisk_payload(library: Path, abi: str, stage_dir: Path) -> None:
    payload_dir = stage_dir / "zygisk"
    payload_dir.mkdir(parents=True, exist_ok=True)
    destination = payload_dir / f"{abi}.so"
    shutil.copy2(library, destination)
    print(f"Copied {library} to {destination}")


def copy_template_files(stage_dir: Path) -> None:
    template_dir = REPO_ROOT / "template"
    if not template_dir.exists():
        raise FileNotFoundError("Template directory not found")

    missing = [name for name in REQUIRED_TEMPLATE_FILES if not (template_dir / name).exists()]
    if missing:
        raise FileNotFoundError(f"Template is missing required file(s): {', '.join(missing)}")

    print(f"Copying template files into {stage_dir}...")
    for item in template_dir.iterdir():
        dst = stage_dir / item.name
        if item.is_dir():
            shutil.copytree(item, dst, dirs_exist_ok=True)
        else:
            shutil.copy2(item, dst)


def copy_project_documents(stage_dir: Path) -> None:
    documents = (
        (REPO_ROOT / "README.md", stage_dir / "README.md"),
        (REPO_ROOT / "LICENSE.md", stage_dir / "LICENSE.md"),
        (REPO_ROOT / "LICENSE-2", stage_dir / "LICENSE-2"),
        (
            REPO_ROOT / "webui" / "LICENSE.upstream",
            stage_dir / "THIRD_PARTY_LICENSES" / "Tricky-Addon-Update-Target-List.txt",
        ),
        (
            REPO_ROOT / "third_party" / "zygisk-api" / "LICENSE",
            stage_dir / "THIRD_PARTY_LICENSES" / "zygisk-api-0BSD.txt",
        ),
        (
            REPO_ROOT / "third_party" / "PlayIntegrityFix" / "LICENSE",
            stage_dir / "THIRD_PARTY_LICENSES" / "PlayIntegrityFix-GPL-3.0.txt",
        ),
    )
    for source, destination in documents:
        if not source.is_file():
            raise FileNotFoundError(f"Required license file not found: {source}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def write_text_lf(path: Path, content: str) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)


def normalize_module_text_files(stage_dir: Path) -> None:
    for relative_path in MODULE_TEXT_FILES:
        path = stage_dir / relative_path
        if not path.exists():
            continue
        content = path.read_text(encoding="utf-8")
        content = content.replace("\r\n", "\n").replace("\r", "\n")
        write_text_lf(path, content)


def configure_template_for_abi(stage_dir: Path, abi: str) -> None:
    customize_path = stage_dir / "customize.sh"
    if not customize_path.exists():
        raise FileNotFoundError(f"customize.sh not found at {customize_path}")

    supported_arch = ABI_TO_MODULE_ARCHES[abi]
    content = customize_path.read_text(encoding="utf-8")
    content = content.replace('SUPPORTED_ABIS="arm64 x64"', f'SUPPORTED_ABIS="{supported_arch}"')
    write_text_lf(customize_path, content)
    print(f"Updated customize.sh supported ABI to {supported_arch}")


def build_version_name(version: str, git_hash: str, release: bool) -> str:
    suffix = "" if release else "-debug"
    return f"{version}-{MODULE_VERSION_CODE}-{git_hash}{suffix}"


def modify_module_prop(
    stage_dir: Path,
    version: str,
    git_hash: str,
    release: bool,
) -> None:
    module_prop_path = stage_dir / "module.prop"
    if not module_prop_path.exists():
        raise FileNotFoundError(f"module.prop not found at {module_prop_path}")

    version_name = build_version_name(version, git_hash, release)
    content = module_prop_path.read_text(encoding="utf-8")
    content = content.replace("${versionName}", version_name)
    content = content.replace("${versionCode}", MODULE_VERSION_CODE)
    write_text_lf(module_prop_path, content)
    print(
        f"Updated module.prop: versionName={version_name}, "
        f"versionCode={MODULE_VERSION_CODE}"
    )


def generate_hash_for_file(file_path: Path) -> None:
    digest = hashlib.sha256()
    with file_path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)

    hash_path = file_path.with_name(f"{file_path.name}.sha256")
    hash_path.write_text(digest.hexdigest(), encoding="utf-8")
    print(f"Created hash file: {hash_path}")


def generate_hash_files(stage_dir: Path) -> None:
    print(f"Generating SHA256 hash files under {stage_dir}...")
    for item in stage_dir.rglob("*"):
        if item.is_file() and not item.name.endswith(".sha256"):
            generate_hash_for_file(item)


def generate_webroot_manifest(stage_dir: Path) -> None:
    webroot = stage_dir / "webroot"
    required = (webroot / "index.html", webroot / "config.json")
    missing = [path.relative_to(stage_dir).as_posix() for path in required if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"WebUI build is incomplete; missing: {', '.join(missing)}")

    assets = sorted(
        path.relative_to(stage_dir).as_posix()
        for path in webroot.rglob("*")
        if path.is_file() and not path.name.endswith(".sha256")
    )
    if not assets:
        raise FileNotFoundError("WebUI build did not produce any files")
    write_text_lf(stage_dir / "webroot.manifest", "\n".join(assets) + "\n")
    print(f"Created WebUI manifest with {len(assets)} asset(s)")


def delete_old_zips(release: bool, selected_abis: list[str], version: str) -> None:
    build_type = "release" if release else "debug"
    debug_suffix = "" if release else "-debug"
    old_zips: set[str] = set()
    for abi in selected_abis:
        # Remove packages produced by earlier naming schemes as well as
        # packages for this version produced by an earlier build (useful when
        # the working tree hash changes between builds).
        for legacy in (
            f"OhMyKeymint-{build_type}-{abi}-*.zip",
            f"OhMyKeymint-{version}-*-{abi}-{build_type}.zip",
            f"OhMyKeymint-{version}-*-{build_type}.zip",
        ):
            old_zips.update(glob.glob(os.fspath(TARGET_ROOT / legacy)))

        if abi == "arm64-v8a":
            new_pattern = TARGET_ROOT / (
                f"{MODULE_NAME}-{version}-{MODULE_VERSION_CODE}-*{debug_suffix}.zip"
            )
            # The arm64 package intentionally omits its ABI in the filename;
            # retain a separately built x86_64 package with the same version.
            old_zips.update(
                path
                for path in glob.glob(os.fspath(new_pattern))
                if "-x86_64" not in Path(path).name
            )
        else:
            new_pattern = TARGET_ROOT / (
                f"{MODULE_NAME}-{version}-{MODULE_VERSION_CODE}-*-{abi}{debug_suffix}.zip"
            )
            old_zips.update(glob.glob(os.fspath(new_pattern)))
    if not old_zips:
        print(f"No old zip files found for build type {build_type} and ABIs {selected_abis}")
        return

    print(f"Found {len(old_zips)} old zip file(s) to delete:")
    for old_zip in old_zips:
        print(f"  Deleting: {old_zip}")
        os.remove(old_zip)


def create_zip_package(
    *,
    stage_dir: Path,
    version: str,
    git_hash: str,
    abi: str,
    release: bool,
) -> Path:
    # The default arm64 package is `MODULE_NAME-version-versionCode-hash7`; an
    # explicit x86_64 build adds an ABI discriminator so separate ABI builds
    # cannot overwrite one another, and debug builds add a `-debug` suffix.
    abi_suffix = f"-{abi}" if abi != "arm64-v8a" else ""
    debug_suffix = "" if release else "-debug"
    zip_name = (
        f"{MODULE_NAME}-{version}-{MODULE_VERSION_CODE}-{git_hash}"
        f"{abi_suffix}{debug_suffix}.zip"
    )
    zip_path = TARGET_ROOT / zip_name
    print(f"Creating zip package: {zip_path}")

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zipf:
        for root, _, files in os.walk(stage_dir):
            for file_name in files:
                file_path = Path(root) / file_name
                arcname = file_path.relative_to(stage_dir)
                zipf.write(file_path, arcname)

    return zip_path


def build_package_for_abi(
    *,
    abi: str,
    release: bool,
    platform: int,
    version: str,
    git_hash: str,
) -> Path:
    target = ABI_TO_TARGET[abi]
    stage_dir = TARGET_ROOT / "temp" / abi
    # Kept for compatibility with old invocations; plain Cargo uses .cargo/config.toml.
    _ = platform
    if stage_dir.exists():
        shutil.rmtree(stage_dir)
    stage_dir.mkdir(parents=True, exist_ok=True)

    try:
        built_binaries: dict[str, Path] = {}
        for spec in BINARY_SPECS:
            built_binaries[spec["output_name"]] = build_binary(
                abi=abi,
                target=target,
                release=release,
                package=spec["package"],
                bin_name=spec["bin"],
            )
        pif_payload = build_pif_payload(abi=abi, release=release)

        copy_template_files(stage_dir)
        copy_project_documents(stage_dir)
        normalize_module_text_files(stage_dir)
        configure_template_for_abi(stage_dir, abi)
        for spec in BINARY_SPECS:
            copy_binary(
                built_binaries[spec["output_name"]],
                spec["output_name"],
                abi,
                stage_dir,
            )
        copy_zygisk_payload(pif_payload, abi, stage_dir)
        copy_classes_dex(stage_dir)

        modify_module_prop(stage_dir, version, git_hash, release)
        normalize_module_text_files(stage_dir)
        generate_webroot_manifest(stage_dir)
        generate_hash_files(stage_dir)
        return create_zip_package(
            stage_dir=stage_dir,
            version=version,
            git_hash=git_hash,
            abi=abi,
            release=release,
        )
    finally:
        if stage_dir.exists():
            shutil.rmtree(stage_dir)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build OhMyKeymint Magisk packages for Android")
    parser.add_argument("--release", action="store_true", help="Build in release mode")
    parser.add_argument("--debug", action="store_true", help="Build in debug mode (default)")
    parser.add_argument(
        "--abi",
        dest="abis",
        action="append",
        choices=sorted(ABI_TO_TARGET),
        help="Build only the selected Android ABI(s). Defaults to arm64-v8a.",
    )
    parser.add_argument(
        "--platform",
        type=int,
        default=DEFAULT_PLATFORM,
        help=(
            "Compatibility option; ordinary cargo builds use .cargo/config.toml "
            f"for the Android API/linker (default: {DEFAULT_PLATFORM})"
        ),
    )
    args = parser.parse_args()

    version = get_version_from_cargo_toml()
    git_hash = get_git_commit_hash()
    selected_abis = args.abis or ["arm64-v8a"]

    print(f"Building {MODULE_NAME} version {version} (hash {git_hash})")
    print(f"Build mode: {'Release' if args.release else 'Debug'}")
    print(f"Target ABIs: {', '.join(selected_abis)}")

    delete_old_zips(args.release, selected_abis, version)
    built_packages = []
    for abi in selected_abis:
        built_packages.append(
            build_package_for_abi(
                abi=abi,
                release=args.release,
                platform=args.platform,
                version=version,
                git_hash=git_hash,
            )
        )

    print("Build completed successfully!")
    for zip_path in built_packages:
        print(f"Output: {zip_path}")


if __name__ == "__main__":
    main()
