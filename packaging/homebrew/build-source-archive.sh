#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
LC_ALL=C
export LC_ALL
umask 077

# A source signature must come from the named private-key file, never from an
# ambient agent or graphical askpass program. An encrypted key may still prompt
# on the process's controlling terminal; with no controlling terminal the
# selected /dev/null input makes validation fail closed.
unset SSH_AUTH_SOCK SSH_AGENT_PID SSH_ASKPASS SSH_ASKPASS_REQUIRE DISPLAY WAYLAND_DISPLAY

key_prompt_input=/dev/null
if /usr/bin/tty 2>/dev/null </dev/tty >/dev/null; then
  key_prompt_input=/dev/tty
fi

fail() {
  printf 'build-source-archive: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
usage: build-source-archive.sh \
  --source ABSOLUTE_CLEAN_GIT_ROOT \
  --version SAFE_VERSION \
  --commit 40_OR_64_LOWERCASE_HEX \
  --signing-key ABSOLUTE_ED25519_SSH_PRIVATE_KEY \
  --allowed-signers ABSOLUTE_FILE \
  --signer SAFE_IDENTITY \
  --output ABSOLUTE_NEW_TAR_GZ

Creates a Git archive augmented with a complete signed Go-build manifest.
The SSH signature uses the fixed owntransit-source-v1 namespace. No Apple
credential and no network access are required.
EOF
}

source_root=
version=
commit=
signing_key=
allowed_signers=
signer=
output=
while test "$#" -gt 0; do
  case "$1" in
    --source|--version|--commit|--signing-key|--allowed-signers|--signer|--output)
      test "$#" -ge 2 || fail "$1 requires a value"
      option=$1
      value=$2
      shift 2
      case "$option" in
        --source) source_root=$value ;;
        --version) version=$value ;;
        --commit) commit=$value ;;
        --signing-key) signing_key=$value ;;
        --allowed-signers) allowed_signers=$value ;;
        --signer) signer=$value ;;
        --output) output=$value ;;
      esac
      ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument $1" ;;
  esac
done

case "$version" in
  ''|*[!A-Za-z0-9._+-]*) fail "version contains an unsafe character" ;;
esac
case "$version" in [A-Za-z0-9]*) ;; *) fail "version must begin with an alphanumeric character" ;; esac
test "${#version}" -le 128 || fail "version is too long"
case "$commit" in ''|*[!0-9a-f]*) fail "commit must be lowercase hexadecimal" ;; esac
case "${#commit}" in 40|64) ;; *) fail "commit must contain 40 or 64 hexadecimal characters" ;; esac
case "$signer" in ''|*[!A-Za-z0-9._@+-]*) fail "signer is not a safe identity" ;; esac
test "$signer" = owntransit-source || fail "source signer identity must be exactly owntransit-source"

canonical_directory() {
  directory=$1
  label=$2
  case "$directory" in /*) ;; *) fail "$label path must be absolute" ;; esac
  test -d "$directory" && test ! -L "$directory" || fail "$label must be a regular non-symlink directory"
  resolved=$(CDPATH= cd -P -- "$directory" && pwd) || fail "cannot resolve $label"
  test "$resolved" = "$directory" || fail "$label path must be canonical"
}

canonical_file() {
  file=$1
  label=$2
  case "$file" in /*) ;; *) fail "$label path must be absolute" ;; esac
  test -f "$file" && test ! -L "$file" || fail "$label must be a regular non-symlink file"
  resolved_parent=$(CDPATH= cd -P -- "$(dirname "$file")" && pwd) || fail "cannot resolve $label parent"
  test "$resolved_parent/$(basename "$file")" = "$file" || fail "$label path must be canonical"
}

path_is_within_tree() {
  candidate_path=$1
  tree_root=$2
  test "$tree_root" = / && return 0
  case "$candidate_path" in
    "$tree_root"/*) return 0 ;;
  esac
  return 1
}

require_key_outside_tree() {
  tree_root=$1
  tree_label=$2
  if path_is_within_tree "$signing_key" "$tree_root"; then
    fail "signing key must be outside the $tree_label tree"
  fi
}

darwin_mode() {
  darwin_mode_raw=$(stat -f %p -- "$1") || return 1
  case "$darwin_mode_raw" in ''|*[!0-7]*) return 1 ;; esac
  printf '%o\n' "$((0$darwin_mode_raw & 07777))"
}

file_mode() {
  if test "$(uname -s)" = Darwin; then
    darwin_mode "$1"
  else
    stat -c '%a' -- "$1"
  fi
}

require_darwin_protected_key_chain() {
  expected_uid=$1
  protected_path=$signing_key
  key_entry=1
  while :; do
    protected_kind=$(stat -f %HT -- "$protected_path") || fail "cannot stat protected key path: $protected_path"
    if test "$key_entry" -eq 1; then
      test "$protected_kind" = "Regular File" || fail "signing key must be an actual regular file"
    else
      test "$protected_kind" = Directory || fail "protected key ancestor is not a directory: $protected_path"
    fi

    protected_owner=$(stat -f %u -- "$protected_path") || fail "cannot read protected key owner: $protected_path"
    case "$protected_owner" in ''|*[!0-9]*) fail "protected key owner is invalid: $protected_path" ;; esac
    if test "$key_entry" -eq 1; then
      test "$protected_owner" -eq "$expected_uid" || fail "signing key must be owned by the current effective UID"
    else
      test "$protected_owner" -eq 0 || test "$protected_owner" -eq "$expected_uid" ||
        fail "protected key ancestor must be owned by root or the current effective UID: $protected_path"
    fi

    acl_listing=$(ls -lde -- "$protected_path") || fail "cannot inspect protected key ACL: $protected_path"
    acl_lines=$(printf '%s\n' "$acl_listing" | wc -l | tr -d '[:space:]')
    test "$acl_lines" -eq 1 || {
      if test "$key_entry" -eq 1; then
        fail "signing key has an extended ACL"
      fi
      fail "protected key ancestor has an extended ACL: $protected_path"
    }

    if test "$key_entry" -ne 1; then
      protected_mode=$(darwin_mode "$protected_path") || fail "cannot read protected key mode: $protected_path"
      case "$protected_mode" in
        [0-7][0-7][0-7]) ;;
        *) fail "protected key ancestor has special or invalid mode bits: $protected_path" ;;
      esac
      protected_permissions=$((0$protected_mode))
      test $((protected_permissions & 022)) -eq 0 ||
        fail "protected key ancestor is group- or world-writable: $protected_path"
    fi

    test "$protected_path" = / && break
    protected_path=$(dirname -- "$protected_path")
    key_entry=0
  done
}

validate_signing_key() {
  expected_uid=$(id -u) || fail "cannot determine current effective UID"
  case "$expected_uid" in ''|*[!0-9]*) fail "current effective UID is invalid" ;; esac

  if test "$(uname -s)" = Darwin; then
    key_kind=$(stat -f %HT -- "$signing_key") || fail "cannot read signing key type"
    key_owner=$(stat -f %u -- "$signing_key") || fail "cannot read signing key owner"
    key_links=$(stat -f %l -- "$signing_key") || fail "cannot read signing key link count"
    key_mode=$(darwin_mode "$signing_key") || fail "cannot read signing key mode"
    key_metadata="$key_kind|$key_owner|$key_links|$key_mode"
  else
    key_metadata=$(stat -c '%F|%u|%h|%a' -- "$signing_key") || fail "cannot stat signing key"
  fi
  key_kind=${key_metadata%%|*}
  key_metadata_rest=${key_metadata#*|}
  key_owner=${key_metadata_rest%%|*}
  key_metadata_rest=${key_metadata_rest#*|}
  key_links=${key_metadata_rest%%|*}
  key_mode=${key_metadata_rest#*|}

  case "$key_owner" in ''|*[!0-9]*) fail "signing key owner is invalid" ;; esac
  case "$key_links" in ''|*[!0-9]*) fail "signing key link count is invalid" ;; esac
  if test "$(uname -s)" = Darwin; then
    test "$key_kind" = "Regular File" || fail "signing key must be an actual regular file"
  else
    test "$key_kind" = "regular file" || fail "signing key must be an actual regular file"
  fi
  test "$key_owner" -eq "$expected_uid" || fail "signing key must be owned by the current effective UID"
  test "$key_links" -eq 1 || fail "signing key must have exactly one hard link"
  case "$key_mode" in
    400|600) ;;
    *) fail "signing key mode must be 0400 or 0600" ;;
  esac

  if test "$(uname -s)" = Darwin; then
    require_darwin_protected_key_chain "$expected_uid"
  fi

  command -v ssh-keygen >/dev/null 2>&1 || fail "ssh-keygen with SSHSIG support is required"
  if ! private_public=$(ssh-keygen -y -f "$signing_key" <"$key_prompt_input"); then
    fail "signing key is not a readable OpenSSH private key (an encrypted key requires a controlling terminal)"
  fi
  test "$(printf '%s\n' "$private_public" | wc -l | tr -d '[:space:]')" -eq 1 ||
    fail "signing key produced a malformed public key"
  private_key_type=$(printf '%s\n' "$private_public" | awk '{print $1}')
  private_key_fields=$(printf '%s\n' "$private_public" | awk '{print NF}')
  test "$private_key_fields" -ge 2 && test "$private_key_type" = ssh-ed25519 ||
    fail "signing key must be an Ed25519 private key"
  private_public=
}

canonical_directory "$source_root" source
canonical_file "$signing_key" signing-key
canonical_file "$allowed_signers" allowed-signers

case "$output" in /*) ;; *) fail "output path must be absolute" ;; esac
test ! -e "$output" && test ! -L "$output" || fail "output already exists"
output_parent=$(CDPATH= cd -P -- "$(dirname "$output")" && pwd) || fail "cannot resolve output parent"
test "$output_parent/$(basename "$output")" = "$output" || fail "output path must be canonical"
case "$(basename "$output")" in *.tar.gz) ;; *) fail "output must end in .tar.gz" ;; esac
require_key_outside_tree "$source_root" "source staging"
require_key_outside_tree "$output_parent" output
validate_signing_key

command -v git >/dev/null 2>&1 || fail "git is required"
command -v ssh-keygen >/dev/null 2>&1 || fail "ssh-keygen with SSHSIG support is required"
test "$(git -C "$source_root" rev-parse --show-toplevel)" = "$source_root" || fail "source is not the Git root"
actual_commit=$(git -C "$source_root" rev-parse --verify HEAD) || fail "cannot resolve source HEAD"
test "$actual_commit" = "$commit" || fail "--commit does not equal source HEAD"
test -z "$(git -C "$source_root" status --porcelain=v1 --untracked-files=all)" || fail "source archive requires a completely clean tree"

unexpected=$(find "$source_root/cmd" "$source_root/internal" ! -type f ! -type d -print)
test -z "$unexpected" || fail "Go build tree contains a symlink or special entry"

workspace=$(mktemp -d "$output_parent/.owntransit-source.XXXXXX") || fail "cannot create build workspace"
cleanup() { rm -rf -- "$workspace"; }
trap cleanup EXIT HUP INT TERM
manifest="$workspace/SOURCE-MANIFEST.txt"
(
  cd "$source_root"
  find go.mod go.sum cmd internal -type f -print | LC_ALL=C sort |
    while IFS= read -r path; do
      case "$path" in *[!A-Za-z0-9._/+:-]*) fail "source path is unsafe: $path" ;; esac
      if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$path"
      else
        shasum -a 256 "$path"
      fi
    done
) > "$manifest"
test -s "$manifest" || fail "source manifest is empty"

ssh-keygen -q -Y sign -f "$signing_key" -n owntransit-source-v1 "$manifest" \
  <"$key_prompt_input" >/dev/null
signature="$manifest.sig"
test -s "$signature" || fail "ssh-keygen did not create the detached signature"

if command -v sha256sum >/dev/null 2>&1; then
  manifest_digest=$(sha256sum "$manifest" | awk '{print $1}')
else
  manifest_digest=$(shasum -a 256 "$manifest" | awk '{print $1}')
fi
project_root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
"$project_root/packaging/macos/verify-sshsig.sh" \
  --subject "$manifest" --sha256 "$manifest_digest" \
  --signature "$signature" --allowed-signers "$allowed_signers" \
  --signer "$signer" --namespace owntransit-source-v1 >/dev/null

archive="$workspace/owntransit-$version-source.tar.gz"
git -c tar.umask=0022 -C "$source_root" archive \
  --format=tar.gz \
  --prefix="owntransit-$version/" \
  --add-file="$manifest" \
  --add-file="$signature" \
  --output="$archive" \
  "$commit"
test -s "$archive" || fail "git archive did not create an archive"

verify_root="$workspace/verify"
mkdir "$verify_root"
tar -xzpf "$archive" -C "$verify_root"
verified_source="$verify_root/owntransit-$version"
test -d "$verified_source" && test ! -L "$verified_source" || fail "source archive omitted its canonical root"
unexpected=$(find "$verified_source" ! -type f ! -type d -print)
test -z "$unexpected" || fail "source archive contains a symlink or special entry"
archive_directories="$workspace/archive-directories"
find "$verified_source" -type d -print > "$archive_directories" ||
  fail "cannot enumerate source archive directories"
while IFS= read -r archive_directory; do
  test "$(file_mode "$archive_directory")" = 755 ||
    fail "source archive directory mode is not 0755: $archive_directory"
done < "$archive_directories"
source_tree="$workspace/source-tree"
git -C "$source_root" ls-tree -r "$commit" > "$source_tree" ||
  fail "cannot enumerate source commit modes"
while IFS="$(printf '\t')" read -r tree_metadata relative; do
  tree_mode=${tree_metadata%% *}
  case "$tree_mode" in
    100644) expected_mode=644 ;;
    100755) expected_mode=755 ;;
    *) fail "source commit contains an unsupported entry mode: $tree_mode $relative" ;;
  esac
  archived_file="$verified_source/$relative"
  test -f "$archived_file" && test ! -L "$archived_file" ||
    fail "source archive omitted a tracked regular file: $relative"
  test "$(file_mode "$archived_file")" = "$expected_mode" ||
    fail "source archive changed tracked mode for $relative"
done < "$source_tree"
for generated_source_member in SOURCE-MANIFEST.txt SOURCE-MANIFEST.txt.sig; do
  test "$(file_mode "$verified_source/$generated_source_member")" = 644 ||
    fail "source archive generated member mode is not 0644: $generated_source_member"
done
"$project_root/packaging/homebrew/verify-source-tree.sh" \
  --source "$verified_source" \
  --allowed-signers "$allowed_signers" \
  --signer "$signer" >/dev/null

mv "$archive" "$output"
trap - EXIT HUP INT TERM
rm -rf -- "$workspace"
if command -v sha256sum >/dev/null 2>&1; then
  archive_digest=$(sha256sum "$output" | awk '{print $1}')
else
  archive_digest=$(shasum -a 256 "$output" | awk '{print $1}')
fi
printf 'created source archive: %s\n' "$output"
printf 'source_archive_sha256=%s\n' "$archive_digest"
printf 'source_manifest_sha256=%s\n' "$manifest_digest"
