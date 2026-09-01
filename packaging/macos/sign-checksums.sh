#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
LC_ALL=C
export LC_ALL
umask 077

# A release signature must come from the named private-key file, never from an
# ambient agent or graphical askpass program. An encrypted key may still prompt
# on the process's controlling terminal; with no controlling terminal the
# selected /dev/null input makes validation fail closed.
unset SSH_AUTH_SOCK SSH_AGENT_PID SSH_ASKPASS SSH_ASKPASS_REQUIRE DISPLAY WAYLAND_DISPLAY

key_prompt_input=/dev/null
if /usr/bin/tty 2>/dev/null </dev/tty >/dev/null; then
  key_prompt_input=/dev/tty
fi

fail() {
  printf 'sign-checksums: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
usage: sign-checksums.sh \
  --subject ABSOLUTE_SHA256SUMS \
  --signing-key ABSOLUTE_ED25519_SSH_PRIVATE_KEY \
  --allowed-signers ABSOLUTE_FILE \
  --signer SAFE_IDENTITY \
  --output ABSOLUTE_NEW_SIGNATURE_OUTSIDE_STAGING

Signs exact checksum bytes in the fixed owntransit-release-v1 SSHSIG namespace,
then verifies the new signature against the intended public trust anchor. The
output is required to be outside the checksum staging tree because the native
installers reject unauthenticated extra files in that tree.
EOF
}

subject=
signing_key=
allowed_signers=
signer=
output=
while test "$#" -gt 0; do
  case "$1" in
    --subject|--signing-key|--allowed-signers|--signer|--output)
      test "$#" -ge 2 || fail "$1 requires a value"
      option=$1
      value=$2
      shift 2
      case "$option" in
        --subject) subject=$value ;;
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

canonical_file() {
  input=$1
  label=$2
  case "$input" in /*) ;; *) fail "$label path must be absolute" ;; esac
  test -f "$input" && test ! -L "$input" || fail "$label must be a regular non-symlink file"
  parent=$(CDPATH= cd -P -- "$(dirname "$input")" && pwd) || fail "cannot resolve $label parent"
  test "$parent/$(basename "$input")" = "$input" || fail "$label path must be canonical"
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
      protected_mode=$(stat -f %Lp -- "$protected_path") || fail "cannot read protected key mode: $protected_path"
      case "$protected_mode" in
        [0-7][0-7][0-7]|[0-7][0-7][0-7][0-7]) ;;
        *) fail "protected key ancestor mode is invalid: $protected_path" ;;
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
    key_metadata=$(stat -f '%HT|%u|%l|%Lp' -- "$signing_key") || fail "cannot stat signing key"
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

canonical_file "$subject" subject
canonical_file "$signing_key" signing-key
canonical_file "$allowed_signers" allowed-signers
case "$signer" in ''|*[!A-Za-z0-9._@+-]*) fail "signer is not a safe identity" ;; esac
test "$signer" = owntransit-release || fail "release signer identity must be exactly owntransit-release"
test -s "$subject" || fail "subject is empty"
test "$(basename "$subject")" = SHA256SUMS || fail "subject basename must be SHA256SUMS"

case "$output" in /*) ;; *) fail "output path must be absolute" ;; esac
test ! -e "$output" && test ! -L "$output" || fail "output already exists"
output_parent=$(CDPATH= cd -P -- "$(dirname "$output")" && pwd) || fail "cannot resolve output parent"
test "$output_parent/$(basename "$output")" = "$output" || fail "output path must be canonical"
subject_parent=$(CDPATH= cd -P -- "$(dirname "$subject")" && pwd)
case "$output_parent/" in "$subject_parent/"*) fail "signature output must be outside the checksum staging tree" ;; esac
require_key_outside_tree "$subject_parent" "checksum staging"
require_key_outside_tree "$output_parent" output
validate_signing_key

signature_workspace=$(mktemp -d "$output_parent/.owntransit-checksums-sign.XXXXXX") ||
  fail "cannot create private signature workspace"
cleanup() { rm -rf -- "$signature_workspace"; }
trap cleanup EXIT HUP INT TERM
signing_subject="$signature_workspace/SHA256SUMS"
cp -- "$subject" "$signing_subject" || fail "cannot copy checksum bytes into the private signature workspace"
chmod 0600 "$signing_subject"
ssh-keygen -q -Y sign -f "$signing_key" -n owntransit-release-v1 "$signing_subject" \
  <"$key_prompt_input" >/dev/null
temporary="$signing_subject.sig"
test -s "$temporary" || fail "ssh-keygen did not produce a signature"
if command -v sha256sum >/dev/null 2>&1; then
  subject_digest=$(sha256sum "$signing_subject" | awk '{print $1}')
else
  subject_digest=$(shasum -a 256 "$signing_subject" | awk '{print $1}')
fi
project_root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
"$project_root/packaging/macos/verify-sshsig.sh" \
  --subject "$subject" --sha256 "$subject_digest" \
  --signature "$temporary" --allowed-signers "$allowed_signers" \
  --signer "$signer" --namespace owntransit-release-v1 >/dev/null
chmod 0644 "$temporary"
mv "$temporary" "$output"
rm -rf -- "$signature_workspace"
trap - EXIT HUP INT TERM
printf 'created checksum signature: %s\n' "$output"
printf 'checksums_sha256=%s\n' "$subject_digest"
