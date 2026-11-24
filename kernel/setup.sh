#!/bin/sh
set -eu

GKI_ROOT=$(pwd)
KSU_REPO=${KSU_REPO:-https://github.com/sohan-f/KernelSU}

display_usage() {
    echo "Usage: $0 [--cert <der>] [--cleanup | <commit-or-tag>]"
    echo "  --cleanup:              Cleans up previous modifications made by the script."
    echo "  <commit-or-tag>:        Sets up or updates the KernelSU to specified tag or commit."
    echo "  -h, --help:             Displays this usage information."
    echo "  (no args):              Sets up or updates the KernelSU environment to the latest main."
    echo "  --cert <der>:           Registers this manager signing certificate (DER) as the only"
    echo "                          accepted one. Same as KSU_MANAGER_CERT=<der>."
    echo "  KSU_REPO=<git-url>:     Repository to clone (default: $KSU_REPO)."
}

initialize_variables() {
    if test -d "$GKI_ROOT/common/drivers"; then
         DRIVER_DIR="$GKI_ROOT/common/drivers"
    elif test -d "$GKI_ROOT/drivers"; then
         DRIVER_DIR="$GKI_ROOT/drivers"
    else
         echo '[ERROR] "drivers/" directory not found.'
         exit 127
    fi

    DRIVER_MAKEFILE=$DRIVER_DIR/Makefile
    DRIVER_KCONFIG=$DRIVER_DIR/Kconfig
}

# Reverts modifications made by this script
perform_cleanup() {
    echo "[+] Cleaning up..."
    [ -L "$DRIVER_DIR/kernelsu" ] && rm "$DRIVER_DIR/kernelsu" && echo "[-] Symlink removed."
    grep -q "kernelsu" "$DRIVER_MAKEFILE" && sed -i '/kernelsu/d' "$DRIVER_MAKEFILE" && echo "[-] Makefile reverted."
    grep -q "drivers/kernelsu/Kconfig" "$DRIVER_KCONFIG" && sed -i '/drivers\/kernelsu\/Kconfig/d' "$DRIVER_KCONFIG" && echo "[-] Kconfig reverted."
    if [ -d "$GKI_ROOT/KernelSU" ]; then
        rm -rf "$GKI_ROOT/KernelSU" && echo "[-] KernelSU directory deleted."
    fi
}

# Points KSU_EXPECTED_SIZE/HASH at the caller's manager certificate. The kernel
# crowns whichever installed manager matches a pair, so this is what binds it to
# a manager we signed; without it only the public dummy.keystore pair matches.
# Re-applied on every run, `git stash` above keeps dropping the previous one.
apply_manager_cert() {
    [ -n "$CERT" ] || return 0

    [ -f "$CERT" ] || { echo "[ERROR] Certificate not found: $CERT"; exit 1; }
    openssl x509 -inform DER -noout -in "$CERT" >/dev/null 2>&1 ||
        { echo "[ERROR] Not a DER certificate: $CERT"; exit 1; }

    cert_size=$(wc -c < "$CERT")
    if [ "$cert_size" -gt 1024 ]; then
        echo "[ERROR] Certificate is $cert_size bytes, CERT_MAX_LENGTH is 1024."
        exit 1
    fi
    cert_hex=$(printf '0x%x' "$cert_size")
    cert_hash=$(openssl dgst -sha256 -r "$CERT" | cut -d' ' -f1)

    sed -i "s/^KSU_EXPECTED_SIZE := .*/KSU_EXPECTED_SIZE := $cert_hex/" "$GKI_ROOT/KernelSU/kernel/Makefile"
    sed -i "s/^KSU_EXPECTED_HASH := .*/KSU_EXPECTED_HASH := $cert_hash/" "$GKI_ROOT/KernelSU/kernel/Makefile"

    echo "[+] Manager certificate registered: $cert_hex $cert_hash"
    echo "[-] The manager APK must be signed with the same key and carry a v2 signature."
    echo "[-] Keep applicationId at me.weishu.kernelsu, or the tracker never reaches the signature check."
}

# Sets up or update KernelSU environment
setup_kernelsu() {
    echo "[+] Setting up KernelSU..."
    test -d "$GKI_ROOT/KernelSU" || git clone "$KSU_REPO" KernelSU && echo "[+] Repository cloned."
    cd "$GKI_ROOT/KernelSU"
    git stash && echo "[-] Stashed current changes."
    git pull && echo "[+] Repository updated."
    if [ -z "${1-}" ]; then
        git checkout main && echo "[-] Checked out main."
    else
        git checkout "$1" && echo "[-] Checked out $1." || echo "[-] Checkout default branch"
    fi
    apply_manager_cert
    cd "$DRIVER_DIR"
    ln -sf "$(realpath --relative-to="$DRIVER_DIR" "$GKI_ROOT/KernelSU/kernel")" "kernelsu" && echo "[+] Symlink created."

    # Add entries in Makefile and Kconfig if not already existing
    grep -q "kernelsu" "$DRIVER_MAKEFILE" || printf "\nobj-\$(CONFIG_KSU) += kernelsu/\n" >> "$DRIVER_MAKEFILE" && echo "[+] Modified Makefile."
    grep -q "source \"drivers/kernelsu/Kconfig\"" "$DRIVER_KCONFIG" || sed -i "/endmenu/i\source \"drivers/kernelsu/Kconfig\"" "$DRIVER_KCONFIG" && echo "[+] Modified Kconfig."
    echo '[+] Done.'
}

CERT=${KSU_MANAGER_CERT-}
REV=""
CLEANUP=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        -h|--help)
            display_usage
            exit 0
            ;;
        --cleanup)
            CLEANUP=1
            shift
            ;;
        --cert)
            [ "$#" -ge 2 ] || { echo '[ERROR] --cert needs a DER file.'; exit 2; }
            CERT=$2
            shift 2
            ;;
        --cert=*)
            CERT=${1#--cert=}
            shift
            ;;
        -*)
            echo "[ERROR] Unknown option: $1"
            display_usage
            exit 2
            ;;
        *)
            [ -z "$REV" ] || { echo '[ERROR] Only one commit-or-tag.'; exit 2; }
            REV=$1
            shift
            ;;
    esac
done

if [ -n "$CERT" ]; then
    [ -e "$CERT" ] || { echo "[ERROR] Certificate not found: $CERT"; exit 1; }
    CERT=$(realpath "$CERT")
fi

initialize_variables
if [ "$CLEANUP" -eq 1 ]; then
    perform_cleanup
elif [ -z "$REV" ]; then
    setup_kernelsu
else
    setup_kernelsu "$REV"
fi
