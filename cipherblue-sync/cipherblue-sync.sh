#!/usr/bin/env bash
set -euo pipefail

# cipherblue-sync.sh
# Full Repository Sync & Rebrand: Pulls upstream, dynamically rebrands, applies deny-list, harmonizes kargs, and generates telemetry.

usage() {
    echo "Usage: ./cipherblue-sync/cipherblue-sync.sh --git-url <url> [options]"
    echo "Options:"
    echo "  --branch <branch>      Branch to checkout (default: live)"
    echo "  --exclude <file>       Path to exclude list"
    exit 1
}

GIT_URL=""
BRANCH="live"
LOCAL_PATH=""
EXCLUDE_FILE="cipherblue-sync/cipherblue-exclude.txt"
PROTECTION_FILE="cipherblue-sync/cipherblue-preserve.txt"
DEST_ROOT="." 
TMP_DIRS=()

cleanup() {
    for dir in "${TMP_DIRS[@]}"; do
        [[ -e "$dir" ]] && rm -rf "$dir"
    done
}
trap cleanup EXIT

while [[ $# -gt 0 ]]; do
  case "$1" in
    --git-url) GIT_URL="$2"; shift 2;;
    --branch) BRANCH="$2"; shift 2;;
    --local-path) LOCAL_PATH="$2"; shift 2;;
    --exclude) EXCLUDE_FILE="$2"; shift 2;;
    -h|--help) usage;;
    *) echo "Unknown arg: $1" >&2; usage;;
  esac
done

if [[ -z "$GIT_URL" && -z "$LOCAL_PATH" ]]; then
  echo "Error: --git-url or --local-path must be provided." >&2
  exit 2
fi

if [[ -n "$GIT_URL" ]]; then
  TMPROOT=$(mktemp -d /tmp/cipherblue-sync-XXXXXX)
  TMP_DIRS+=("$TMPROOT")
  echo "Cloning $GIT_URL (branch $BRANCH) to $TMPROOT..."
  git clone --depth 1 --branch "$BRANCH" "$GIT_URL" "$TMPROOT"
  SRCROOT="$TMPROOT"
else
  SRCROOT="$LOCAL_PATH"
fi

# ==============================================================================
# REBRANDING ENGINE (Surgical Strike on TMPROOT)
# ==============================================================================
echo "Initializing Rebranding Engine (secureblue -> cipherblue)..."

# Strip upstream .git to speed up processing and prevent corruption
rm -rf "$SRCROOT/.git"

# Text Content Replacement
echo "Rebranding file contents (Shielding Cryptographic Keys)..."
grep -Irl "secureblue" "$SRCROOT" | grep -vE '\.(gpg|der|pub)$' | xargs -r sed -i 's/secureblue/cipherblue/g' || true
grep -Irl "Secureblue" "$SRCROOT" | grep -vE '\.(gpg|der|pub)$' | xargs -r sed -i 's/Secureblue/Cipherblue/g' || true
grep -Irl "SecureBlue" "$SRCROOT" | grep -vE '\.(gpg|der|pub)$' | xargs -r sed -i 's/SecureBlue/CipherBlue/g' || true

echo "Healing network URLs and upstream package dependencies..."
grep -Irl "cipherblue\.dev" "$SRCROOT" | xargs -r sed -i 's/cipherblue\.dev/secureblue\.dev/g' || true
grep -Irl "github\.com/cipherblue" "$SRCROOT" | xargs -r sed -i 's/github\.com\/cipherblue/github\.com\/secureblue/g' || true
grep -Irl "api\.github\.com/repos/cipherblue" "$SRCROOT" | xargs -r sed -i 's/api\.github\.com\/repos\/cipherblue/api\.github\.com\/repos\/secureblue/g' || true
grep -Irl "raw\.githubusercontent\.com/cipherblue" "$SRCROOT" | xargs -r sed -i 's/raw\.githubusercontent\.com\/cipherblue/raw\.githubusercontent\.com\/secureblue/g' || true
grep -Irl "ghcr\.io/cipherblue" "$SRCROOT" | xargs -r sed -i 's/ghcr\.io\/cipherblue/ghcr\.io\/secureblue/g' || true
grep -Irl "quay\.io/cipherblue" "$SRCROOT" | xargs -r sed -i 's/quay\.io\/cipherblue/quay\.io\/secureblue/g' || true

grep -Irl "copr\.fedorainfracloud\.org/coprs/cipherblue" "$SRCROOT" | xargs -r sed -i 's/coprs\/cipherblue/coprs\/secureblue/g' || true
grep -Irl "copr\.fedorainfracloud\.org/results/cipherblue" "$SRCROOT" | xargs -r sed -i 's/results\/cipherblue/results\/secureblue/g' || true
grep -Irl "repo\.secureblue\.dev/cipherblue" "$SRCROOT" | xargs -r sed -i 's/repo\.secureblue\.dev\/cipherblue/repo\.secureblue\.dev\/secureblue/g' || true

grep -Irl "akmods-cipherblue" "$SRCROOT" | xargs -r sed -i 's/akmods-cipherblue/akmods-secureblue/g' || true
grep -Irl "cipherblue/trivalent" "$SRCROOT" | xargs -r sed -i 's/cipherblue\/trivalent/secureblue\/trivalent/g' || true
grep -Irl "cipherblue/hardened_malloc" "$SRCROOT" | xargs -r sed -i 's/cipherblue\/hardened_malloc/secureblue\/hardened_malloc/g' || true

echo "Rebranding directory and file names..."
find "$SRCROOT" -depth -name "*secureblue*" | while read -r item; do
    dir=$(dirname "$item")
    base=$(basename "$item")
    new_base=${base//secureblue/cipherblue}
    mv "$item" "$dir/$new_base"
done

find "$SRCROOT" -depth -name "*Secureblue*" | while read -r item; do
    dir=$(dirname "$item")
    base=$(basename "$item")
    new_base=${base//Secureblue/Cipherblue}
    mv "$item" "$dir/$new_base"
done
echo "Rebranding complete!"

# ==============================================================================
# RSYNC ENGINE
# ==============================================================================
echo "Syncing FULL REBRANDED REPOSITORY from $SRCROOT to $DEST_ROOT"

RUNTIME_EXCLUDE=$(mktemp)
TMP_DIRS+=("$RUNTIME_EXCLUDE")

if [[ -f "$EXCLUDE_FILE" ]]; then
  grep -v '^#' "$EXCLUDE_FILE" | grep -v '^[[:space:]]*$' | tr -d '\r' > "$RUNTIME_EXCLUDE" || true
fi

if [[ -f "$PROTECTION_FILE" ]]; then
  grep -v '^#' "$PROTECTION_FILE" | grep -v '^[[:space:]]*$' | tr -d '\r' >> "$RUNTIME_EXCLUDE" || true
fi

rsync -a -m --delete --exclude-from="$RUNTIME_EXCLUDE" "$SRCROOT/" "$DEST_ROOT/" 2>&1 | grep -v 'cannot delete non-empty directory' || true

MERGE_DEST="files/system"
for VAR in silverblue desktop; do
  for DIR in usr etc; do
    if [[ -d "$SRCROOT/files/system/$VAR/$DIR" ]]; then
      mkdir -p "$MERGE_DEST/$DIR"
      
      MERGE_EXCLUDE=$(mktemp)
      TMP_DIRS+=("$MERGE_EXCLUDE")
      
      if [[ -f "$EXCLUDE_FILE" ]]; then
        while IFS= read -r pat; do
          pat="${pat//$'\\r'/}" 
          if [[ "$pat" == "files/system/$VAR/$DIR/"* ]]; then
            echo "${pat#files/system/$VAR/$DIR/}" >> "$MERGE_EXCLUDE"
          elif [[ "$pat" == "files/system/$DIR/"* ]]; then
            echo "${pat#files/system/$DIR/}" >> "$MERGE_EXCLUDE"
          elif [[ "$pat" == *"*"* && "$pat" != "files/system/"* ]]; then
            echo "$pat" >> "$MERGE_EXCLUDE"
          fi
        done < "$EXCLUDE_FILE"
      fi
      
      rsync -a -m --exclude-from="$MERGE_EXCLUDE" "$SRCROOT/files/system/$VAR/$DIR/" "$MERGE_DEST/$DIR/" 2>&1 | grep -v 'cannot delete non-empty directory' || true
    fi
  done
done

# ==============================================================================
# UPSTREAM PRESERVE PROTOCOL (Variant-Aware Fuzzy Seeker)
# Forcibly copies specific upstream files, bypassing all exclude rules.
# ==============================================================================
UPSTREAM_PRESERVE="cipherblue-sync/upstream-preserve.txt"
if [[ -f "$UPSTREAM_PRESERVE" ]]; then
  echo "OVERRIDE: Force-syncing files from upstream-preserve.txt..."
  while IFS= read -r file || [[ -n "$file" ]]; do
    file="${file//$'\\r'/}"
    [[ -z "$file" || "$file" =~ ^# ]] && continue
    
    found=false
    
    # Attempt 1: Exact Path Matching
    for prefix in "" "desktop/" "silverblue/"; do
      src_path="$SRCROOT/${file/files\/system\//files\/system\/$prefix}"
      if [[ -f "$src_path" ]]; then
        mkdir -p "$(dirname "$DEST_ROOT/$file")"
        cp -a "$src_path" "$DEST_ROOT/$file"
        found=true
        echo "[Success] Laser Scalpel exact match synced: $file"
        break
      fi
    done
    
    # Attempt 2: FUZZY SEEKER (Handles Unknown Names and Directory Drift)
    if [[ "$found" == false ]]; then
      filename=$(basename "$file")
      fuzzy_name="*${filename#*-}"
      
      echo "[Warn] $file not found at exact path. Fuzzy hunting for $fuzzy_name..."
      hunted_path=$(find "$SRCROOT/files/system" -type f -name "$fuzzy_name" | grep -vE '/(cosmic|kinoite|sericea|server|zfs|nvidia)/' | head -n 1 || true)
      
      if [[ -n "$hunted_path" ]]; then
        echo "[Success] Found $(basename "$hunted_path")! Relocating to requested target directory..."
        mkdir -p "$(dirname "$DEST_ROOT/$file")"
        cp -a "$hunted_path" "$DEST_ROOT/$file"
      else
        echo "[Error] Could not locate any file matching $fuzzy_name anywhere in valid upstream directories."
      fi
    fi
  done < "$UPSTREAM_PRESERVE"
fi

# ==============================================================================
# KERNEL ARGUMENT HARMONIZATION ENGINE (The "Smart Way")
# Intercepts upstream's TOML file, strips performance blockers, injects AI flags.
# ==============================================================================
TARGET_TOML="$DEST_ROOT/files/system/usr/lib/bootc/kargs.d/10-cipherblue.toml"

if [[ -f "$TARGET_TOML" ]]; then
    echo "CIPHERBLUE: Harmonizing Upstream Kernel Arguments..."
    
    # 1. Strip Out Performance/Boot Blockers (Preserve AI/ML Hyper-Threading)
    sed -i '/"nosmt=force",*/d' "$TARGET_TOML"          
    sed -i 's/,nosmt//g' "$TARGET_TOML"                 
    sed -i '/"fips=1",*/d' "$TARGET_TOML"               
    sed -i '/"ima_appraise=enforce",*/d' "$TARGET_TOML" 
    
    # 2. Inject ALL missing Cipherblue Custom Zero-Trust Parameters
    CUSTOM_KARGS=(
        "amd_iommu=force_isolation"
        "bdev_allow_write_mounted=0"
        "debugfs=off"
        "efi=disable_early_pci_dma"
        "extra_latent_entropy"
        "ftrace=off"
        "gather_data_sampling=force"
        "ia32_emulation=0"
        "ipv6.disable=1"
        "kvm.nx_huge_pages=force"
        "lsm=lockdown,yama,selinux,bpf"
        "mds=full"
        "mem_encrypt=on"
        "oops=panic"
        "page_poison=1"
        "reg_file_data_sampling=on"
        "spec_rstack_overflow=safe-ret"
        "spectre_bhi=on"
        "tsx=off"
        "tsx_async_abort=full"
    )
    
    for karg in "${CUSTOM_KARGS[@]}"; do
        if ! grep -q "\"$karg\"" "$TARGET_TOML"; then
            sed -i "/kargs.*\[/a \ \ \"$karg\"," "$TARGET_TOML"
        fi
    done

    # 3. The SRE Polish: Perfect Alphabetical Sorting & Deduplication
    echo "CIPHERBLUE: Alphabetizing and deduplicating TOML array..."
    TMP_TOML=$(mktemp)
    sed '/kargs = \[/q' "$TARGET_TOML" > "$TMP_TOML"
    grep '^[[:space:]]*"' "$TARGET_TOML" | sort -u >> "$TMP_TOML"
    echo "]" >> "$TMP_TOML"
    mv "$TMP_TOML" "$TARGET_TOML"

    echo "CIPHERBLUE: Kernel arguments mathematically harmonized."
fi

# ==============================================================================
# TELEMETRY & AUDIT ENGINE
# Mathematically cross-references rules against the upstream repo to generate a report.
# ==============================================================================
echo "Generating CI/CD Sync Audit Report..."
AUDIT_FILE="$DEST_ROOT/cipherblue-sync/SYNC_AUDIT.md"

cat << 'EOF' > "$AUDIT_FILE"
# 🛡️ Cipherblue Sync Telemetry Report
*Auto-generated during the CI/CD pipeline run to provide complete visibility into the Sync Engine state machine.*

EOF

echo "## 🔒 The Local Vault (Preserved Local Files)" >> "$AUDIT_FILE"
echo "These files exist in our repo. If upstream pushes a file with the exact same name, the Sync Engine **blocks** the upstream version to protect our custom code." >> "$AUDIT_FILE"
echo "" >> "$AUDIT_FILE"
if [[ -f "$PROTECTION_FILE" ]]; then
  while IFS= read -r file || [[ -n "$file" ]]; do
    file="${file//$'\\r'/}"
    [[ -z "$file" || "$file" =~ ^# ]] && continue
    echo "- \`$file\`" >> "$AUDIT_FILE"
  done < "$PROTECTION_FILE"
fi
echo "" >> "$AUDIT_FILE"

echo "## ⚡ The Laser Scalpel (Force-Synced Files)" >> "$AUDIT_FILE"
echo "These files are explicitly ripped from upstream and pulled into our OS, mathematically bypassing all blanket exclusions." >> "$AUDIT_FILE"
echo "" >> "$AUDIT_FILE"
if [[ -f "$UPSTREAM_PRESERVE" ]]; then
  while IFS= read -r file || [[ -n "$file" ]]; do
    file="${file//$'\\r'/}"
    [[ -z "$file" || "$file" =~ ^# ]] && continue
    echo "- \`$file\`" >> "$AUDIT_FILE"
  done < "$UPSTREAM_PRESERVE"
fi
echo "" >> "$AUDIT_FILE"

echo "## ✂️ The Great Wall (Excluded Upstream Files)" >> "$AUDIT_FILE"
echo "These files and directories were completely annihilated from the upstream pull. Click the dropdowns to see the exact upstream files that were dropped by the wildcard rules." >> "$AUDIT_FILE"
echo "" >> "$AUDIT_FILE"

if [[ -f "$EXCLUDE_FILE" ]]; then
  while IFS= read -r pat || [[ -n "$pat" ]]; do
    pat="${pat//$'\\r'/}"
    [[ -z "$pat" || "$pat" =~ ^# ]] && continue

    echo "<details><summary><b>Excluded Rule: <code>$pat</code></b></summary>" >> "$AUDIT_FILE"
    echo "" >> "$AUDIT_FILE"
    echo '```text' >> "$AUDIT_FILE"

    clean_pat="${pat#/}"
    clean_pat="${clean_pat%\/\*\*}"
    clean_pat="${clean_pat%\/\*}"

    found_any=false
    TMP_LIST=$(mktemp)
    
    # Loop conditionally based on whether the path requires variant targeting
    for prefix in "" "desktop/" "silverblue/"; do
        if [[ "$clean_pat" == files/system/* ]]; then
             search_dir="$SRCROOT/${clean_pat/files\/system\//files\/system\/$prefix}"
        else
             if [[ "$prefix" != "" ]]; then continue; fi
             search_dir="$SRCROOT/$clean_pat"
        fi

        if [[ -d "$search_dir" ]]; then
            find "$search_dir" -type f | sed "s|$SRCROOT/||" >> "$TMP_LIST" || true
        elif [[ -f "$search_dir" ]]; then
            echo "${search_dir#$SRCROOT/}" >> "$TMP_LIST"
        fi
    done

    # The mathematical deduplication buffer
    if [[ -s "$TMP_LIST" ]]; then
        sort -u "$TMP_LIST" | sed "s|^|  - |" >> "$AUDIT_FILE"
        found_any=true
    fi
    rm -f "$TMP_LIST"

    if [[ "$found_any" == false ]]; then
        echo "  (No upstream files matched this rule during this sync commit)" >> "$AUDIT_FILE"
    fi

    echo '```' >> "$AUDIT_FILE"
    echo "</details>" >> "$AUDIT_FILE"
    echo "" >> "$AUDIT_FILE"

  done < "$EXCLUDE_FILE"
fi

# ==============================================================================
# POST-SYNC PURGE
# ==============================================================================
echo "Purging raw variant directories from disk to prevent ghost staging..."
rm -rf "files/system/desktop" "files/system/silverblue"
rm -rf "files/system/cosmic" "files/system/kinoite" "files/system/sericea" "files/system/server" "files/system/zfs" "files/system/nvidia"

echo "Full Repository Sync complete."
exit 0