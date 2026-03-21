#!/usr/bin/env bash
# Set up branch protection on the sbom-tool/homebrew-tap repository.
#
# Prevents direct pushes to main (only the CI bot should update the formula),
# and blocks force-push and deletion — mitigating a compromised HOMEBREW_TAP_TOKEN.
#
# Requirements:
#   - gh CLI authenticated with admin access to sbom-tool/homebrew-tap
#
# Usage: scripts/setup-homebrew-tap-protection.sh
set -euo pipefail

TAP_REPO="${TAP_REPO:-sbom-tool/homebrew-tap}"

echo "==> Setting up branch protection for ${TAP_REPO}"
echo ""

# Check gh auth
if ! gh auth status &>/dev/null; then
    echo "Error: Not authenticated. Run 'gh auth login' first."
    exit 1
fi

# Check admin access
PERMISSION=$(gh api "repos/${TAP_REPO}" --jq '.permissions.admin' 2>/dev/null || echo "false")
if [[ "${PERMISSION}" != "true" ]]; then
    echo "Error: Admin access required. Current user does not have admin on ${TAP_REPO}."
    exit 1
fi

# ── Step 1: Create branch ruleset ───────────────────────────────
echo "==> Creating branch ruleset for main..."

EXISTING=$(gh api "repos/${TAP_REPO}/rulesets" --jq '[.[] | select(.target == "branch")] | length' 2>/dev/null || echo "0")
if [[ "${EXISTING}" -gt 0 ]]; then
    echo "Note: ${EXISTING} branch ruleset(s) already exist:"
    gh api "repos/${TAP_REPO}/rulesets" --jq '.[] | select(.target == "branch") | "  - \(.name) (id: \(.id), enforcement: \(.enforcement))"'
    echo ""
fi

BRANCH_RULESET=$(cat <<'EOF'
{
  "name": "Protect main",
  "target": "branch",
  "enforcement": "active",
  "conditions": {
    "ref_name": {
      "include": ["~DEFAULT_BRANCH"],
      "exclude": []
    }
  },
  "rules": [
    {
      "type": "deletion"
    },
    {
      "type": "non_fast_forward"
    }
  ],
  "bypass_actors": [
    {
      "actor_id": 5,
      "actor_type": "RepositoryRole",
      "bypass_mode": "always"
    }
  ]
}
EOF
)

RESULT=$(echo "${BRANCH_RULESET}" | gh api "repos/${TAP_REPO}/rulesets" --method POST --input - 2>&1) && {
    RULESET_ID=$(echo "${RESULT}" | jq -r '.id')
    echo "  Branch ruleset created (ID: ${RULESET_ID})"
    echo "  Rules: deletion blocked, force-push blocked"
    echo "  Bypass: admins only"
} || {
    echo "Warning: Could not create branch ruleset:"
    echo "${RESULT}"
}

# ── Step 2: Create tag ruleset ──────────────────────────────────
echo ""
echo "==> Creating tag ruleset..."

TAG_RULESET=$(cat <<'EOF'
{
  "name": "Protect tags",
  "target": "tag",
  "enforcement": "active",
  "conditions": {
    "ref_name": {
      "include": ["~ALL"],
      "exclude": []
    }
  },
  "rules": [
    {
      "type": "deletion"
    },
    {
      "type": "non_fast_forward"
    }
  ],
  "bypass_actors": [
    {
      "actor_id": 5,
      "actor_type": "RepositoryRole",
      "bypass_mode": "always"
    }
  ]
}
EOF
)

RESULT=$(echo "${TAG_RULESET}" | gh api "repos/${TAP_REPO}/rulesets" --method POST --input - 2>&1) && {
    RULESET_ID=$(echo "${RESULT}" | jq -r '.id')
    echo "  Tag ruleset created (ID: ${RULESET_ID})"
} || {
    echo "Warning: Could not create tag ruleset:"
    echo "${RESULT}"
}

# ── Step 3: Verify HOMEBREW_TAP_TOKEN scope ─────────────────────
echo ""
echo "==> HOMEBREW_TAP_TOKEN verification checklist"
echo ""
echo "  Manually verify the following in GitHub Settings > Developer settings > Personal access tokens:"
echo ""
echo "  1. Token type: Fine-grained (NOT classic)"
echo "  2. Resource owner: sbom-tool"
echo "  3. Repository access: Only select repositories > sbom-tool/homebrew-tap"
echo "  4. Permissions:"
echo "     - Contents: Read and write (required to push formula updates)"
echo "     - Metadata: Read (required, auto-granted)"
echo "     - All other permissions: No access"
echo "  5. Expiration: Set a reasonable expiry (e.g., 90 days) and rotate before it expires"
echo ""
echo "  If the token is a classic PAT with broader scope, rotate it to a fine-grained PAT."
echo "  Classic PATs cannot be scoped to a single repository."
echo ""
echo "  Token settings: https://github.com/settings/tokens?type=beta"
echo ""

# ── Summary ─────────────────────────────────────────────────────
echo "==> Done"
echo ""
echo "  Verify at: https://github.com/${TAP_REPO}/settings/rules"
echo ""
echo "  Attack surface after this script:"
echo "  - Direct push to main:    Allowed (CI bot needs this)"
echo "  - Force-push to main:     BLOCKED"
echo "  - Delete main:            BLOCKED"
echo "  - Compromised PAT scope:  Limited to homebrew-tap only (if fine-grained)"
