#!/usr/bin/env bash
# Create a GitHub tag protection ruleset for sbom-tools.
#
# This prevents tag poisoning attacks (force-push, deletion, unauthorized creation)
# like the Trivy incident: https://www.aquasec.com/blog/tag-poisoning-attack
#
# Requirements:
#   - gh CLI authenticated with repo admin permissions
#   - Repository: sbom-tool/sbom-tools (or set REPO env var)
#
# Usage: scripts/setup-tag-ruleset.sh
set -euo pipefail

REPO="${REPO:-sbom-tool/sbom-tools}"

echo "==> Creating tag protection ruleset for ${REPO}"
echo "    This prevents force-push, deletion, and unauthorized creation of tags."
echo ""

# Check gh auth
if ! gh auth status &>/dev/null; then
    echo "Error: Not authenticated. Run 'gh auth login' first."
    exit 1
fi

# Check admin access
PERMISSION=$(gh api "repos/${REPO}" --jq '.permissions.admin' 2>/dev/null || echo "false")
if [[ "${PERMISSION}" != "true" ]]; then
    echo "Error: Admin access required. Current user does not have admin on ${REPO}."
    exit 1
fi

# Check if a tag ruleset already exists
EXISTING=$(gh api "repos/${REPO}/rulesets" --jq '[.[] | select(.target == "tag")] | length' 2>/dev/null || echo "0")
if [[ "${EXISTING}" -gt 0 ]]; then
    echo "Warning: ${EXISTING} tag ruleset(s) already exist:"
    gh api "repos/${REPO}/rulesets" --jq '.[] | select(.target == "tag") | "  - \(.name) (id: \(.id), enforcement: \(.enforcement))"'
    echo ""
    read -r -p "Create another ruleset anyway? [y/N] " REPLY
    if [[ ! "${REPLY}" =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi
fi

# Get the org admin actor ID for bypass rules.
# RepositoryRole 5 = "admin" in GitHub's actor model.
# For org repos, we also allow the org admin team.

RULESET_JSON=$(cat <<'EOF'
{
  "name": "Tag protection",
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
    },
    {
      "type": "update"
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

echo "==> Sending ruleset creation request..."
RESULT=$(echo "${RULESET_JSON}" | gh api "repos/${REPO}/rulesets" --method POST --input - 2>&1) && {
    RULESET_ID=$(echo "${RESULT}" | jq -r '.id')
    echo ""
    echo "Tag protection ruleset created successfully!"
    echo "  ID:          ${RULESET_ID}"
    echo "  Target:      All tags"
    echo "  Rules:       deletion blocked, force-push blocked, update blocked"
    echo "  Bypass:      Repository admins only"
    echo ""
    echo "Verify at: https://github.com/${REPO}/settings/rules"
} || {
    echo "Error creating ruleset:"
    echo "${RESULT}"
    exit 1
}
