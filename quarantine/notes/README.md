# Quarantine rationale notes

Every entry in `quarantine/policy.json` requires a sibling Markdown file in
this directory named `<package>@<version>.md` (scoped packages use
`@scope__name@version.md` so the slash does not collide with the filesystem).

The `apiary-quarantine validate` CLI fails if any policy entry lacks a note
or if any note is orphaned. Wire it into a git pre-commit hook.
