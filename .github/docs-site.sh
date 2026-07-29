#!/bin/sh
# Stage the documentation site's sources into .docs-site/ (mkdocs.yml's docs_dir).
#
# The repo's markdown is written to be read on GitHub: the README is the landing
# page and links into docs/, and pages link to source files that have no page of
# their own. Rather than keep a second copy of any of it, this stages a build
# tree and rewrites those links — the ones into docs/ become site pages, the
# rest point back at the repo. Nothing here is a list to maintain: link targets
# are discovered from the files, and anything missed fails the build, since
# mkdocs runs with strict: true.
#
#   .github/docs-site.sh && mkdocs build     # or: mkdocs serve
#
# Re-run it after editing README.md or CHANGELOG.md; `mkdocs serve` watches
# .docs-site/, not the originals.
set -eu

out=.docs-site
blob=https://github.com/lncrawl/tor-pool/blob/main

rm -rf "$out"
mkdir -p "$out"
cp -R docs/. "$out"/

# The landing page. Its links are relative to the repo root, so the ones into
# docs/ are siblings once staged — including the screenshots, which are <picture>
# elements with the path in an attribute rather than a markdown link.
sed \
  -e 's|](docs/|](|g' \
  -e 's|"docs/|"|g' \
  -e 's|](CHANGELOG.md)|](changelog.md)|g' \
  README.md > "$out/index.md"

# Worth a page of its own: it is the release notes, and what the versions in
# operations.md's upgrade section refer to.
cp CHANGELOG.md "$out/changelog.md"

# docs/ pages reach source files and AGENTS.md with ../.
find "$out" -name '*.md' -exec sed -i.bak -e "s|](\.\./|]($blob/|g" {} +

# Whatever is left pointing at a path with no page here is a repo file: the
# README's and changelog's root-relative links, and any ../ target that survived
# the rule above. Rewriting only paths that exist keeps a typo a build failure
# rather than a link to a 404.
for page in "$out"/*.md; do
  for target in $(grep -oE '\]\([^)]+\)' "$page" | sed -e 's/^](//' -e 's/)$//' | sort -u); do
    case $target in
      http*|'#'*|mailto:*) continue ;;
    esac
    [ -e "$out/$target" ] && continue
    [ -e "$target" ] || continue
    quoted=$(printf '%s' "$target" | sed 's/[].[^$*\/]/\\&/g')
    sed -i.bak "s|](${quoted})|](${blob}/${target})|g" "$page"
  done
done

find "$out" -name '*.bak' -delete

echo "staged $out"
