#!/usr/bin/env sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 vX.Y.Z"
  exit 1
fi

TAG="$1"

case "$TAG" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *)
    echo "Tag must match vX.Y.Z"
    exit 1
    ;;
esac

git fetch origin
git checkout main
git pull --rebase origin main
git tag -a "$TAG" -m "Release $TAG"
git push origin "$TAG"

echo "Release tag $TAG created and pushed."
