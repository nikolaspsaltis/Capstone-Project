# Release Cadence

## Versioning

Use semantic versioning:
- `MAJOR.MINOR.PATCH`
- Example milestones: `v0.2.0`, `v0.3.0`

## Cadence

- Create a release tag at each assessed milestone or major security feature set.
- Use patch releases for bug fixes between milestones.

## Release Checklist

1. Ensure `main` is green in GitHub Actions.
2. Run local checks:
   ```bash
   ruff check .
   black --check .
   pytest
   ```
3. Update docs/changelog.
4. Create and push tag:
   ```bash
   git tag -a vX.Y.Z -m "Release vX.Y.Z"
   git push origin vX.Y.Z
   ```
5. Verify GitHub Actions created a release from the tag.

## Key Rotation Reminder

Rotate `API_KEYS` and `JWT_SECRET` each milestone release (or sooner if exposed).
