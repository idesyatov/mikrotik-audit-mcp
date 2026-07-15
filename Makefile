# Makefile — wrappers around docker compose and the release flow.
# Rust is not required on the host: build/test/lint run inside the container.
# Requires: docker, docker compose, git, make. Recipes assume sh
# (Git Bash / WSL / Linux) — grep/sed are used to parse the version.

.DEFAULT_GOAL := help

RELEASE_BRANCH ?= master
# Crate version from Cargo.toml — must match the numeric part of the release tag.
CARGO_VERSION := $(shell grep -m1 '^version' Cargo.toml | sed -E 's/.*"(.*)".*/\1/')

.PHONY: help build dev test lint build-release check version clean release

help: ## Show the list of targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

build: ## Build the dev image
	docker compose build dev

dev: ## Interactive development (cargo watch)
	docker compose up dev

test: ## Run tests
	docker compose run --rm test

lint: ## fmt --check + clippy (-D warnings)
	docker compose run --rm lint

build-release: ## Release build of the binary in the container
	docker compose run --rm build-release

check: lint test ## Full pre-release check (same as CI)

version: ## Print the crate version from Cargo.toml
	@echo $(CARGO_VERSION)

clean: ## Remove containers and volumes (cargo/target caches)
	docker compose down -v

# One-command release (like ssl-watch): make release VERSION=v0.2.0
# Pushes the branch and the tag; pushing the tag triggers
# .github/workflows/release.yml, which builds binaries for 4 platforms and
# publishes them to a GitHub Release.
# The tag must match the version in Cargo.toml — bump and commit it first.
release: ## Release: make release VERSION=vX.Y.Z (branch + tag + push)
ifndef VERSION
	$(error VERSION is not set. Usage: make release VERSION=v$(CARGO_VERSION))
endif
	@set -e; \
	branch=$$(git rev-parse --abbrev-ref HEAD); \
	echo "Releasing $(VERSION) from $$branch"; \
	[ "$$branch" = "$(RELEASE_BRANCH)" ] || { echo "Not on $(RELEASE_BRANCH) (on $$branch). Switch first or set RELEASE_BRANCH."; exit 1; }; \
	[ "$(VERSION)" = "v$(CARGO_VERSION)" ] || { echo "Tag $(VERSION) != Cargo.toml version (v$(CARGO_VERSION)). Bump version in Cargo.toml and commit."; exit 1; }; \
	git diff --quiet && git diff --cached --quiet || { echo "Worktree is dirty. Commit changes first."; exit 1; }; \
	git rev-parse $(VERSION) >/dev/null 2>&1 && { echo "Tag $(VERSION) already exists."; exit 1; } || true; \
	git fetch origin; \
	git push origin $$branch; \
	git tag $(VERSION); \
	git push origin $(VERSION); \
	echo "Done. Watch: https://github.com/idesyatov/mikrotik-audit-mcp/actions"
