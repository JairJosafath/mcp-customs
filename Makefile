# The quality contract of this repository. CI runs `make check` on every pull
# request, or, when the Container's checks are BeforeRelease, `make check-light`
# there and `make check` before each release; agents and people run
# `make check` before every commit. `make help` lists the targets.
#
# Nothing here deploys, bootstraps or calls AWS: `synth` only writes
# CloudFormation into cdk.out/, one folder per tier, offline, without Docker
# or credentials, and `dist` copies it, flat, into dist/ for a release to
# carry; a `cloudFormation` deploy target ships it.

NAME := mcp-customs
BIN := node_modules/.bin
# cfn-lint, pinned, run through uv like every Python tool on the runner.
CFN_LINT := uvx cfn-lint==1.57.2
# The tiers synth builds, as infra/standard.ts names them.
TIERS := production development
# The CDK CLI offline and quiet: no telemetry, no notices fetched, no check
# for a newer CLI.
CDK := CDK_DISABLE_CLI_TELEMETRY=true CDK_DISABLE_VERSION_CHECK=true $(BIN)/cdk --no-notices

.DEFAULT_GOAL := help
.PHONY: help check check-light deps fmt fmt-check lint typecheck test synth cfn-lint dist clean
.PHONY: go-deps tidy-check go-fmt-check vet go-lint go-test demo-publish

help: ## List the targets.
	@awk 'BEGIN {FS = ":.*## "} /^[a-z-]+:.*## / {printf "  %-14s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

check: deps go-deps tidy-check fmt-check go-fmt-check lint vet go-lint typecheck go-test test synth cfn-lint ## Everything CI checks.

check-light: deps go-deps tidy-check fmt-check go-fmt-check lint vet go-lint typecheck ## check without the tests, which CI runs on each change with checks BeforeRelease.

deps: ## Install the exact packages in package-lock.json.
	npm ci --no-audit --no-fund

fmt: ## Format every file: Prettier, and gofumpt and goimports for Go.
	$(BIN)/prettier --write .
	cd src && golangci-lint fmt

fmt-check: ## Fail when a file is not formatted.
	$(BIN)/prettier --check .

lint: ## Lint with eslint.config.mjs, failing on any finding.
	$(BIN)/eslint --max-warnings 0 .

typecheck: ## Type-check with tsconfig.json.
	$(BIN)/tsc --noEmit

test: ## Run the stacks' assertions, which build the function.
	$(BIN)/vitest run

# The function is its own Go module in src/: node_modules/ holds stray .go
# files that would otherwise be part of it.
go-deps: ## Download the modules in src/go.mod.
	cd src && go mod download

tidy-check: ## Fail when go mod tidy would change src/go.mod or src/go.sum.
	cd src && go mod tidy -diff

go-fmt-check: ## Fail when the Go code is not formatted, showing the diff.
	cd src && golangci-lint fmt --diff

vet: ## Run go vet.
	cd src && go vet ./...

go-lint: ## Lint the Go code with .golangci.yml, failing on any finding.
	cd src && golangci-lint run

go-test: ## Run the function's tests with the race detector, never from the cache.
	cd src && go test -race -count=1 ./...

# A deploy target picks a tier's templates; a hand deploy names it the same
# way, `cdk deploy -c tier=production`, and is development when it doesn't.
synth: ## Write each tier's CloudFormation templates into cdk.out/<tier>/; fails on a CDK Nag finding.
	rm -rf cdk.out
	$(foreach tier,$(TIERS),$(CDK) synth --quiet -c tier=$(tier) -o cdk.out/$(tier) &&) true

# --include-checks I adds the informational checks the Standard wants:
# I3011, a stateful resource without a deletion policy, and I3013, one whose
# content expires without a set retention. W3005: CDK makes a function depend
# on its role and the role's policy, which it also references; cfn-lint calls
# the DependsOn redundant. It is harmless, and not ours to change.
cfn-lint: ## Lint the templates synth wrote, for both tiers.
	$(CFN_LINT) --include-checks I --ignore-checks W3005 -- $(foreach tier,$(TIERS),cdk.out/$(tier)/*.template.json)

# The release's files, what the gitea-release Deployment attaches to the tag's
# release: both tiers' assemblies, flat (infra/dist.ts says how). VERSION is
# accepted and unused; the tag is the version.
dist: deps synth ## Write both tiers' cloud assemblies, flat, into dist/ for a release.
	rm -rf dist
	$(BIN)/tsx infra/dist.ts dist $(TIERS)

clean: ## Remove what synth and dist wrote.
	rm -rf cdk.out dist

# The live rug pull: the stack serves the demo servers' versions itself,
# from its bucket's goproxy/ prefix, which no role of the stack may write
# (docs/runbook.md, "The demo proxy"). The one target that calls AWS, with
# the deployer's credentials; nothing else runs it. BUCKET, or else the
# bucket STACK outputs, receives the files; publishing an earlier version
# takes the later ones off.
STACK ?= $(NAME)
DEMO_PROXY_DIR := cdk.out/demo-proxy
demo-publish: ## Publish the demo servers' VERSION (v1.0.0 or v1.0.1) to the stack's Go module proxy; needs AWS credentials.
	@test -n "$(VERSION)" || { echo 'Name the version: make demo-publish VERSION=v1.0.1' >&2; exit 1; }
	rm -rf $(DEMO_PROXY_DIR)
	cd src && go run ./cmd/demopublish -version $(VERSION) -out ../$(DEMO_PROXY_DIR)
	bucket='$(BUCKET)'; \
	  if [ -z "$$bucket" ]; then bucket=$$(aws cloudformation describe-stacks --stack-name $(STACK) \
	    --query "Stacks[0].Outputs[?OutputKey=='ReportsBucketName'].OutputValue" --output text); fi; \
	  test -n "$$bucket" && aws s3 sync --delete $(DEMO_PROXY_DIR) "s3://$$bucket/goproxy/"
