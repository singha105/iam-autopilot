# IAM Least-Privilege Autopilot
#
# Nothing here auto-approves a change to AWS: `plan` writes tfplan, you read it,
# and `apply` applies exactly that saved plan. `destroy` is interactive.

SHELL      := /bin/bash
TF_DIR     := infra/terraform
BUILD_DIR  := build
CMDS       := $(notdir $(wildcard cmd/*))
# -buildvcs=false: no git revision in the binary, so an unrelated commit does not
# change the zip hash and make Terraform redeploy every function.
GOFLAGS_LAMBDA := -trimpath -buildvcs=false -tags lambda.norpc -ldflags "-s -w"

.PHONY: all build test lint tf-fmt tf-validate check plan apply traffic cost-audit destroy clean help catalog rollout status quarter-end

all: check

help:
	@echo "build        Build every cmd/* for linux/arm64 into build/<name>/bootstrap"
	@echo "test         go test ./... -race"
	@echo "lint         go vet and gofmt check"
	@echo "tf-fmt       terraform fmt -check -recursive"
	@echo "tf-validate  terraform init -backend=false && terraform validate"
	@echo "check        lint + test + tf-fmt + tf-validate (no AWS calls)"
	@echo "plan         build, then terraform plan -out=tfplan"
	@echo "apply        terraform apply tfplan (the saved plan only)"
	@echo "traffic      invoke each demo Lambda 5 times"
	@echo "cost-audit   fail if any forbidden resource type exists"
	@echo "destroy      terraform destroy (interactive)"
	@echo "catalog      re-download the IAM action catalog into internal/catalog/data/actions.json"
	@echo "rollout      start a rollout: make rollout ROLE=<roleName>"
	@echo "status       list rollouts (autopilot report --short)"
	@echo "quarter-end  invoke iamap-demo-quarterly in its rare quarter-end mode (the Day 6 rollback demo)"

build: $(addprefix $(BUILD_DIR)/,$(addsuffix /bootstrap,$(CMDS)))

# The Lambda binaries live under cmd/; internal/catalog/gen is a dev tool, not deployed.
# Always rebuild: Go's own cache makes this cheap and avoids stale binaries.
$(BUILD_DIR)/%/bootstrap: FORCE
	@mkdir -p $(dir $@)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(GOFLAGS_LAMBDA) -o $@ ./cmd/$*

FORCE:

test:
	go test ./... -race

lint:
	go vet ./...
	@unformatted="$$(gofmt -l cmd internal)"; \
	if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi

tf-fmt:
	terraform -chdir=$(TF_DIR) fmt -check -recursive

tf-validate:
	terraform -chdir=$(TF_DIR) init -backend=false -input=false >/dev/null
	terraform -chdir=$(TF_DIR) validate

check: lint test tf-fmt tf-validate

plan: build
	terraform -chdir=$(TF_DIR) init -input=false >/dev/null
	terraform -chdir=$(TF_DIR) plan -input=false -out=tfplan

apply:
	@test -f $(TF_DIR)/tfplan || { echo "no saved plan: run 'make plan' and review it first"; exit 1; }
	terraform -chdir=$(TF_DIR) apply -input=false tfplan
	@rm -f $(TF_DIR)/tfplan

traffic:
	./scripts/traffic.sh

cost-audit:
	./scripts/cost-audit.sh

destroy:
	terraform -chdir=$(TF_DIR) destroy

# Start one rollout of the state machine. ROLE is validated before it goes
# into the JSON input.
rollout:
	@[[ "$(ROLE)" =~ ^[A-Za-z0-9+=,.@_-]+$$ ]] || { echo "usage: make rollout ROLE=<roleName>"; exit 1; }
	@sm=$$(terraform -chdir=$(TF_DIR) output -raw state_machine_arn) && \
	region=$${AWS_REGION:-us-east-1} && \
	exec=$$(aws stepfunctions start-execution --region "$$region" --state-machine-arn "$$sm" \
	  --input "$$(jq -cn --arg r '$(ROLE)' '{roleName: $$r}')" --query executionArn --output text) && \
	echo "execution: $$exec" && \
	echo "console:   https://$$region.console.aws.amazon.com/states/home?region=$$region#/v2/executions/details/$$exec"

status:
	@go run ./cmd/autopilot report --short

# The rare code path: ssm:GetParametersByPath. Fails (exit 1) if the function
# returns an error, which is what a tightened policy should cause.
quarter-end:
	@out=$$(mktemp) && \
	err=$$(aws lambda invoke --region $${AWS_REGION:-us-east-1} --function-name iamap-demo-quarterly \
	  --cli-binary-format raw-in-base64-out --payload '{"mode":"quarter-end"}' "$$out" \
	  --query FunctionError --output text) && \
	echo "$$(date -u +%H:%M:%SZ) quarter-end: $$(cat $$out)"; rm -f "$$out"; \
	if [ "$$err" != "None" ]; then echo "quarter-end FAILED ($$err)"; exit 1; fi

catalog:
	go run ./internal/catalog/gen -out internal/catalog/data/actions.json

clean:
	rm -rf $(BUILD_DIR) $(TF_DIR)/tfplan
