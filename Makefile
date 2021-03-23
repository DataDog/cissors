##@ Development

all: build test ## Build test

build: manager kubectl-datadog ## Builds manager + kubectl plugin

fmt: ## Run go fmt against code
	go fmt ./...

vet: ## Run go vet against code
	go vet ./...

gotest:
	go test ./... -coverprofile cover.out


.PHONY: license
license: bin/wwhrd vendor
	./hack/license.sh

.PHONY: verify-license
verify-license: bin/wwhrd vendor ## Verify licenses
	./hack/verify-license.sh

.PHONY: tidy
tidy: ## Run go tidy
	go mod tidy -v

.PHONY: vendor
vendor: ## Run go vendor
	go mod vendor

bin/wwhrd:
	./hack/install-wwhrd.sh 0.2.4
