.PHONY: install demo test verify schema lint clean docker-demo

install:                ## Install all dependencies via Poetry
	poetry install

demo:                   ## Run the full end-to-end demo (one command)
	poetry run openwright demo

test:                   ## Run the test suite (incl. RFC 6962 vectors + AC-01..07)
	poetry run pytest

schema:                 ## (Re)generate the published JSON Schemas under schemas/
	poetry run openwright schema --kind event --out schemas/compliance_event/1.0.0/compliance_event.schema.json
	poetry run openwright schema --kind crosswalk --out schemas/crosswalk/1.0.0/crosswalk.schema.json

docker-demo:            ## Build the image and run the demo in a container
	docker build -t openwright:0.1.0 .
	docker run --rm openwright:0.1.0 demo

clean:                  ## Remove generated demo/ledger artifacts
	rm -rf openwright-demo openwright-ledger quickstart-ledger openwright-out

help:                   ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS=":.*?## "} {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'
