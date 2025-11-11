.PHONY: migrate-create migrate-up migrate-down migrate-status migrate-drop sqlc fmt lint test build ci seed

COMPOSE_CMD = docker-compose \
    --env-file ../../.env \
    -f ../../docker-compose.yml \

name = $(filter-out $@,$(MAKECMDGOALS))

migrate-create:
	@$(COMPOSE_CMD) exec backend migrate create -ext sql -dir /app/db/migrations -seq $(name)

migrate-up:
	@$(COMPOSE_CMD) exec backend sh -c 'migrate -path /app/db/migrations -database "$$DATABASE_URL" -verbose up'

# 預設 Rollback 1 步
n ?= 1
migrate-down:
	@$(COMPOSE_CMD) exec backend sh -c 'migrate -path /app/db/migrations -database "$$DATABASE_URL" -verbose down $(n)'

migrate-status:
	@$(COMPOSE_CMD) exec backend sh -c 'migrate -path /app/db/migrations -database "$$DATABASE_URL" version'

migrate-drop:
	@$(COMPOSE_CMD) exec backend sh -c 'migrate -path /app/db/migrations -database "$$DATABASE_URL" drop'

sqlc:
	@$(COMPOSE_CMD) exec backend sh -c 'sqlc generate'

fmt:
	@gofumpt -l -w .

lint:
	@golangci-lint run --config .golangci.yml

test:
	@go test -race ./...

build:
	@go build ./...

ci:
	@$(MAKE) -j 3 lint test build
	@echo "Lint, test and build checks passed!"

seed:
	@$(COMPOSE_CMD) exec -T backend go run /app/cmd/seed/main.go