.PHONY: migrate-create migrate-up migrate-down migrate-status migrate-drop

COMPOSE_CMD = docker-compose \
    --env-file ../.env \
    -f ../docker-compose.yml \
    -f ../docker-compose.dev.yml

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
