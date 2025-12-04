.PHONY: migrate-create migrate-up migrate-down migrate-status migrate-drop sqlc artisan fmt lint test build ci

# ====================================================================================
# Development Workflow Notes
# ====================================================================================
# 當前開發流程：由於 docker-compose 未使用 volumes 掛載本機 code，而是直接複製到 container
# 因此開發流程為：本機編輯 -> docker compose up --build -> 在 container 中測試
#
# 指令分類：
# 1. migrate-* / sqlc: 在 container 中執行，直接影響 container 環境
# 2. fmt / lint / test / build / ci: 在本機執行，輔助本機開發
#
# 未來計畫：待 HPB-214 (熱重載) 完成後，將統一遷移至完全容器化開發模式
# 屆時所有開發指令都將在 container 中執行，確保環境一致性
# ====================================================================================

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

# ====================================================================================
# Artisan Commands (CLI 工具指令)
# ====================================================================================
# artisan: 在 container 中執行 CLI 工具（推薦）
# artisan-local: 在本機執行 CLI 工具（需要本機有 DATABASE_URL）
#
# 使用範例：
#   make artisan make:user
# ====================================================================================

artisan:
	@$(COMPOSE_CMD) exec backend go run cmd/artisan/main.go $(name)

# 讓 make 不會把後面的參數當作 target
%:
	@:

# ====================================================================================
# Local Development Commands (本機開發指令)
# ====================================================================================
# 以下指令在本機環境執行，用於輔助開發但不影響 container 中的 code
#
# 原因：目前無法使用 volumes 掛載，因此 container 中的修改不會同步到本機
# 這些指令主要用於本機開發時的程式碼檢查與測試
#
# 注意：待 HPB-214 完成後，這些指令將改為在 container 中執行
# ====================================================================================

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