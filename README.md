# 快樂小夥伴後端專案

## 常用指令說明

我們會使用 Makefile 管理相關指令，確保大家使用的指令皆為一致。

本段落僅說明目前大概有哪些指令可以使用，詳細指令請自行去 Makefile 查閱，一切以 Makefile 為準。

- Migration: 我們目前使用 `golang-migrate/migrate` 來管理 Table Schema，如果要建立 Migration 請使用相關指令，可參考[官方文件](https://github.com/golang-migrate/migrate?tab=readme-ov-file)。
- sqlc: 我們目前使用 `sqlc-dev/sqlc` 來產生查詢式。使用上可以先在 `db/queries/` 資料夾裡面寫好 Query，然後使用 `make sqlc` 產生查詢式。
- fmt: 使用 gofumpt 格式化程式碼。
- lint: 使用 golangci-lint 檢查程式碼品質。
- test: 執行測試（包含 race detection）。
- build: 建置 Go 程式。
- ci: 平行執行 test、lint、build 三個檢查。

## 本機開發流程
建議在提交 PR 前，依序執行以下指令：

1. `make fmt`
2. `sqlc generate`
3. `make ci` 確認一切無誤
4. `docker compose up --build` 測試，確認一切無誤

## 專案架構說明

Reference: 
- https://github.com/golang-standards/project-layout

因目前正在開發中，以下專案架構僅提供參考。若有發現任何問題，歡迎提出討論。
```bash
.
├── cmd/
│   └── server/
│       └── main.go             # 程式進入點：初始化, logger, db, 啟動 server
├── internal/
│   ├── /api            # API 層 (Gin)
│   │   ├── handler.go      # Gin 路由和 Handler 綁定
│   │   ├── user_handler.go # 處理 /users 相關的 HTTP 請求
│   │   └── middleware.go   # 中間件 (auth, logging)
│   │
│   ├── config/                 # 設定檔讀取 (e.g., Viper)
│   │
│   ├── /db             # 【sqlc】自動生成的 Go 程式碼
│   │   ├── db.go
│   │   ├── models.go
│   │   └── user.sql.go
│   │
│   ├── domain/                 # 1. 核心層：Domain (或稱 Entity)
│   │   ├── user.go             # 核心業務物件 (純 struct，不應有 json, sql 等 tag)
│   │   └── ...
│   │
│   ├── /repository     # 資料存取層 (Data Access Layer)
│   │   ├── repository.go   # 定義 Repository 介面 (Interface)
│   │   └── user_repo.go      # PostgreSQL 的 Repository 實作 (包裹 sqlc)
│   │
│   └── /service        # 業務邏輯層 (Business Logic)
│       ├── service.go      # 定義 Service 介面
│       └── user_service.go # User 相關的業務邏輯
│
├── pkg/                        # 可被外部專案引用的共用庫 (e.g., logger, validator)
│   ├── logger/
│   └── validator/
│
├── /sql                # SQL 檔案
│   ├── /migrations     # 資料庫遷移 (Migration) 檔案
│   │   └── 001_init.sql
│   ├── /queries        # 【sqlc】讀取的 SQL 查詢
│       └── user.sql
│
├── go.mod
├── go.sum
├── .gitignore
├── Dockerfile
└── README.md
```

## Coding Style

在實作時，若對 Coding Style 有疑慮，建議先以以下三份文件為主：
- [Effective Go](https://go.dev/doc/effective_go)
- [Go Style](https://google.github.io/styleguide/go/index)
- [Twelve Go Best Practices](https://go.dev/talks/2013/bestpractices.slide)

實際在 Code Review 時，建議也以文件當作 Review 的依據。在初期應避免參雜過多個人主觀意見。