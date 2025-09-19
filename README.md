# 快樂小夥伴後端專案

## 常用指令說明

我們會使用 Makefile 管理相關指令，確保大家使用的指令皆為一致。

本段落僅說明目前大概有哪些指令可以使用，詳細指令請自行去 Makefile 查閱，一切以 Makefile 為準。

- Migration: 我們目前使用 `golang-migrate/migrate` 來管理 Table Schema，如果要建立 Migration 請使用相關指令，可參考[官方文件](https://github.com/golang-migrate/migrate?tab=readme-ov-file)。
- sqlc: 我們目前使用 `sqlc-dev/sqlc` 來產生查詢式。使用上可以先在 `db/queries/` 資料夾裡面寫好 Query，然後使用 `make sqlc` 產生查詢式。