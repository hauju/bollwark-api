default:
    @just --list

# Build the project
build:
    cargo build

# Build in release mode
release:
    cargo build --release

# Run the server
serve:
    cargo run

# Run all tests
test:
    cargo test

# Run unit tests only
test-unit:
    cargo test --lib

# Run integration tests only
test-integration:
    cargo test --test api_integration

# Run a specific test by name
test-one NAME:
    cargo test {{ NAME }}

# Check compilation without building
check:
    cargo check

# Run clippy lints
lint:
    cargo clippy -- -D warnings

# Format code
fmt:
    cargo fmt

# Check formatting without modifying
fmt-check:
    cargo fmt -- --check

# Run clippy + format check
ci: fmt-check lint test
