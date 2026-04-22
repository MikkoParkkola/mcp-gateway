.PHONY: install safe-clean clean force-clean

install:
	cargo build --release
	cargo install --path . --root ~/.local --force

safe-clean: install
	cargo clean

clean:
	@echo "WARNING: This removes ALL build artifacts including release binaries."
	@echo "Use 'make safe-clean' to install binaries first."
	@echo "Or 'make force-clean' to clean without installing."
	cargo clean

force-clean:
	cargo clean
