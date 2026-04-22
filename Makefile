.PHONY: fmt check test help \
	package-linux package-linux-deb package-linux-rpm \
	package-windows package-windows-msi package-all

help:
	@printf '%s\n' \
		'fmt                  Run cargo fmt --all' \
		'check                Run cargo check --workspace' \
		'test                 Run cargo test --workspace' \
		'package-linux        Build Linux DEB/RPM packages via the configured Linux build host' \
		'package-linux-deb    Alias of package-linux; downloads the DEB artifact locally' \
		'package-linux-rpm    Alias of package-linux; downloads the RPM artifact locally' \
		'package-windows      Alias of package-windows-msi' \
		'package-windows-msi  Build the Windows MSI via the configured Windows build host' \
		'package-all          Build Linux and Windows installer packages'

fmt:
	cargo fmt --all

check:
	cargo check --workspace

test:
	cargo test --workspace

package-linux:
	./scripts/linux-package-build.sh

package-linux-deb: package-linux

package-linux-rpm: package-linux

package-windows: package-windows-msi

package-windows-msi:
	./scripts/windows-package-build.sh

package-all: package-linux package-windows-msi
