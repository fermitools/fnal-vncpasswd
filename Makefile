current_dir:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
version:=$(shell git describe --tags --abbrev=0)

_default:
	@mkdir -p build
	@echo "Perhaps you want:"
	@echo "mkdir build ; cd ./build && cmake .. && cmake --build . --verbose && make test"
sources:
	@echo "You found my koji hook"
	@tmpdir=$$(mktemp -d); \
	set -e; \
	git archive --format=tar --prefix=fnal-vncpasswd-$(version)/ HEAD > "$$tmpdir/src.tar"; \
	gzip --best -c "$$tmpdir/src.tar" > "$(current_dir)/fnal-vncpasswd-$(version).tar.gz"; \
	rm -rf "$$tmpdir"
srpm: sources
	@echo "You found my copr hook"
	rpmbuild -bs --define '_sourcedir $(current_dir)' --define '_srcrpmdir $(current_dir)/SRPMS' fnal-vncpasswd.spec
rpm: sources
	@echo "You found my 'just build it' hook"
	rpmbuild -bb --define '_rpmdir $(current_dir)/RPMS' --define '_builddir $(current_dir)/BUILD' --define '_sourcedir $(current_dir)' fnal-vncpasswd.spec
