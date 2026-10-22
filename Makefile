.PHONY: test lint deb rpm demo checks-doc clean
test:
	python3 -m unittest discover -s tests -t . -v
lint:
	python3 -m pyflakes fleetguard tests plugins
	shellcheck packaging/*.sh tests/*.sh
deb:
	sh packaging/build-deb.sh dist
rpm:
	sh packaging/build-rpm.sh dist
demo:
	python3 examples/make_demo.py /tmp/fg-demo
	FLEETGUARD_STATE=/tmp/fg-demo python3 -m fleetguard serve
checks-doc:
	python3 docs/gen_checks.py
clean:
	rm -rf dist build *.egg-info
