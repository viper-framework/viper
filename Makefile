PWD = $(shell pwd)

clean:
	rm -rf $(PWD)/build $(PWD)/dist $(PWD)/*.egg-info

dist:
	python3 setup.py sdist bdist_wheel

upload:
	python3 -m twine upload dist/*

test-upload:
	python3 -m twine upload --repository-url https://test.pypi.org/legacy/ dist/*
