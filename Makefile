all: build

build:
	python setup.py build

install:
	python setup.py install --record installed_files.txt
	mkdir -p /usr/share/viper
	cp -rf data/* /usr/share/viper
	cp viper.conf.sample /usr/share/viper/viper.conf.sample

uninstall:
	cat installed_files.txt | xargs rm -rf
	rm installed_files.txt
	rm -rf /usr/share/viper /etc/viper

dist:
	python setup.py sdist

clean:
	find . -type f -iname '*.pyc' -delete
	find . -type d -iname "__pycache__" -delete
	rm -rf dist build viper.egg-info
