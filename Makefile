


updateGems:
	docker run --rm -v "$$PWD":/usr/src/app -w /usr/src/app ruby:2.1 bundle install

build:
	docker build -t ajmath/kube-labeler .

run: build
	docker run --rm --name kube-labeler ajmath/kube-labeler $(args)
