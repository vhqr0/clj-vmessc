clean:
	clj -T:build clean

build:
	clj -T:build uber

run:
	java -jar target/*-standalone.jar
