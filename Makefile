build:
	clj -T:build uber

run:
	java -jar target/*-standalone.jar
