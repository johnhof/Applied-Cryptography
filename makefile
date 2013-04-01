all:
	javac -cp .:bcprov-jdk15on-147.jar *.java
	
clean:
	rm -r *.class *_Resources*
