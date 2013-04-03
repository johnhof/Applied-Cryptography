all:
	rm -rf bin
	mkdir bin
	javac -cp .:bcprov-jdk15on-147.jar -d bin *.java


setup:
	java -cp bcprov-jdk15on-147.jar:./bin ResourceGenerator

runGroup:
	java -cp .:bcprov-jdk15on-147.jar:./bin RunGroupServer

runFile:
	java -cp .:bcprov-jdk15on-147.jar:./bin RunFileServer

ui:
	java -cp .:bcprov-jdk15on-147.jar:./bin UI
	
UI:
	java -cp .:bcprov-jdk15on-147.jar:./bin UI
	
clean:
	rm -r *.class *_Resources* shared_files bin/
