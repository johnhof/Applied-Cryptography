all:
	javac -cp .:bcprov-jdk15on-147.jar *.java

setup:
	java -cp .:bcprov-jdk15on-147.jar ResourceGenerator

runGroup:
	java -cp .:bcprov-jdk15on-147.jar RunGroupServer

runFile:
	java -cp .:bcprov-jdk15on-147.jar RunFileServer

UI:
	java -cp .:bcprov-jdk15on-147.jar UI
	
clean:
	rm -r *.class *_Resources* shared_files
