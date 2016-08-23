These jars are the ones used/produced by the Java project in https://github.com/google/certificate-transparency:

 ctlog-jdk6-0605d35.jar
 guava-16.0.1.jar
 httpclient-4.2.5.jar
 httpcore-4.2.4.jar
 json-simple-1.1.1.jar
 protobuf-java-2.4.1.jar

You need to get these jars and put then in the current folder before building EJBCA. The procedure to get these jars in Windows is shown below.

Prerequisites
-------------

- Ant (tested with version 1.9.5).
- Java 6 or 7 (tested with version 1.7.0_76).
- Git
- Download https://github.com/google/protobuf/releases/download/v2.4.1/protoc-2.4.1-win32.zip and place protoc.exe in the PATH variable.

Procedure
---------

1. From any folder outside of 'ejbca-custom/': git clone https://github.com/google/certificate-transparency.git
2. cd certificate-transparency/
3. git checkout 0605d35
4. ant release
5. Finally copy the JARs to the folder containing this 'readme.txt':
 copy java\build\distrib\ctlog.jar ...\ejbca-custom\lib\ct\ctlog-jdk6-0605d35.jar
 copy java\libs\guava-16.0.1.jar ...\ejbca-custom\lib\ct\
 copy java\libs\httpclient-4.2.5.jar ...\ejbca-custom\lib\ct\
 copy java\libs\httpcore-4.2.4.jar ...\ejbca-custom\lib\ct\
 copy java\libs\json-simple-1.1.1.jar ...\ejbca-custom\lib\ct\
 copy java\libs\protobuf-java-2.4.1.jar ...\ejbca-custom\lib\ct\
6. Now you can delete the 'certificate-transparency/' folder.