# light-encryptor
A command line utility to encrypt plain text secret into a string with prefix CRYPT

Most light-4j modules have a config file, and it might contain sensitive values that cannot be checked into the git repository in plain text. Users can use this command line utility to encrypt the sensitive value and check into the repository. During the runtime, the [Decryptor](https://doc.networknt.com/concern/decryptor/) class defined in the [config.yml](https://github.com/networknt/light-4j/blob/master/config/src/main/resources/config/config.yml) file will decrypt the encrypted text into plain text again. 


### Usage

The jar file has been released to maven central, and it can be downloaded from the following [Download URL](https://repo1.maven.org/maven2/com/networknt/light-encryptor/1.0.0/light-encryptor-1.0.0.jar). 

Or you can download it with curl in the command line. 

```
curl -k -o light-encryptor-1.0.0.jar https://repo1.maven.org/maven2/com/networknt/light-encryptor/1.0.0/light-encryptor-1.0.0.jar
```

If your organization has Artifactory installed to proxy the Maven Central libraries, the URL might look like the following. 

```
curl -k -o light-encryptor-1.0.0.jar https://artifactary.example.com/artifactory/Maven_Central/com/networknt/light-encryptor/1.0.0/light-encryptor-1.0.0.jar
```

To encrypt a secret with a master key named master-key

```
java -jar light-encryptor-1.0.0.jar "master-key" "secret"
```

When running the above command on Windows, enclose the plain text into double quotes("") in the command line above. 

The master key should be configured on the target server as an environment variable or -D option in the java command line to start the light-4j server. 

It is recommended to use the same master key for all the services belonging to the same application. Or use the same master key per DevOps engineer. 

To learn how to set up the master key on the deployment server, please refer to the [decryptor](https://doc.networknt.com/concern/decryptor/).


### Build

```
mvn clean install
```


### Release

```
mvn clean install deploy -DperformRelease
```



