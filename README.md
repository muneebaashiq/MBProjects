# MBProjects

## Task Given: 
1. Build benchmark Maven and Gradle applications with the Java packages provided.
2. Use the same components for the applications’ vulnerable and non-vulnerable parts just with different versions 

## Approach To Task: 
1. First, I found out the components from the data given along with the versions that had vulnerabilities and the ones in which these vulnerabilities had been patched.
2. Although the patched components have their own vulnerabilities, they do not include the vulnerabilities that the unpatched versions include.
3. Then I made 4 separate projects in total.
4. The Maven project was divided into its vulnerable and non-vulnerable parts.
5. The same thing was done for the Gradle projects. 

## Human Analysis: 
The following are a few of the CVEs I expect to be present in the non-vulnerable versions of the projects. 

They are in the form: 
CVE Score Explanation 

 

### com.thoughtworks.xstream:xstream:1.4.18  

CVE-2021-43859 7.5 Uncontrolled Resource Consumption vulnerability  
CVE-2022-40151 7.5 Out-of-bounds Write vulnerability  
CVE-2022-40152 7.5 Out-of-bounds Write vulnerability  
CVE-2022-41966 7.5 Deserialization of Untrusted Data vulnerability 

### org.elasticsearch:elasticsearch:7.9.1  

CVE-2021-22134 4.3 Exposure of Sensitive Information to an Unauthorized Actor vulnerability 
CVE-2021-22132 4.8 Insufficiently Protected Credentials vulnerability  
CVE-2020-7021 4.9 Insertion of Sensitive Information into Log File vulnerability  
CVE-2020-7020 3.1 Improper Privilege Management vulnerability  
CVE-2021-22135 5.3 Exposure of Sensitive Information to an Unauthorized Actor vulnerability  
CVE-2021-22144 6.5 Uncontrolled Recursion vulnerability  
CVE-2021-22137 5.3 Exposure of Sensitive Information to an Unauthorized Actor vulnerability  
CVE-2021-22146 7.5 Exposure of Resource to Wrong Sphere vulnerability 
CVE-2023-31419 7.5 Out-of-bounds Write vulnerability with High severity found 
CVE-2023-46673 7.5 Improper Handling of Exceptional Conditions vulnerability with High severity found 

### com.liferay.portal:release.portal.bom:7.3.6 

CVE-2022-39975 4.3 Missing Authorization vulnerability 
 
### io.undertow:undertow-core:2.2.6.Final  

CVE-2021-3629 5.9 Uncontrolled Resource Consumption vulnerability  
CVE-2021-3597 5.9 Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') vulnerability  
CVE-2021-3859 7.5 Exposure of Resource to Wrong Sphere vulnerability  
CVE-2021-3690 7.5 Uncontrolled Resource Consumption vulnerability  
CVE-2022-2053 7.5 Uncontrolled Resource Consumption vulnerability  
CVE-2022-1319 7.5 Unchecked Return Value vulnerability  
CVE-2022-2764 4.9 Uncontrolled Resource Consumption vulnerability  
CVE-2022-4492 7.5 Improper Certificate Validation vulnerability  
CVE-2023-1108 7.5 Uncontrolled Resource Consumption vulnerability 

### org.apache.tomcat.embed:tomcat-embed-core:9.0.78  

CVE-2023-24998 7.5 Allocation of Resources Without Limits or Throttling vulnerability  
CVE-2023-41080 6.1 URL Redirection to Untrusted Site ("Open Redirect") vulnerability with Medium severity found  
CVE-2023-45648 5.3 Improper Input Validation vulnerability with Medium severity found  
CVE-2023-46589 7.5 Inconsistent Interpretation of HTTP Requests ("HTTP Request Smuggling") vulnerability with High severity found  
CVE-2023-42794 5.9 Incomplete Cleanup vulnerability with Medium severity found 

### org.keycloak:keycloak-parent:12.0.2 

CVE-2021-20222 7.5 Improper Input Validation vulnerability  
CVE-2020-27838 6.5 Improper Authentication vulnerability  
CVE-2021-20195 9.6 Improper Input Validation vulnerability  
CVE-2020-14302 4.9 Authentication Bypass by Capture-replay vulnerability Cx0bb7b9a7-4707 6.1 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability  
CVE-2021-3424 5.3 Improper Authentication vulnerability  
CVE-2021-3827 6.8 Improper Authentication vulnerability  
CVE-2022-1245 9.8 Missing Authorization vulnerability  
CVE-2021-3513 7.5 Generation of Error Message Containing Sensitive Information vulnerability 
CVE-2022-2256 3.8 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability Results powered by Checkmarx(c) 

### org.springframework:spring-core:5.3.10  

CVE-2021-22060 4.3 Improper Output Neutralization for Logs vulnerability  
CVE-2022-22950 6.5 Allocation of Resources Without Limits or Throttling vulnerability  
CVE-2021-22096 4.3 Improper Output Neutralization for Logs vulnerability  
CVE-2022-22970 5.3 Allocation of Resources Without Limits or Throttling vulnerability  
CVE-2022-22971 6.5 Allocation of Resources Without Limits or Throttling vulnerability  
CVE-2024-22233 7.5 Uncontrolled Resource Consumption vulnerability with High severity found 

### org.apache.nifi:nifi:1.14.0 

CVE-2022-26850 4.3 Insufficiently Protected Credentials vulnerability 
CVE-2022-29265 7.5 Improper Restriction of XML External Entity Reference vulnerability  
CVE-2022-33140 8.8 Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') vulnerability 

### org.eclipse.jetty:jetty-server:9.4.43.v20210629 

CVE-2022-2047 2.7 Improper Input Validation vulnerability  
CVE-2023-26048 5.3 Allocation of Resources Without Limits or Throttling vulnerability  
CVE-2023-26049 5.3 Exposure of Sensitive Information to an Unauthorized Actor vulnerability 

### com.fasterxml.woodstox:woodstox-core:6.2.4  

CVE-2022-40151 7.5 Out-of-bounds Write vulnerability  
CVE-2022-40152 7.5 Out-of-bounds Write vulnerability 

### org.springframework.security:spring-security-core:5.5.3  

CVE-2022-22976 5.3 Integer Overflow or Wraparound vulnerability 

### org.keycloak:keycloak-services:12.0.2 

CVE-2020-27838 6.5 Improper Authentication vulnerability  
CVE-2021-20202 7.3 Insecure Temporary File vulnerability  
CVE-2020-14302 4.9 Authentication Bypass by Capture-replay vulnerability  
CVE-2021-4133 8.8 Incorrect Authorization vulnerability  
CVE-2021-3461 7.1 Insufficient Session Expiration vulnerability  
CVE-2021-3424 5.3 Improper Authentication vulnerability  
CVE-2021-3827 6.8 Improper Authentication vulnerability  
CVE-2022-1245 9.8 Missing Authorization vulnerability  
CVE-2021-3513 7.5 Generation of Error Message Containing Sensitive Information vulnerability 
CVE-2021-3632 7.5 Improper Authentication vulnerability 

### org.apache.shiro:shiro-core:1.9.0  

CVE-2022-32532 9.8 Incorrect Authorization vulnerability 
CVE-2022-40664 9.8 Improper Authentication vulnerability 

### org.bouncycastle:bcprov-jdk14:1.70  

CVE-2023-33201 5.3 Improper Certificate Validation vulnerability with Medium severity found 

### org.apache.activemq:activemq-client:5.16.0  

CVE-2023-46604 9.8 Deserialization of Untrusted Data vulnerability with High severity found 
### org.apache.dubbo:dubbo:2.7.10 

CVE-2021-36161 9.8 Use of Externally-Controlled Format String vulnerability  
CVE-2021-36162 8.8 Improper Control of Generation of Code ('Code Injection') vulnerability  
CVE-2021-36163 9.8 Deserialization of Untrusted Data vulnerability  
CVE-2021-37579 9.8 Deserialization of Untrusted Data vulnerability 
CVE-2021-43297 9.8 Deserialization of Untrusted Data vulnerability  
CVE-2022-24969 6.1 Server-Side Request Forgery (SSRF) vulnerability  
CVE-2022-39198 9.8 Deserialization of Untrusted Data vulnerability  
CVE-2023-23638 9.8 Deserialization of Untrusted Data vulnerability 

### org.apache.jspwiki:jspwiki-main:2.11.0.M8 

CVE-2021-44140 9.1 Incorrect Default Permissions vulnerability  
CVE-2021-40369 6.1 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability  
CVE-2022-24947 8.8 Cross-Site Request Forgery (CSRF) vulnerability  
CVE-2022-24948 6.1 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability CVE-2022-27166 6.1 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability  
CVE-2022-28732 6.1 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability CVE-2022-46907 6.1 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability 

### org.apache.hadoop:hadoop-common:3.3.1  

CVE-2022-26612 9.8 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability  
CVE-2021-37404 9.8 Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') vulnerability  
CVE-2022-25168 9.8 Improper Neutralization of Argument Delimiters in a Command ('Argument Injection') vulnerability  

### org.apache.jspwiki:jspwiki-war:2.11.0.M8   

CVE-2022-27166 6.1 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability  
CVE-2022-28731 6.5 Cross-Site Request Forgery (CSRF) vulnerability  
CVE-2022-34158 8.8 Cross-Site Request Forgery (CSRF) vulnerability  
CVE-2022-46907 6.1 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability 

### com.vaadin:flow-server:6.0.6  

CVE-2021-31412 5.3 Exposure of Resource to Wrong Sphere vulnerability 
CVE-2021-33604 2.5 Encoding Error vulnerability  
CVE-2023-25500 4.3 Exposure of Sensitive Information to an Unauthorized Actor vulnerability with Medium severity found 

### org.apache.cxf:cxf-core:3.4.7  

CVE-2022-46364 9.8 Server-Side Request Forgery (SSRF) vulnerability 

### org.apache.hadoop:hadoop-main:3.3.5 

CVE-2022-46364 9.8 Server-Side Request Forgery (SSRF) vulnerability 
 
