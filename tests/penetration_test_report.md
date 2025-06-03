
  

# Penetration Testing Report

## Executive Summary

This report outlines the results of a security review carried out on our file sharing system at the end of May 2025. The purpose of this testing was to identify any weaknesses in the system before launch, ensuring that user data and files are kept safe from potential threats.

The testing identified a few areas that needed improvement. These included missing protections that help prevent malicious activity in web browsers, a weakness that could allow overly large files to crash the system, and some outdated software components that could pose a risk if left unaddressed. Importantly, we found no major flaws in the way the system handles logins, file permissions, or database security — the core areas responsible for keeping user information private.

All of the issues found during testing have since been addressed. The team has applied recommended fixes and improved several key areas to strengthen the platform. Going forward, regular security checks and updates will help maintain this improved level of protection.

## Key Findings

Below is a list of all major vunerabilities discovered during penetration testing.

**Missing Content Security Policy (CSP) Header**

-  **Location:** All server responses

-  **Technique used to find:** Automated header audit via OWASP ZAP and manual HTTP header inspection.
-  **Proof of Concept:** CSP header is completely absent from server responses, verified with curl and browser dev tools

-  **Likelihood of exploitation:** Medium

-  **Potential Impact:** Increased risk of cross-site scripting (XSS), injection via third-party script abuse

-  **Risk Assessment :** 6.1 - Medium (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

-  **Reccomendations:**
	- Implement a restrictive CSP header (e.g., `default-src 'self';`)
	- Avoid inline scripts and `eval()` to improve CSP enforcement

  

**No Clickjacking Protection**

-  **Location:** All server responses

-  **Technique used to find:** Automated header audit via OWASP ZAP and manual HTTP header inspection.

-  **Proof of Concept:** No `X-Frame-Options` or `Content-Security-Policy: frame-ancestors` header present

-  **Likelihood of exploitation:** Medium

-  **Potential Impact:** Users could be tricked into clicking malicious UI elements (UI redress attacks)

-  **Risk Assessment :** 5.4 - Medium (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N)

-  **Reccomendations:** 
	- Add `X-Frame-Options: DENY` or use `Content-Security-Policy: frame-ancestors 'none'`
  

**CORS Misconfiguration**

-  **Location:** API endpoints

-  **Technique used to find:** Automatic scan using OWASP ZAP

-  **Proof of Concept:** Unauthenticated endpoints allow `Access-Control-Allow-Origin: *`

-  **Likelihood of exploitation:** Medium

-  **Potential Impact:** Sensitive data exposure when combined with other flaws (e.g., weak API tokens)

-  **Risk Assessment : 5.3 - Medium (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

-  **Reccomendations:**
	-  Restrict CORS origins to known, trusted domains
    
	-   Remove wildcard access, especially on sensitive or authenticated endpoints
    
	-   Validate `Origin` headers server-side when returning CORS responses

  

**Improper File Size Validation**

-  **Location:** File upload endpoint (`/api/upload`)

-  **Technique used to find:** Manual tampering with `Content-Length` headers and oversized file submissions via Postman

-  **Proof of Concept:** Uploads exceeding 100MB cause internal server errors due to unhandled exceptions at the database level

-  **Likelihood of exploitation:** High — this can be easily exploited without authentication

-  **Potential Impact:** Denial of service or resource exhaustion on the backend; loss of data integrity

-  **Risk Assessment :** 7.5 High (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)

-  **Reccomendations:**

	- Enforce upload limits at the application layer using Flask’s `MAX_CONTENT_LENGTH`
	- Implement proper error handling and reject oversized requests with a 413 Payload Too Large response

  
**Vunerable Libraries**

-  **Location:** Backend Python dependencies

-  **Technique used to find:** Analysis using `pip-audit`

-  **Proof of Concept:** 12 known CVEs found across 5 packages (see full `pip-audit` output below)

-  **Likelihood of exploitation:** High, depending on attack surface exposure

-  **Potential Impact:** Known exploits could allow RCE, privilege escalation, or data leaks

-  **Risk Assessment :** High (CVSS scores ranged from 6.5–9.8 across packages)

-  **Reccomendations:**
	-   Update or replace vulnerable libraries with secure versions
	-   Integrate automated dependency scanning into CI/CD pipelines
	-   Maintain a regular update schedule and monitor CVE databases
  

## Engagement Summary

Penetration testing was conducted between 31/05/2025 and 01/06/2025, following the completion of all major project components. This timing allowed the development team an opportunity to address any identified vulnerabilities before submission.

  

The assessment was carried out under a zero-trust security model, operating on the assumption that neither client nor server components could be inherently trusted. Our approach combined automated vulnerability scanning with in-depth manual testing to ensure thorough coverage across the application surface. Vulnerabilities were identified, classified, and prioritised using OWASP guidelines and the CVSS v3.1 scoring system.

  

**Scope of Testing**

- Server-side API endpoints

- Authentication mechanisms

- File handling and permissions

- Database interactions

- Cryptographic implementations

  

## Testing Methodology

### Testing Tools

1.  **OWASP ZAP (Zed Attack Proxy)**

- Automated vulnerability scanning

- API endpoint testing

- Configuration: Full scan with maximum alert levels

  

2.  **Burp Suite Professional**

- API security testing

- Authentication bypass attempts

- Configuration: Intercepting proxy with active scanning

  

3.  **Postman**

- API endpoint testing

- Authentication flow testing

- Request/response analysis

- Custom test collections for automated testing

  

4.  **Wireshark**

- Network traffic analysis

- TLS/SSL implementation verification

- Data transmission security

- Configuration: Full packet capture during testing

  

### Manual Inspection

1. Code review of security-critical components

2. Cryptographic implementation analysis

3. Configuration security audit

4. Dependency vulnerability assessment

  

## Full Penetration Testing Results

  

### 1. Security Misconfiguration

  

#### Test Case: Server Configuration

**Description**: Analyzed server configuration through automated and manual analysis of HTTP headers, response behavior, and configuration settings.

  

**Testing Method**:

- Performed automated scanning with **OWASP ZAP** to identify server misconfigurations.

- Conducted manual inspection of HTTP response headers, CORS policies, and general security directive

  

**Findings**:

-  **Missing Content Security Policy (CSP)**: No CSP header was present, leaving the application more susceptible to XSS and injection attacks.

-  **CORS Misconfiguration**: The server allowed cross-domain requests from arbitrary origins on unauthenticated endpoints, which could allow data exposure under certain conditions.

-  **No Protection Against Clickjacking**: The application did not set `X-Frame-Options` or `Content-Security-Policy: frame-ancestors`, leaving it open to UI redress attacks.

-  **Missing HTTP Strict Transport Security (HSTS)**: The server did not enforce HTTPS-only access using HSTS, which weakens transport layer protection.

-  **Anti-MIME Sniffing Header Absent**: The `X-Content-Type-Options: nosniff` header was missing, increasing risk of MIME-based attacks in older browsers.

-  **Missing or Weak Cache-Control Headers**: Sensitive resources could be cached by browsers or intermediaries due to absent or loose cache-control settings.

  

**Protection Mechanisms**:

- Consider implementing a restrictive CSP header to limit executable sources

- Apply strict `Access-Control-Allow-Origin` rules, especially on sensitive routes.

- Use either `X-Frame-Options: DENY` or a CSP frame-ancestors directive.

- Add the `Strict-Transport-Security` header with appropriate max-age and subdomain directives.

- Set `X-Content-Type-Options: nosniff` on all responses.

- Apply `Cache-Control: no-store` or similar directives to sensitive endpoints and content.

  

### 2. Improper Input Validation

  

#### Test Case: File Size Validation Bypass

**Description:** Attempted to bypass file size restrictions through various methods including malformed requests and size manipulation.

**Testing Method**:

Used Postman to send files exceeding the 100MB limit

Attempted to manipulate Content-Length headers to bypass size restrictions

Tested with malformed multipart/form-data requests

Monitored server response and database behavior

  

**Finding**s:

- Files exceeding size limit cause server crashes instead of graceful rejection

- Size validation occurs only at database level, not application level

- Server accepts malformed requests without proper validation

- No proper error handling for oversized files

- Client-side size validation can be bypassed by manipulating request headers

  

**Protection Mechanisms:**

- Implement application-level file size validation before database interaction

- Configure Flask's MAX_CONTENT_LENGTH to match database constraints

- Add proper error handling for oversized files

- Implement request validation for Content-Length headers

- Add server-side validation independent of client-side checks

- Implement proper error responses instead of server crashes

- Add logging for failed upload attempts

  

### 3. Broken Authentication

  

#### Test Case: JWT Token Security

**Description**: Analyzed JWT implementation and token handling.

  

**Testing Method**:

- Used Burp Suite to analyze token structure

- Tested token invalidation and refresh mechanisms:

- Attempted to perform file uploads with a logged out user's token

- Attempted token manipulation to change the timestamp of a logged out user's token, and tries to fetch files from another user

- Attempted to resign manipulated tokens to pass integrity checks

  
  

**Findings**:

- When accessing files with a logged out user's token the request is rejected with message `'Token has been invalidated', 401`

- After changing the Issued At timestamp of an invalidated token, we recieve an error `Missing or malformed token`, as integrity checks fail

- TODO when we resign

  

**Protection Mechanisms**:

- Ensure that JWT_SECRET_KEY is properly configured

- Token signing is in place, to protect against token manipulation

- JWT_SECRET_KEY properly configured

- Token expiration and refresh mechanisms are properly configured

  

### 4. Broken Access Control

  

#### Test Case: File Permission Bypass

**Description:** Conducted comprehensive testing of the file access control system to identify potential permission bypass vulnerabilities.

  

**Testing Method:**

- Utilized Postman to simulate various access control scenarios

- Established two distinct user accounts with separate authentication tokens

- Created a test file under User 1's ownership

- Attempted unauthorized access using User 2's credentials

- Conducted horizontal privilege escalation testing by manipulating file access requests

  

**Findings:**

- System correctly enforced access controls with appropriate 403 Forbidden responses

- Robust permission verification system prevented unauthorized access attempts

- Owner-based access control mechanisms functioned as intended

- No Insecure Direct Object Reference (IDOR) vulnerabilities were identified

- Access control checks were consistently applied across all file operations

  

**Protection Mechanisms:**

- Multi-layered permission verification system in file access routes

- Strict owner validation in permission management system

- Comprehensive error handling for unauthorized access attempts

- Proper separation of user contexts and access rights

  

#### Test Case: Path Traversal

**Description:** Conducted comprehensive testing of path traversal vulnerabilities in file operations, focusing on attempts to access files from outside the designated uploads directory.

  

**Testing Method:**

- Used Postman to send crafted path traversal payloads to file endpoints

- Tested with various path traversal techniques targeting the uploads directory

- Tested with URL encoding variations

```

GET /api/files/../../uploads/other_user_file.txt

GET /api/files/..%2f..%2fuploads%2fother_user_file.txt

GET /api/files/..\..\uploads\other_user_file.txt

GET /api/files/....//....//uploads//other_user_file.txt

GET /api/files/%2e%2e%2f%2e%2e%2fuploads%2fother_user_file.txt

```

  

**Findings:**

- All path traversal attempts were properly blocked

- System correctly rejected attempts to access files outside the user's designated area in the uploads directory

  

**Protection Mechanisms:**

- Secure filename sanitisation using werkzeug.utils.secure_filename

- Proper file path construction using os.path.join is in place

- User-specific file path prefixes to prevent cross-user access

  

### 5. Cryptographic Issues

  

#### Test Case: File Encryption Implementation

TODO Client side encryption??

  

### 6. Injection

  

#### Test Case: SQL Injection in Login

**Description**: Conducted comprehensive testing of SQL injection vulnerabilities in authentication endpoints, focusing on login and password management functionality.

  

**Testing Method**:

- Manual testing with common SQL injection payloads such as

```

#Tested login endpoint with payloads

{

"username": "admin' OR '1'='1",

"password": "anything"

}

{

"username": "admin'--",

"password": "anything"

}

#Attempted to bypass password verification

{

"username": "valid_user",

"password": "' OR '1'='1"

}

```

- Tested database interaction points such as login, change password

  

**Findings**:

- No SQL injection vulnerabilities found

- Proper use of parameterized queries

- Input sanitization in place

  

**Protection Mechanisms**:

- SQLAlchemy ORM usage

- Parameterized queries

- Input validation

  

#### Test Case: SQL Injection in File Queries

**Description**: Conducted testing of common SQL injections when retrieving files, in attempt to retrieve another users file

  

**Testing Method**:

- Manual testing with common SQL injections in the url

```

GET /api/files/1' OR '1'='1

GET /api/files/1'--

GET /api/files/1' OR 1=1--

GET /api/files/1' UNION SELECT * FROM files--

GET /api/files/384c2f09-c878-42ca-a6c9-d4a826b65b5c' OR '1'='1

GET /api/files/384c2f09-c878-42ca-a6c9-d4a826b65b5c'--

GET /api/files/384c2f09-c878-42ca-a6c9-d4a826b65b5c' OR 1=1--

```

  

**Findings**:

- No SQL injection vulnerabilities found

- Input sanitisation is in place - file UUID is validated before use using the Python UUID libary

- Proper use of parameterized queries

  

**Protection Mechanisms**:

- SQLAlchemy ORM usage

- Parameterized queries

-Secure error handling

- Input validation at multiple levels

  
  

### 7. Sensitive Data Exposure

  

#### Test Case: SSL over HTTPS communication

**Description**: Analyzed packets to ensure that sensitive information such as passwords could not be read if intercepted

  

**Testing Method**:

- Used Wireshark to monitor network traffic and verify that transmitted requests were encrypted

- Sent requests via Postman, testing sign up and login

- Analysed the transmission protocol

- Captured packets and analysed that they are unreadable and sent over a secure protocol

- Attempted to send the same request to a HTTP URL

  

**Findings**:

- Login and signup requests could be easily intercepted, but their contents were unreadable

- Application data packets were transmitted via TLS 1.3

- The client/server handshake packets were visible, confirming that a key exchange takes place *(see fig TODO)

- The request to the HTTP URL was rejected

  

<img  src="../src/pen_test_screenshots/application_data_tls_1_3.png"  style="width:45%;"  />  <img  src="../src/pen_test_screenshots/server_client_hello.png"  style="width:45%;"  />

  
  
  

**Protection Mechanisms in Place**:

- SSL/TLS communication over HTTPS is enforced by the server.

- Requests that do not use HTTPS are rejected, ensuring that a poorly configured client cannot communicate.

  
  

#### Test Case: File Content Protection

**Description**: Analyzed file content handling and storage.

  

**Testing Method**:

- Used Wireshark to monitor network traffic and verify that transmitted file contents were encrypted

- Captured network packets during file uploads and downloads

- Analyzed transmission protocol (HTTPS/TLS)- Analyzed storage mechanisms

- Tested file access controls

  

**Findings**:

- Files are transmitted over TLS 1.3

  

**Protection Mechanisms**:

- File content encryption during transit

  

<img  src="../src/pen_test_screenshots/wireshark_file_upload.png"  style="width:80%;"  />

  
  

### 8. Vulnerable Components

  

#### Test Case: Dependency Analysis

**Description**: Analyzed application dependencies for known vulnerabilities.

  

**Testing Method**:

- Used `pip-audit` to scan for vunerabilities in installed dependencies

  

**Findings**:

- 12 vulnerabilities were discovered across 5 packages (see figureTODO below)

- Version pinning in a requirements.txt file was in place, however the versions were not always recent

  

<img  src="../src/pen_test_screenshots/pip-audit_output.png"  style="width:50%;"  />

  
  
  

**Protection Mechanisms**:

- The current packages should be updated to secure versions where possible, or an alternative used instead.

- Regular dependency updates

- Regular dependency audits as new vunerabilities may be found over tiem

- Version pinning in requirements (already implemented)

  

TODO maybe get rid of this

## Recommendations
1.  Missing Security Headers
   Add CSP, X-Frame-Options, HSTS, X-Content-Type-Options, and Cache-Control headers to harden browser-side security.

2. Tighten CORS Policy
   Avoid using * and restrict access to trusted origins only.

3. Limit File Upload Size
   Enforce server-side upload limits to prevent crashes and abuse.

4. Update Vulnerable Dependencies
   Replace or upgrade outdated packages flagged during testing.

5. Automate and Schedule Security Checks
   Integrate automated scans into development and perform regular security review

  

## Conclusion

The penetration test confirmed that the core security mechanisms of the system — including authentication, access control, and protection against common injection attacks — are functioning as intended. Several moderate-risk issues were identified, primarily related to HTTP header configuration, upload validation, and third-party components.
  
  
  
  

## Appendix

### Ratings and Risk Score

Vulnerability severities in this report are assessed using the CVSS v3.1 (Common Vulnerability Scoring System), an industry-standard framework for evaluating the risk posed by software vulnerabilities.

Each score is calculated based on multiple factors, grouped into the following categories:

-  **Attack Vector (AV)** – How the vulnerability is exploited (e.g., Network, Adjacent, Local, Physical)

-  **Attack Complexity (AC)** – The complexity of exploiting the vulnerability (Low or High)

-  **Privileges Required (PR)** – The level of access needed to exploit the vulnerability (None, Low, High)

-  **User Interaction (UI)** – Whether exploitation requires user involvement (None or Required)

-  **Scope (S)** – Whether the vulnerability affects resources beyond its original security scope (Unchanged or Changed)

-  **Confidentiality (C )** – The impact on confidentiality if exploited (None, Low, High)

-  **Integrity (I)** – The impact on data integrity (None, Low, High)

-  **Availability (A)** – The impact on system availability (None, Low, High)

  

Each vulnerability is scored using a **vector string**, such as: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L`

The final score is a number between **0.0 and 10.0**, categorised as

| Score Range   | Severity |
|---------------|----------|
| 0.0           | None     |
| 0.1 – 3.9     | Low      |
| 4.0 – 6.9     | Medium   |
| 7.0 – 8.9     | High     |
| 9.0 – 10.0    | Critical |

*https://www.first.org/cvss/v4-0/specification-document*

### Vunerability Details

1.  **Security Misconfiguration:** Occurs when systems are set up with insecure defaults, unnecessary features, or misapplied permissions, potentially exposing sensitive data or functionality to attackers.

2.  **Improper Input Validation:** Refers to the failure to properly validate user input, which can lead to unexpected behavior such as crashes, data corruption, or exploitation through malformed or malicious input.

3.  **Broken Authentication:** Involves flaws in login systems, session management, or credential handling that can allow attackers to impersonate other users or gain unauthorized access.

4.  **Broken Access Control:** Occurs when users can access resources or perform actions outside of their intended permissions, such as viewing or modifying another user's files.

5.  **Cryptographic Issues:** Includes the use of weak or outdated encryption algorithms, improper key management, or insecure implementations that may lead to data exposure or manipulation.

6.  **Injection:** Happens when untrusted input is interpreted as code or commands by the system (e.g., SQL injection), potentially allowing attackers to access, alter, or delete backend data.

7.  **Sensitive Data Exposure:** Refers to the unintentional leakage of sensitive information (e.g., passwords, personal data, files), especially when data is transmitted or stored without proper encryption.

8.  **Vulnerable Components:** Relates to the use of outdated or insecure third-party libraries, frameworks, or modules with known vulnerabilities that could be exploited if not patched or replaced.

  

### Test Environment Details

*All tests used non-sensitive, synthetic data to avoid exposure of real user information.*

#### Local Testing Environment

-  **Application Stack**: The server was executed locally using the Flask development server in a controlled test environment.

-  **Client Interface**: API endpoints were accessed using tools such as Postman and Burp Suite.

-  **Configuration**: Environment variables and configurations such as database structure reflected production settings where applicable

-  **Purpose**: This environment allowed for controlled testing of potentially destructive or invasive attack vectors without impacting live data or users.

#### Production Environment Testing

-  **Hosted Instance**: A production version of the application was deployed on `gobbler.info` for black-box and grey-box testing.

-  **TLS/SSL Configuration**: Live HTTPS endpoints enabled full analysis of network-layer encryption, including TLS 1.3 verification via packet inspection.

-  **Authentication & Permissions**: Realistic user accounts and workflows were used to simulate genuine user behavior and test access controls and token-based authentication.

-  **Live File Handling**: File uploads, downloads, and permission enforcement were tested using real interactions in the production environment to ensure proper validation.