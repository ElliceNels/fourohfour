# Penetration Testing Report

## Executive Summary
This report details the security assessment conducted on our file sharing application, covering both client and server-side components. 

## Key Findings
Below is a list of all major vunerabilities discovered during penetration testing. 

**Name (Standardised)**
- **Location:**
- **Technique used to find:**
- **Proof of Concept:**
- **Likelihood of exploitation:**
- **Potential Impact:**
- **Risk Assessment :**
- **Reccomendations:**

**Vunerable Libraries**
- **Cryptographic operations used for TODO:**
- **TDependency audit**
- **Proof of Concept:**
- **Likelihood of exploitation:**
- **Potential Impact:**
- **Risk Assessment :**
- **Update dependency packages, periodically audit going forward**


## Engagement Summary
Testing was performed from 31/05/25 to 01/06/25, once all major components of the project were completed, and to give the team time to remediate the vunerabilities discovered. 
The testing was performed with the assumption that neither client nor server can be fully trusted, implementing a zero-trust security model. Our testing methodology combined automated scanning tools with manual penetration testing to ensure comprehensive coverage of potential vulnerabilities, and applied OWASP and CVSS 3.1 standards to identify and catagorise vunerabilities.

**Scope of Testing**
- Server-side API endpoints
- Client-side web application
- Authentication mechanisms
- File handling and permissions
- Database interactions
- Cryptographic implementations

## Testing Methodology
### Testing Tools
1. **OWASP ZAP (Zed Attack Proxy)**
   - Automated vulnerability scanning
   - API endpoint testing
   - Authentication testing
   - Session management analysis
   - Configuration: Full scan with maximum alert levels

2. **Burp Suite Professional**
   - API security testing
   - Authentication bypass attempts
   - Session handling analysis
   - Configuration: Intercepting proxy with active scanning

3. **Postman**
   - API endpoint testing
   - Authentication flow testing
   - Request/response analysis
   - Custom test collections for automated testing

4. **Wireshark**
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

### 1. Improper Input Validation

#### Test Case: Buffer Overflow in File Upload
**Description**: Attempted to upload files with excessive sizes and malformed headers to test buffer handling.

**Testing Method**:
- Used Postman to send malformed file upload requests
- Attempted file uploads with corrupted headers
- Tested with files exceeding configured size limits

**Findings**: 
- No direct buffer overflow vulnerabilities found
- Application uses Python's built-in memory management, so buffer overflows are unlikely
- Files larger than 100mb are rejected TODO what if we change the size parameter
- Flask's request size limits are properly configured

**Protection Mechanisms**:
- Input validation in file upload routes is in place
- Size limits are enforced on client side, but the size in the request is trusted TODO
- Proper error handling and logging implemented

#### Test Case: Integer Overflow in Permission Management
**Description**: Tested permission creation with extreme values and invalid IDs.

**Testing Method**:
- Used Burp Suite to intercept and modify permission requests
- Tested with maximum integer values
- Attempted negative ID values

**Findings**:
- SQLAlchemy's type system prevents integer overflow
- Proper validation of user and file IDs
- Error handling for invalid numeric inputs

**Protection Mechanisms**:
- Type checking in database models
- Input validation in permission routes
- Proper error responses for invalid inputs

### 2. Broken Authentication

#### Test Case: JWT Token Security
**Description**: Analyzed JWT implementation and token handling.

**Testing Method**:
- Used Burp Suite to analyze token structure
- Attempted token manipulation
- Tested token expiration and refresh mechanisms

**Findings**:
- JWT tokens properly implemented with expiration
- Secure token storage in client
- Proper refresh token rotation

**Protection Mechanisms**:
- JWT_SECRET_KEY properly configured
- Token expiration and refresh mechanisms
- Secure cookie handling

### 3. Broken Access Control

#### Test Case: File Permission Bypass
**Description**: Attempted to access files without proper permissions.

**Testing Method**:
- Used Postman to test various permission scenarios
- Created 2 user logins, and a file belonging to user 1
- Attempted to access user 1's file with user 2's JWT token
- Tested horizontal privilege escalation

**Findings**:
- Proper permission checks implemented
- Owner verification in place
- No IDOR vulnerabilities found

**Protection Mechanisms**:
- Permission verification in file access routes
- Owner validation in permission management
- Proper error handling for unauthorized access

### 4. Cryptographic Issues

#### Test Case: File Encryption Implementation
**Description**: Analyzed file encryption and key management.

**Testing Method**:
- Used Wireshark to analyze key exchange
- Tested encryption implementation
- Analyzed key storage mechanisms

**Findings**:
- Proper implementation of asymmetric encryption
- Secure key storage and transmission
- No hardcoded keys found

**Protection Mechanisms**:
- Public/private key pair generation
- Secure key exchange mechanism
- Proper encryption key management

### 5. Injection

#### Test Case: SQL Injection in File Queries
**Description**: Attempted SQL injection through file operations.

**Testing Method**:
- Used OWASP ZAP for automated SQL injection testing
- Manual testing with common SQL injection payloads
- Tested all database interaction points

**Findings**:
- No SQL injection vulnerabilities found
- Proper use of parameterized queries
- Input sanitization in place

**Protection Mechanisms**:
- SQLAlchemy ORM usage
- Parameterized queries
- Input validation

### 6. Security Misconfiguration

#### Test Case: Server Configuration
**Description**: Analyzed server and application configuration.

**Testing Method**:
- Used OWASP ZAP to scan for misconfigurations
- Manual review of security headers
- Analysis of CORS implementation

**Findings**:
- Proper CORS configuration
- Secure headers implemented
- Debug mode disabled in production

**Protection Mechanisms**:
- Environment-based configuration
- Secure default settings
- Proper error handling

### 7. Sensitive Data Exposure

#### Test Case: SSL over HTTPS communication
**Description**: Analyzed packets to ensure that sensitive information such as passwords could not be read if intercepted

**Testing Method**:
- Used Wireshark to monitor network traffic and verify that transmitted requests were encrypted
- Captured network packets during sign up and login
- Analyzed transmission protocol (HTTPS/TLS)
- Attempted to send to http??

**Findings**:
- Login and signup requests could be intercepted, but their contents were unreadable

**Protection Mechanisms in Place**:
- SSL/TLS communication over HTTPS is enforced by the server. 

#### Test Case: File Content Protection
**Description**: Analyzed file content handling and storage.

**Testing Method**:
- Used Wireshark to monitor network traffic and verify that transmitted file contents were encrypted
- Captured network packets during file uploads and downloads
- Analyzed transmission protocol (HTTPS/TLS)- Analyzed storage mechanisms
- Tested file access controls

**Findings**:
- Proper file encryption
- Secure storage implementation
- No sensitive data exposure

**Protection Mechanisms**:
- File content encryption
- Secure storage mechanisms
- Proper access controls

### 8. Vulnerable Components

#### Test Case: Dependency Analysis
**Description**: Analyzed application dependencies for known vulnerabilities.

**Testing Method**:
- Used `pip-audit` to scan for vunerabilities in installed dependencies

**Findings**:
- 12 vulnerabilities were discovered across 5 packages (see figureTODO below)
- Version pinning in a requirements.txt file was in place, however the versions were not always recent

    <img src="../src/pen_test_screenshots/pip-audit_output.png" style="width:50%;" />



**Protection Mechanisms**:
- The current packages should be updated to secure versions where possible, or an alternative used instead. 
- Regular dependency updates
- Regular dependency audits as new vunerabilities may be found over tiem
- Version pinning in requirements (already implemented)

## Recommendations
1. Implement rate limiting for API endpoints
2. Add additional logging for security events
3. Regular security audits of dependencies
4. Implement automated security testing in CI/CD

## Conclusion
The application demonstrates strong security measures across all tested areas. No critical vulnerabilities were found, and existing protections effectively mitigate common attack vectors. Regular security testing and updates are recommended to maintain security posture.




## Appendix
### Ratings and Risk Score

### Vunerability Details

### Test Environment Details
- Local development environment
- Production-like staging environment
- Isolated testing network

### Tools Used
1. OWASP ZAP
   - Version: 2.12.0
   - Configuration: Full scan with maximum alert levels

2. Burp Suite Professional
   - Version: 2023.1.1
   - Configuration: Intercepting proxy with active scanning

3. Postman
   - Version: 10.14.0
   - Custom test collections
   - Automated testing scripts

4. Wireshark
   - Version: 4.0.3
   - Full packet capture
   - TLS/SSL analysis


