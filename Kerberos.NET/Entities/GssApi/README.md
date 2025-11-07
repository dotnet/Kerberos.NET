# GSS-API Implementation for Kerberos.NET

This directory contains a GSS-API (Generic Security Service Application Program Interface) compatible implementation for Kerberos.NET as described in RFC 2743.

## Overview

The GSS-API provides a standardized interface for security services, making it easier to write applications that can work with multiple authentication mechanisms. This implementation wraps the existing Kerberos.NET functionality to provide a GSS-API compatible interface.

## Components

### Core Types

- **`IGssContext`**: The main GSS-API interface defining all required functions per RFC 2743
- **`GssContext`**: Concrete implementation of the GSS-API interface
- **`GssSecurityContext`**: Represents an established security context
- **`GssCredential`**: Represents GSS-API credentials
- **`GssName`**: Represents a GSS-API principal name
- **`GssBuffer`**: Buffer descriptor for data exchange
- **`GssOid`**: Object identifier for mechanisms and name types
- **`GssOidSet`**: Collection of OIDs
- **`GssChannelBindings`**: Channel binding information
- **`GssStatus`**: Status codes (major and minor)

### Status Codes

The implementation includes all standard GSS-API major status codes:
- `GSS_S_COMPLETE`: Operation completed successfully
- `GSS_S_CONTINUE_NEEDED`: Multi-step operation requires continuation
- `GSS_S_BAD_MECH`: Unsupported mechanism
- `GSS_S_BAD_NAME`: Invalid name
- `GSS_S_NO_CRED`: No credentials available
- And many more...

## Usage Examples

### Basic Context Establishment (Initiator)

```csharp
using Kerberos.NET.Entities.GssApi;

// Create a GSS context
using (var gssContext = new GssContext())
{
    // Import target name
    var targetNameBuffer = new GssBuffer(Encoding.UTF8.GetBytes("HTTP/server.example.com"));
    var status = gssContext.GSS_Import_name(
        targetNameBuffer,
        GssNameType.GSS_C_NT_HOSTBASED_SERVICE,
        out GssName targetName,
        out uint minorStatus
    );

    // Initialize security context
    GssSecurityContext contextHandle = null;
    status = await gssContext.GSS_Init_sec_context(
        initiatorCredHandle: null, // Use default credentials
        contextHandle: ref contextHandle,
        targetName: targetName,
        mechType: GssOid.GSS_MECH_KRB5,
        reqFlags: GssContextEstablishmentFlag.GSS_C_MUTUAL_FLAG | 
                  GssContextEstablishmentFlag.GSS_C_INTEG_FLAG,
        timeReq: 0,
        inputChanBindings: null,
        inputToken: null,
        actualMechType: out GssOid actualMech,
        outputToken: out GssBuffer outputToken,
        retFlags: out GssContextEstablishmentFlag retFlags,
        timeRec: out uint timeRec,
        minorStatus: out minorStatus
    );

    // Send outputToken to peer...
}
```

### Accepting a Security Context (Acceptor)

```csharp
using Kerberos.NET.Entities.GssApi;

using (var gssContext = new GssContext())
{
    GssSecurityContext contextHandle = null;
    
    // Receive token from peer
    var inputToken = new GssBuffer(receivedTokenData);
    
    var status = await gssContext.GSS_Accept_sec_context(
        contextHandle: ref contextHandle,
        acceptorCredHandle: null,
        inputTokenBuffer: inputToken,
        inputChanBindings: null,
        srcName: out GssName srcName,
        mechType: out GssOid mechType,
        outputToken: out GssBuffer outputToken,
        retFlags: out GssContextEstablishmentFlag retFlags,
        timeRec: out uint timeRec,
        delegatedCredHandle: out GssCredential delegatedCred,
        minorStatus: out uint minorStatus
    );

    if (status == GssMajorStatus.GSS_S_COMPLETE)
    {
        Console.WriteLine($"Authenticated: {srcName}");
        // Use the established context...
    }
}
```

### Per-Message Protection

```csharp
// Generate a MIC (Message Integrity Code)
var message = new GssBuffer(Encoding.UTF8.GetBytes("Hello, World!"));
var status = gssContext.GSS_GetMIC(
    contextHandle,
    qopReq: 0,
    messageBuffer: message,
    messageToken: out GssBuffer mic,
    minorStatus: out uint minorStatus
);

// Verify a MIC
status = gssContext.GSS_VerifyMIC(
    contextHandle,
    messageBuffer: message,
    tokenBuffer: mic,
    qopState: out uint qopState,
    minorStatus: out minorStatus
);

// Wrap (encrypt) a message
status = gssContext.GSS_Wrap(
    contextHandle,
    confReq: true, // Request confidentiality
    qopReq: 0,
    inputMessageBuffer: message,
    confState: out bool confState,
    outputMessageBuffer: out GssBuffer wrappedMessage,
    minorStatus: out minorStatus
);

// Unwrap (decrypt) a message
status = gssContext.GSS_Unwrap(
    contextHandle,
    inputMessageBuffer: wrappedMessage,
    outputMessageBuffer: out GssBuffer unwrappedMessage,
    confState: out confState,
    qopState: out qopState,
    minorStatus: out minorStatus
);
```

### Credential Management

```csharp
// Acquire credentials
var status = await gssContext.GSS_Acquire_cred(
    desiredName: null, // Default identity
    timeReq: 3600, // 1 hour
    desiredMechs: null, // All available mechanisms
    credUsage: GssCredentialUsage.GSS_C_INITIATE,
    outputCredHandle: out GssCredential credHandle,
    actualMechs: out GssOidSet actualMechs,
    timeRec: out uint timeRec,
    minorStatus: out uint minorStatus
);

// Inquire credential information
status = gssContext.GSS_Inquire_cred(
    credHandle,
    name: out GssName name,
    lifetime: out uint lifetime,
    credUsage: out GssCredentialUsage usage,
    mechanisms: out GssOidSet mechanisms,
    minorStatus: out minorStatus
);

// Release credentials
status = gssContext.GSS_Release_cred(ref credHandle, out minorStatus);
```

## Supported GSS-API Functions

### Credential Management
- ✅ `GSS_Acquire_cred` - Acquire credentials
- ✅ `GSS_Release_cred` - Release credentials
- ✅ `GSS_Inquire_cred` - Query credential information
- ⚠️ `GSS_Add_cred` - Add credential element (partial)
- ✅ `GSS_Inquire_cred_by_mech` - Query per-mechanism credential info

### Context Management
- ✅ `GSS_Init_sec_context` - Initiate security context
- ⚠️ `GSS_Accept_sec_context` - Accept security context (partial)
- ✅ `GSS_Delete_sec_context` - Delete security context
- ⚠️ `GSS_Process_context_token` - Process context token (not implemented)
- ✅ `GSS_Context_time` - Query context lifetime
- ✅ `GSS_Inquire_context` - Query context information
- ✅ `GSS_Wrap_size_limit` - Query wrap size limits
- ⚠️ `GSS_Export_sec_context` - Export context (not implemented)
- ⚠️ `GSS_Import_sec_context` - Import context (not implemented)

### Per-Message Protection
- ✅ `GSS_GetMIC` - Generate message integrity code
- ✅ `GSS_VerifyMIC` - Verify message integrity code
- ✅ `GSS_Wrap` - Wrap (protect) message
- ✅ `GSS_Unwrap` - Unwrap (unprotect) message

### Support Functions
- ✅ `GSS_Display_status` - Convert status to string
- ✅ `GSS_Indicate_mechs` - List available mechanisms
- ✅ `GSS_Compare_name` - Compare two names
- ✅ `GSS_Display_name` - Convert name to string
- ✅ `GSS_Import_name` - Convert string to name
- ✅ `GSS_Release_name` - Release name
- ✅ `GSS_Release_buffer` - Release buffer
- ✅ `GSS_Release_OID_set` - Release OID set
- ✅ `GSS_Create_empty_OID_set` - Create empty OID set
- ✅ `GSS_Add_OID_set_member` - Add OID to set
- ✅ `GSS_Test_OID_set_member` - Test OID membership
- ✅ `GSS_Inquire_names_for_mech` - List name types for mechanism
- ✅ `GSS_Inquire_mechs_for_name` - List mechanisms for name type
- ✅ `GSS_Canonicalize_name` - Convert to mechanism name
- ⚠️ `GSS_Export_name` - Export name (partial)
- ✅ `GSS_Duplicate_name` - Duplicate name

Legend:
- ✅ Fully implemented
- ⚠️ Partially implemented or stub
- ❌ Not implemented

## Supported Mechanisms

- Kerberos V5 (OID: 1.2.840.113554.1.2.2)
- Kerberos V5 Legacy (OID: 1.2.840.113554.1.2.1.1)
- SPNEGO (OID: 1.3.6.1.5.5.2)

## Implementation Notes

1. **Async Support**: The implementation extends the standard GSS-API with async/await support for network operations.

2. **Integration with Kerberos.NET**: This GSS-API layer wraps existing Kerberos.NET components:
   - `KerberosClient` for ticket acquisition
   - `KerberosAuthenticator` for validation
   - Crypto services for message protection

3. **Partial Implementation**: Some functions (marked with ⚠️) have partial or stub implementations. These can be extended based on requirements.

4. **Error Handling**: All functions follow GSS-API conventions:
   - Return major status code
   - Provide minor (mechanism-specific) status via out parameter
   - Use standard GSS-API status codes

## Testing

Unit tests are provided in `Tests/Tests.Kerberos.NET/GssApi/GssApiTests.cs` covering:
- Basic type creation and manipulation
- OID and OID set operations
- Name operations
- Buffer management
- Status code handling

## References

- [RFC 2743](https://tools.ietf.org/html/rfc2743) - Generic Security Service Application Program Interface Version 2, Update 1
- [RFC 2744](https://tools.ietf.org/html/rfc2744) - Generic Security Service API Version 2: C-bindings
- [RFC 4121](https://tools.ietf.org/html/rfc4121) - The Kerberos Version 5 Generic Security Service Application Program Interface (GSS-API) Mechanism

## Contributing

Contributions to complete the partial implementations or add new features are welcome. Please ensure:
- Follow existing code style and patterns
- Add unit tests for new functionality
- Update this documentation as needed
- Maintain compatibility with RFC 2743
