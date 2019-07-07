using System;

namespace Kerberos.NET.Win32
{
    public enum ContextStatus
    {
        RequiresContinuation,
        Accepted,
        Error
    }

    [Flags]
    internal enum ContextFlag
    {
        Zero = 0,
        Delegate = 0x00000001,
        MutualAuth = 0x00000002,
        ReplayDetect = 0x00000004,
        SequenceDetect = 0x00000008,
        Confidentiality = 0x00000010,
        UseSessionKey = 0x00000020,
        AllocateMemory = 0x00000100,
        Connection = 0x00000800,
        InitExtendedError = 0x00004000,
        AcceptExtendedError = 0x00008000,
        InitStream = 0x00008000,
        AcceptStream = 0x00010000,
        InitIntegrity = 0x00010000,
        AcceptIntegrity = 0x00020000,
        InitManualCredValidation = 0x00080000,
        InitUseSuppliedCreds = 0x00000080,
        InitIdentify = 0x00020000,
        AcceptIdentify = 0x00080000,
        ProxyBindings = 0x04000000,
        AllowMissingBindings = 0x10000000,
        UnverifiedTargetName = 0x20000000
    }

    public enum SecStatus : uint
    {
        SEC_E_OK = 0x0,
        SEC_E_ERROR = 0x80000000,
        SEC_E_INSUFFICENT_MEMORY = 0x80090300,
        SEC_E_INVALID_HANDLE = 0x80090301,
        SEC_E_TARGET_UNKNOWN = 0x80090303,
        SEC_E_UNSUPPORTED_FUNCTION = 0x80090302,
        SEC_E_INTERNAL_ERROR = 0x80090304,
        SEC_E_SECPKG_NOT_FOUND = 0x80090305,
        SEC_E_INVALID_TOKEN = 0x80090308,
        SEC_E_QOP_NOT_SUPPORTED = 0x8009030A,
        SEC_E_LOGON_DENIED = 0x8009030C,
        SEC_E_UNKNOWN_CREDENTIALS = 0x8009030D,
        SEC_E_NO_CREDENTIALS = 0x8009030E,
        SEC_E_MESSAGE_ALTERED = 0x8009030F,
        SEC_E_OUT_OF_SEQUENCE = 0x80090310,
        SEC_E_NO_AUTHENTICATING_AUTHORITY = 0x80090311,
        SEC_E_CONTEXT_EXPIRED = 0x80090317,
        SEC_E_INCOMPLETE_MESSAGE = 0x80090318,
        SEC_E_BUFFER_TOO_SMALL = 0x80090321,
        SEC_E_WRONG_PRINCIPAL = 0x80090322,
        SEC_E_CRYPTO_SYSTEM_INVALID = 0x80090337,
        SEC_I_CONTINUE_NEEDED = 0x00090312,
        SEC_I_CONTEXT_EXPIRED = 0x00090317,
        SEC_I_INCOMPLETE_CREDENTIALS = 0x00090320,
        SEC_I_RENEGOTIATE = 0x00090321
    }

    public enum SecurityContextAttribute
    {
        SECPKG_ATTR_SIZES = 0,
        SECPKG_ATTR_NAMES = 1,
        SECPKG_ATTR_LIFESPAN = 2,
        SECPKG_ATTR_DCE_INFO = 3,
        SECPKG_ATTR_STREAM_SIZES = 4,
        SECPKG_ATTR_AUTHORITY = 6,
        SECPKG_ATTR_PACKAGE_INFO = 10,
        SECPKG_ATTR_NEGOTIATION_INFO = 12,
        SECPKG_ATTR_UNIQUE_BINDINGS = 25,
        SECPKG_ATTR_ENDPOINT_BINDINGS = 26,
        SECPKG_ATTR_CLIENT_SPECIFIED_TARGET = 27,
        SECPKG_ATTR_APPLICATION_PROTOCOL = 35
    }
}
