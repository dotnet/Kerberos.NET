namespace Kerberos.NET.Crypto
{
    public enum NtStatus : uint
    {
        // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55

        STATUS_SUCCESS = 0x00000000,
        STATUS_INVALID_HANDLE = 0xC0000008,
        STATUS_INVALID_PARAMETER = 0xC000000D,
        STATUS_NO_MEMORY = 0xC0000017,
        STATUS_BUFFER_TOO_SMALL = 0xC0000023,
        STATUS_NOT_SUPPORTED = 0xC00000BB,
        STATUS_NOT_FOUND = 0xC0000225
    }
}
