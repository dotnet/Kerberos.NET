namespace Kerberos.NET.Entities
{
    public enum ApOptions : long
    {
        // X X X X X X X X X X X X X X X X X X X X X X X X X X X X X X X X
        // 1 0 0
        // 0 1 0
        // 0 0 1
        RESERVED = 0,
        CHANNEL_BINDING_SUPPORTED = 1 << 14,
        USE_SESSION_KEY = 1 << 30,
        MUTUAL_REQUIRED = 1 << 29
    }
}
