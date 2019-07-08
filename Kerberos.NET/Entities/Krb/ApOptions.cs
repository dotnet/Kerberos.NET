namespace Kerberos.NET.Entities
{
    public enum ApOptions : long
    {
        Reserved = 0,
        ChannelBindingSupported = 1 << 14,
        UseSessionKey = 1 << 30,
        MutualRequired = 1 << 29
    }
}
