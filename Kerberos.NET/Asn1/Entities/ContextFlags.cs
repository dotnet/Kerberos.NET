namespace Kerberos.NET.Asn1.Entities
{
    public enum ContextFlags
    {
        delegFlag = 1 << 6,
        mutualFlag = 1 << 5,
        replayFlag = 1 << 4,
        sequenceFlag = 1 << 3,
        anonFlag = 1 << 2,
        confFlag = 1 << 1,
        integFlag = 1 << 0
    }
}