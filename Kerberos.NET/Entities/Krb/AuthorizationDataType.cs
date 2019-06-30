namespace Kerberos.NET.Entities
{
    public enum AuthorizationDataType : long
    {
        AdIfRelevant = 1,
        AdIntendedForServer = 2,
        AdIntendedForApplicationClass = 3,
        AdKdcIssued = 4,
        AdAndOr = 5,
        AdMandatoryTicketExtensions = 6,
        AdInTicketExtensions = 7,
        AdMandatoryForKdc = 8,
        OsfDce = 64,
        Sesame = 65,
        AdOsfDcePkiCertId = 66,
        AdWin2kPac = 128,
        AdETypeNegotiation = 129,
        KerbAuthDataTokenRestrictions = 141,
        KerbLocal = 142,
        KerbApOptions = 143,
        KerbServiceTarget = 144
    }
}
