namespace Kerberos.NET.Entities
{
    public partial class KrbPaEncTsEnc
    {
        internal static KrbPaEncTsEnc Now()
        {
            var ts = new KrbPaEncTsEnc();

            KerberosConstants.Now(out ts.PaTimestamp, out ts.PaUSec);

            return ts;
        }
    }
}
