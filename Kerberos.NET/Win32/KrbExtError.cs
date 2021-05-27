namespace Kerberos.NET.Win32
{
    public class KrbExtError
    {
        public Win32StatusCode Status { get; set; }

        public int Reserved { get; set; }

        public ExtendedErrorFlag Flags { get; set; }
    }
}
