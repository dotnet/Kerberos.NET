using System;

namespace Kerberos.NET.Asn1
{
    [System.AttributeUsage(AttributeTargets.All, Inherited = false, AllowMultiple = true)]
    public sealed class KerberosIgnoreAttribute : Attribute
    {
        public KerberosIgnoreAttribute()
        { }
    }
}
