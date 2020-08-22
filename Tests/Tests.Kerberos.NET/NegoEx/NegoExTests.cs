// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Threading.Tasks;
using Kerberos.NET;
using Kerberos.NET.Crypto;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class NegoExTests : BaseTest
    {
        private const string NegoExStart = "YIIBcwYGKwYBBQUCoIIBZzCCAWOgGjAYBgorBgEEAYI3AgIeBgorBgEEAYI3AgIKooIBQwSCAT9ORUdPRVhUUw" +
            "AAAAAAAAAAYAAAAHAAAAApPlDFQtzzkyZf8n2/xHwRyG5IBp4oTHobhammNhN8W4rI6HvHIOZ0VoatafBKCREAAAAAAAAAAGAAAAABAAAAAAAAAAAAAAB" +
            "cM1MN6vkNTbLsSuN4bsMITkVHT0VYVFMCAAAAAQAAAEAAAADPAAAAKT5QxULc85MmX/J9v8R8EVwzUw3q+Q1NsuxK43huwwhAAAAAjwAAADCBjKBVMFMw" +
            "UYBPME0xSzBJBgNVBAMeQgBNAFMALQBPAHIAZwBhAG4AaQB6AGEAdABpAG8AbgAtAFAAMgBQAC0AQQBjAGMAZQBzAHMAIABbADIAMAAxADgAXaEzMDGgE" +
            "RsPV0VMTEtOT1dOOlBLVTJVoRwwGqADAgGAoRMwERsPZGVza3RvcC1tOHFuYjAx";

        private const string U2UStart = "YFcGCiqGSIb3EgECAgMEADBHoAMCAQWhAwIBEKIaMBigAwIBAaERMA8bDWFkbWluaXN0cmF0b3KjHxsdY29ycC5pZGVudGl0eWludGVydmVudGlvbi5jb20=";

        [TestMethod]
        [ExpectedException(typeof(NotSupportedException))]
        public async Task NegoExFirstClassUnsupported()
        {
            var validator = new KerberosValidator(new KerberosKey(key: new byte[16]))
            {
                ValidateAfterDecrypt = DefaultActions
            };

            await validator.Validate(Convert.FromBase64String(NegoExStart));
        }

        [TestMethod]
        [ExpectedException(typeof(NotSupportedException))]
        public async Task User2UserFirstClassUnsupported()
        {
            var validator = new KerberosValidator(new KerberosKey(key: new byte[16]))
            {
                ValidateAfterDecrypt = DefaultActions
            };

            await validator.Validate(Convert.FromBase64String(U2UStart));
        }
    }
}