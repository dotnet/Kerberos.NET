﻿using Kerberos.NET;
using Kerberos.NET.Crypto;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Threading.Tasks;

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

        [TestMethod, ExpectedException(typeof(NotSupportedException))]
        public async Task NegoExFirstClassUnsupported()
        {
            var validator = new KerberosValidator(new KerberosKey())
            {
                ValidateAfterDecrypt = DefaultActions
            };

            await validator.Validate(Convert.FromBase64String(NegoExStart));
        }
    }
}
