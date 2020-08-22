// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.Text;

namespace Kerberos.NET.Entities
{
    public partial class KrbHostAddress
    {
        public string DecodeAddress()
        {
            switch (this.AddressType)
            {
                case AddressType.NetBios:
                    return Encoding.ASCII.GetString(this.Address.ToArray());
            }

            return null;
        }
    }
}