// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Net;
using System.Net.Sockets;
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

        public static KrbHostAddress ParseAddress(string addr)
        {
            if (IPAddress.TryParse(addr, out IPAddress ip))
            {
                if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || IPAddress.IsLoopback(ip))
                {
                    throw new InvalidOperationException($"Address cannot be Link-Local, Site-Local, or Loopback: {ip}");
                }

                return new KrbHostAddress
                {
                    AddressType = ip.AddressFamily == AddressFamily.InterNetwork ? AddressType.IPv4 : AddressType.IPv6,
                    Address = ip.GetAddressBytes()
                };
            }

            return new KrbHostAddress
            {
                Address = Encoding.ASCII.GetBytes(addr),
                AddressType = AddressType.NetBios
            };
        }
    }
}
