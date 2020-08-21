// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using Kerberos.NET.Entities.Pac;
using Kerberos.NET.Ndr;

namespace Kerberos.NET.Entities
{
    public class PacDelegationInfo : NdrPacObject
    {
        public override void Marshal(NdrBuffer buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            buffer.WriteStruct(this.S4U2ProxyTarget);

            buffer.WriteInt32LittleEndian(this.S4UTransitedServices.Count());

            buffer.WriteDeferredStructArray(this.S4UTransitedServices);
        }

        public override void Unmarshal(NdrBuffer buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            this.S4U2ProxyTarget = buffer.ReadStruct<RpcString>();

            var transitedListSize = buffer.ReadInt32LittleEndian();

            buffer.ReadDeferredStructArray<RpcString>(transitedListSize, v => this.S4UTransitedServices = v);
        }

        public RpcString S4U2ProxyTarget { get; set; }

        public IEnumerable<RpcString> S4UTransitedServices { get; set; }

        public override PacType PacType => PacType.CONSTRAINED_DELEGATION_INFO;

        public override string ToString()
        {
            return $"{this.S4U2ProxyTarget} => {string.Join(", ", this.S4UTransitedServices)}";
        }
    }
}