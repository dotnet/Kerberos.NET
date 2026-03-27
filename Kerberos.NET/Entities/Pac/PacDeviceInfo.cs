// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

namespace Kerberos.NET.Entities.Pac
{
    public class PacDeviceInfo : PacLogonInfo
    {
        public override PacType PacType => PacType.DEVICE_INFO;
    }
}
