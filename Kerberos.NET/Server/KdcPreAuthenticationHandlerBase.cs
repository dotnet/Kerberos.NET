// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.Collections.Generic;
using Kerberos.NET.Entities;

namespace Kerberos.NET.Server
{
    public abstract class KdcPreAuthenticationHandlerBase
    {
        protected IRealmService Service { get; }

        protected KdcPreAuthenticationHandlerBase(IRealmService service)
        {
            this.Service = service;
        }

        /// <summary>
        /// Executes before the validation occurs and can be used to parse the message data for external pipelines.
        /// </summary>
        /// <param name="preauth">Contains the current state of the request to inform the outer message handler</param>
        public virtual void PreValidate(PreAuthenticationContext preauth)
        {
        }

        /// <summary>
        /// Execute the PA-Data validation phase and verify if the presented message meets the requirement of the handler.
        /// </summary>
        /// <param name="asReq">The authentication request message</param>
        /// <param name="preauth">Contains the current state of the request to inform the outer message handler</param>
        /// <returns>Optionally returns PA-Data that should be returned to the client in the response</returns>
        public virtual KrbPaData Validate(KrbKdcReq asReq, PreAuthenticationContext preauth)
        {
            return this.Validate(asReq, preauth?.Principal);
        }

        /// <summary>
        /// Execute the PA-Data validation phase and verify if the presented message meets the requirement of the handler.
        /// </summary>
        /// <param name="asReq">The authentication request message</param>
        /// <param name="principal">The user principal found during the AS-REQ processing that should be evaluated by this handler</param>
        /// <returns>Optionally returns PA-Data that should be returned to the client in the response</returns>
        public virtual KrbPaData Validate(KrbKdcReq asReq, IKerberosPrincipal principal) => null;

        /// <summary>
        /// Executes after the pre-auth validation has completed and can be used to modify the response message
        /// </summary>
        /// <param name="principal">The authenticated principal</param>
        /// <param name="preAuthRequirements">The list of PA-Data that will be sent in the response message</param>
        public virtual void PostValidate(IKerberosPrincipal principal, List<KrbPaData> preAuthRequirements)
        {
        }
    }
}