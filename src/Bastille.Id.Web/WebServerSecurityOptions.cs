/*
 * Bastille.ID Identity Server
 * (c) Copyright Talegen, LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
*/

namespace Bastille.Id.Web
{
    using System;
    using System.Collections.Generic;
    using System.Text;
    using Bastille.Id.Web.Security;
    using Microsoft.IdentityModel.Protocols.OpenIdConnect;

    /// <summary>
    /// This class contains properties for the web server security extension.
    /// </summary>
    /// <seealso cref="Bastille.Id.Web.IdentityProviderOptions" />
    public class WebServerSecurityOptions : IdentityProviderOptions
    {
        /// <summary>
        /// Gets or sets the redis cache configuration.
        /// </summary>
        /// <value>The redis cache configuration. Default is empty and distributed memory cache is used instead.</value>
        public string RedisCacheConfiguration { get; set; }

        /// <summary>
        /// Gets or sets the type of the client response used.
        /// </summary>
        /// <value>The type of the client response used. The hybrid grant type is the default.</value>
        public string ClientResponseType { get; set; } = OpenIdConnectResponseType.Code;

        /// <summary>
        /// Gets or sets the client response mode.
        /// </summary>
        /// <value>The client response mode. Default is form POST.</value>
        public string ClientResponseMode { get; set; } = OpenIdConnectResponseMode.FormPost;

        /// <summary>
        /// Gets or sets the name of the API resource.
        /// </summary>
        /// <value>The name of the API resource. By default "bastille-id-api" but can be modified by the IdP admin.</value>
        public string ApiResourceName { get; set; } = "bastille-id-api";

        /// <summary>
        /// Gets or sets the sliding session timeout minutes.
        /// </summary>
        /// <value>The sliding session timeout minutes. Default is 20 minutes. Setting to 0 will disable the sliding session.</value>
        public int SlidingSessionTimeoutMinutes { get; set; } = 20;

        /// <summary>
        /// Gets or sets additional scopes to request from the client.
        /// </summary>
        /// <value>
        /// Any additional scopes to request for the client web app. The <see cref="ApiResourceName" /> will always be added. The default contains a "profile" scope.
        /// </value>
        public List<string> Scopes { get; set; } = new List<string>() { IdentityModel.JwtClaimTypes.Profile };

        /// <summary>
        /// Gets or sets the authentication ticket expiration minutes.
        /// </summary>
        /// <value>The authentication ticket expiration minutes. Default is 60 minutes.</value>
        public int AuthenticationTicketExpirationMinutes { get; set; } = 60;

        /// <summary>
        /// Gets or sets the allowed origins that can access the web application.
        /// </summary>
        /// <value>The allowed origins. No values will set a default * CORS origin setting.</value>
        public List<string> AllowedOrigins { get; set; } = new List<string>();

        /// <summary>
        /// Gets or sets a value indicating whether to always require SSL when optional.
        /// </summary>
        public bool ForceSsl { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether the default map inbound claims is used.
        /// </summary>
        /// <value><c>true</c> if [default map inbound claims]; otherwise, <c>false</c>. The default is <c>false</c>.</value>
        public bool DefaultMapInboundClaims { get; set; } = false;

        /// <summary>
        /// Gets or sets a value indicating whether [enable cookie refresh token handling].
        /// </summary>
        /// <value><c>true</c> if [enable cookie refresh token handling]; otherwise, <c>false</c>.</value>
        public bool EnableCookieRefreshTokenHandling { get; set; } = true;
    }
}