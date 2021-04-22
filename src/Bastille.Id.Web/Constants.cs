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
    /// <summary>
    /// This class contains constants used within the Bastille Identity Web App libraries.
    /// </summary>
    public static class Constants
    {
        /// <summary>
        /// LoginHint. Represents the preferred_username claim in the ID token.
        /// </summary>
        public const string LoginHint = "login_hint";

        /// <summary>
        /// DomainHint. Determined by the tenant Id.
        /// </summary>
        public const string DomainHint = "domain_hint";

        /// <summary>
        /// Claims. Determined from the signed-in user.
        /// </summary>
        public const string Claims = "claims";

        /// <summary>
        /// Bearer. Predominant type of access token used with OAuth 2.0.
        /// </summary>
        public const string Bearer = "Bearer";

        /// <summary>
        /// Configuration section name for Bastille.ID.
        /// </summary>
        public const string BastilleId = "BastilleId";

        /// <summary>
        /// Scope.
        /// </summary>
        public const string Scope = "scope";

        /// <summary>
        /// Policy for B2C user flows. The name of the policy to check against a specific user flow.
        /// </summary>
        public const string Policy = "policy";

        /// <summary>
        /// Register Valid Audience.
        /// </summary>
        internal const string Version = "ver";

        /// <summary>
        /// Version 1.0.
        /// </summary>
        internal const string V1 = "1.0";

        /// <summary>
        /// Version 2.0.
        /// </summary>
        internal const string V2 = "2.0";

        /// <summary>
        /// The name claim.
        /// </summary>
        internal const string NameClaim = "name";

        /// <summary>
        /// The consent claim.
        /// </summary>
        internal const string Consent = "consent";

        /// <summary>
        /// The consent URI claim.
        /// </summary>
        internal const string ConsentUrl = "consentUri";

        /// <summary>
        /// The scopes claim.
        /// </summary>
        internal const string Scopes = "scopes";

        /// <summary>
        /// The preferred user name claim.
        /// </summary>
        internal const string PreferredUserName = "preferred_username";

        /// <summary>
        /// The cors policy name.
        /// </summary>
        internal const string CorsPolicyName = "DefaultCorsPolicy";
    }
}