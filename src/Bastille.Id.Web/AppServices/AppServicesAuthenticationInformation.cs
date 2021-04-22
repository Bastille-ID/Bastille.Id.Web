namespace Bastille.Id.Web.AppServices
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Claims;
    using System.Text;
    using Microsoft.Extensions.Primitives;
    using Microsoft.IdentityModel.JsonWebTokens;
    using Talegen.Common.Core.Extensions;

    /// <summary>
    /// Information about the App Services configuration on the host.
    /// </summary>
    public static class AppServicesAuthenticationInformation
    {
        #region Private Constant Environment Variable Names

        /// <summary>
        /// The application services authentication enabled environment variable.
        /// </summary>
        private const string AppServicesAuthEnabledEnvironmentVariable = "WEBSITE_AUTH_ENABLED"; // e.g. True

        /// <summary>
        /// The application services authentication open identifier issuer environment variable.
        /// </summary>
        private const string AppServicesAuthOpenIdIssuerEnvironmentVariable = "WEBSITE_AUTH_OPENID_ISSUER"; // e.g. https://auth.bastille.id/<tenantId>/

        /// <summary>
        /// The application services authentication client identifier environment variable.
        /// </summary>
        private const string AppServicesAuthClientIdEnvironmentVariable = "WEBSITE_AUTH_CLIENT_ID";         // A Unique Client ID, e.g. GUID

        /// <summary>
        /// The application services authentication client secret environment variable.
        /// </summary>
        private const string AppServicesAuthClientSecretEnvironmentVariable = "WEBSITE_AUTH_CLIENT_SECRET"; // A string, e.g. SHA256 base64 encoded value.

        /// <summary>
        /// The application services authentication logout path environment variable.
        /// </summary>
        private const string AppServicesAuthLogoutPathEnvironmentVariable = "WEBSITE_AUTH_LOGOUT_PATH";    // /.auth/logout

        #endregion

        #region Private Constant Header Names

        /// <summary>
        /// The application services authentication identifier token header.
        /// </summary>
        private const string AppServicesAuthIdTokenHeader = "X-TOKEN-ID-TOKEN";

        /// <summary>
        /// The application services authentication idp token header.
        /// </summary>
        private const string AppServicesAuthIdpTokenHeader = "X-CLIENT-PRINCIPAL-IDP";

        /// <summary>
        /// The application services authentication debug headers environment variable.
        /// </summary>
        /// <remarks>Artificially added by library to help debugging App Services. See the Debug controller of the test app.</remarks>
        private const string AppServicesAuthDebugHeadersEnvironmentVariable = "APP_SERVICES_AUTH_LOCAL_DEBUG";

        #endregion

        /// <summary>
        /// Gets a value indicating whether this instance is application services authentication enabled.
        /// </summary>
        /// <value><c>true</c> if this instance is application services authentication enabled; otherwise, <c>false</c>.</value>
        public static bool IsAppServicesAuthenticationEnabled => Environment.GetEnvironmentVariable(AppServicesAuthEnabledEnvironmentVariable).ToBoolean();

        /// <summary>
        /// Gets the Logout URL for App Services Auth web sites.
        /// </summary>
        /// <value>The logout URL.</value>
        public static string LogoutUrl => Environment.GetEnvironmentVariable(AppServicesAuthLogoutPathEnvironmentVariable);

        /// <summary>
        /// Gets the ClientID of the App Services Auth web site.
        /// </summary>
        internal static string ClientId => Environment.GetEnvironmentVariable(AppServicesAuthClientIdEnvironmentVariable);

        /// <summary>
        /// Gets the client secret of the App Services Auth web site.
        /// </summary>
        internal static string ClientSecret => Environment.GetEnvironmentVariable(AppServicesAuthClientSecretEnvironmentVariable);

        /// <summary>
        /// Gets the Issuer of the App Services Auth web site.
        /// </summary>
        internal static string Issuer => Environment.GetEnvironmentVariable(AppServicesAuthOpenIdIssuerEnvironmentVariable);

#if DEBUG

        /// <summary>
        /// Simulates the gettting header from debug environment variable.
        /// </summary>
        /// <param name="header">The header.</param>
        /// <returns>Returns the environment variable value.</returns>
        internal static string SimulateGetttingHeaderFromDebugEnvironmentVariable(string header)
        {
            string headerPlusValue = Environment.GetEnvironmentVariable(AppServicesAuthDebugHeadersEnvironmentVariable)?.Split(';')?.FirstOrDefault(h => h.StartsWith(header));
            return headerPlusValue?.Substring(header.Length + 1);
        }

#endif

        /// <summary>
        /// Get the ID token from the headers sent by App services authentication.
        /// </summary>
        /// <param name="headers">Headers.</param>
        /// <returns>The ID Token.</returns>
        internal static string GetIdToken(IDictionary<string, StringValues> headers)
        {
            if (headers is null)
            {
                throw new ArgumentNullException(nameof(headers));
            }

            headers.TryGetValue(AppServicesAuthIdTokenHeader, out var idToken);

#if DEBUG
            if (string.IsNullOrEmpty(idToken))
            {
                idToken = SimulateGetttingHeaderFromDebugEnvironmentVariable(AppServicesAuthIdTokenHeader);
            }
#endif
            return idToken;
        }

        /// <summary>
        /// Get the IDP from the headers sent by App services authentication.
        /// </summary>
        /// <param name="headers">Headers.</param>
        /// <returns>The IDP.</returns>
        internal static string GetIdp(IDictionary<string, StringValues> headers)
        {
            if (headers is null)
            {
                throw new ArgumentNullException(nameof(headers));
            }

            headers.TryGetValue(AppServicesAuthIdpTokenHeader, out var idp);
#if DEBUG
            if (string.IsNullOrEmpty(idp))
            {
                idp = SimulateGetttingHeaderFromDebugEnvironmentVariable(AppServicesAuthIdpTokenHeader);
            }
#endif
            return idp;
        }

        /// <summary>
        /// Get the user claims from the headers and environment variables.
        /// </summary>
        /// <param name="headers">Headers.</param>
        /// <returns>User claims.</returns>
        internal static ClaimsPrincipal GetUser(IDictionary<string, StringValues> headers)
        {
            ClaimsPrincipal claimsPrincipal = null;
            string idToken = GetIdToken(headers);
            string idp = GetIdp(headers);

            if (idToken != null && idp != null)
            {
                JsonWebToken jsonWebToken = new JsonWebToken(idToken);
                bool isAadV1Token = jsonWebToken.Claims.Any(c => c.Type == Constants.Version && c.Value == Constants.V1);

                claimsPrincipal = new ClaimsPrincipal(
                    new ClaimsIdentity(
                    jsonWebToken.Claims,
                    idp,
                    isAadV1Token ? Constants.NameClaim : Constants.PreferredUserName,
                    ClaimsIdentity.DefaultRoleClaimType));
            }

            return claimsPrincipal;
        }
    }
}