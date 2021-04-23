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

namespace Bastille.Id.Web.Security
{
    using System;
    using System.IdentityModel.Tokens.Jwt;
    using System.Net.Http;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using IdentityModel.Client;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Authentication.Cookies;
    using Microsoft.Extensions.Logging;
    using Microsoft.IdentityModel.Protocols.OpenIdConnect;
    using Serilog;

    /// <summary>
    /// This class contains cookie validation handler methods for OIDC related authentication.
    /// </summary>
    public class CookieEventHandler : CookieAuthenticationEvents
    {
        /// <summary>
        /// This contains an instance of logout session manager.
        /// </summary>
        private readonly LogoutSessionManager logoutSessions;

        /// <summary>
        /// This contains the discovery cache.
        /// </summary>
        private readonly IDiscoveryCache discoveryCache;

        /// <summary>
        /// The options.
        /// </summary>
        private readonly CookieHandlerOptions options;

        /// <summary>
        /// Initializes a new instance of the <see cref="CookieEventHandler" /> class.
        /// </summary>
        /// <param name="options">Contains the application settings.</param>
        /// <param name="logoutSessions">Contains the logout session manager.</param>
        /// <param name="discoveryCache">Contains an instance of the discovery cache.</param>
        public CookieEventHandler(CookieHandlerOptions options, LogoutSessionManager logoutSessions, IDiscoveryCache discoveryCache)
        {
            this.options = options ?? throw new ArgumentNullException(nameof(options));
            this.logoutSessions = logoutSessions ?? throw new ArgumentNullException(nameof(logoutSessions));
            this.discoveryCache = discoveryCache;
        }

        /// <summary>
        /// This event is fired every time the cookie has been validated by the cookie middleware, during every authenticated request the decryption of the
        /// cookie has already happened so we have access to the user claims and cookie properties - expiration, etc..
        /// </summary>
        /// <param name="context">Contains the context.</param>
        /// <returns>Returns a task.</returns>
        public override async Task ValidatePrincipal(CookieValidatePrincipalContext context)
        {
            Log.Debug(Properties.Resources.DebugCookieTokenValidateProcessCheckMessageText);

            // since our cookie lifetime is based on the access token one, check if we're more than halfway of the cookie lifetime
            bool signedOut = false;
            DateTime rightNow = DateTime.UtcNow;
            ClaimsIdentity identity = context?.Principal.Identity as ClaimsIdentity ?? throw new ArgumentNullException(nameof(context));

            Claim accessTokenClaim = identity.FindFirst("access_token");
            Claim refreshTokenClaim = identity.FindFirst("refresh_token");

            if (accessTokenClaim != null)
            {
                Log.Debug("Cookie OnValidatePrincipal: Access Token: {0}", accessTokenClaim.Value);
            }

            if (refreshTokenClaim != null)
            {
                Log.Debug("Cookie OnValidatePrincipal: Refresh Token: {0}", refreshTokenClaim.Value);
            }

            // at first, determine if user has been logged out...
            if (identity.IsAuthenticated)
            {
                string sub = context.Principal.FindFirst("sub")?.Value;
                string sid = context.Principal.FindFirst("sid")?.Value;

                // if we found user logged out...
                if (await this.logoutSessions.IsLoggedOutAsync(sub, sid).ConfigureAwait(false))
                {
                    signedOut = true;

                    // reject the validation
                    context.RejectPrincipal();

                    // sign out.
                    await context.HttpContext.SignOutAsync().ConfigureAwait(false);

                    // revoke the token.
                    await this.RevokeRefreshTokenAsync(refreshTokenClaim.Value).ConfigureAwait(false);
                }
            }

            if (!signedOut && accessTokenClaim != null)
            {
                JwtSecurityToken tokenFound = new JwtSecurityToken(accessTokenClaim.Value);

                // validate that token is still not stale...
                bool validToken = tokenFound.ValidFrom <= rightNow && tokenFound.ValidTo > rightNow;

                // if the certificate has gone stale...
                if (!validToken)
                {
                    Log.Debug(Properties.Resources.DebugCookieTokenRefreshProcessMessageText);

                    try
                    {
                        // if we have to refresh, grab the refresh token from the claims, and request new access
                        TokenResponse response = null;

                        // retrieve discovery
                        DiscoveryDocumentResponse discovery = await this.discoveryCache.GetAsync().ConfigureAwait(false);
                        string tokenEndpoint = this.options.UseDiscovery && discovery != null ? discovery.TokenEndpoint : new Uri(this.options.AuthorityUri, "/connect/token").ToString();
                        Log.Debug(Properties.Resources.DebugCookieTokenEndpointUsedMessageText, tokenEndpoint);

                        // create a new Http Client
                        using (HttpClient client = new HttpClient())
                        using (var request = new RefreshTokenRequest
                        {
                            Address = tokenEndpoint,
                            GrantType = OpenIdConnectGrantTypes.RefreshToken,
                            ClientId = this.options.ClientId,
                            ClientSecret = this.options.Secret,
                            RefreshToken = refreshTokenClaim.Value
                        })
                        {
                            // Request a refresh token call
                            response = await client.RequestRefreshTokenAsync(request)
                            .ConfigureAwait(false);
                        }

                        if (response != null)
                        {
                            // if there was no error in communicating with authority for refresh...
                            if (!response.IsError)
                            {
                                Log.Debug(Properties.Resources.DebugCookieTokenRefreshSuccessMessageText, response.AccessToken, response.RefreshToken);

                                // everything went right, remove old tokens and add new ones
                                identity.RemoveClaim(accessTokenClaim);
                                identity.RemoveClaim(refreshTokenClaim);

                                identity.AddClaims(new[]
                                {
                                    new Claim("access_token", response.AccessToken),
                                    new Claim("refresh_token", response.RefreshToken)
                                });

                                // indicate to the cookie middleware to renew the session cookie the new lifetime will be the same as the old one, so the
                                // alignment between cookie and access token is preserved
                                context.ShouldRenew = true;
                            }
                            else
                            {
                                Log.Error(
                                    Properties.Resources.DebugCookieTokenRefreshFailedMessageText,
                                    response.Error,
                                    response.ErrorDescription,
                                    response.ErrorType,
                                    response.HttpErrorReason);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Log.Error(ex, Properties.Resources.DebugCookieTokenRefreshExceptionErrorText);
                    }
                }
                else
                {
                    Log.Debug(Properties.Resources.DebugCookieTokenValidTokenMessageText);
                }
            }
        }

        /// <summary>
        /// This method makes a call to revoke the refresh token.
        /// </summary>
        /// <param name="refreshToken">The refresh token to revoke.</param>
        /// <returns>Contains a task.</returns>
        private async Task RevokeRefreshTokenAsync(string refreshToken)
        {
            try
            {
                // retrieve discovery
                DiscoveryDocumentResponse discovery = await this.discoveryCache.GetAsync().ConfigureAwait(false);

                // revoke refresh token
                string revokeRefreshEndpoint = this.options.UseDiscovery && discovery != null ? discovery.RevocationEndpoint : new Uri(this.options.AuthorityUri, "/connect/revocation").ToString();

                using (HttpClient client = new HttpClient())
                {
                    // Request a refresh token call
                    using (var request = new TokenRevocationRequest
                    {
                        Address = revokeRefreshEndpoint,
                        ClientId = this.options.ClientId,
                        ClientSecret = this.options.Secret,
                        Token = refreshToken,
                        TokenTypeHint = "refresh_token"
                    })
                    {
                        TokenRevocationResponse response = await client.RevokeTokenAsync(request)
                            .ConfigureAwait(false);

                        if (response != null)
                        {
                            // if there was no error in communicating with authority for refresh...
                            if (!response.IsError)
                            {
                                Log.Debug("Refresh token revoked successfully.");
                            }
                            else
                            {
                                Log.Warning(
                                    response.Exception,
                                    "Refresh token revocation failed. {0} {1} {2}",
                                    response.Error,
                                    response.ErrorType,
                                    response.HttpErrorReason);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "An error occurred during refresh token revocation");
            }
        }
    }
}