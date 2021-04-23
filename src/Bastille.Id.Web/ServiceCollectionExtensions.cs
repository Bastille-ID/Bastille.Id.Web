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
    using System.IdentityModel.Tokens.Jwt;
    using System.Linq;
    using System.Net.Http;
    using System.Security.Claims;
    using System.Threading;
    using System.Threading.Tasks;
    using Bastille.Id.Web.Security;
    using IdentityModel.Client;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Authentication.Cookies;
    using Microsoft.AspNetCore.Authentication.OpenIdConnect;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Builder;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.Extensions.Logging;
    using Microsoft.IdentityModel.Protocols.OpenIdConnect;
    using Microsoft.IdentityModel.Tokens;
    using Newtonsoft.Json;
    using Serilog;
    using Talegen.Common.Core.Extensions;
    using Vasont.AspnetCore.RedisClient;

    /// <summary>
    /// This class contains extension methods for supporting ASP.net Core Web Applications using an OpenID Identity Provider like Bastille.ID.
    /// </summary>
    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Changes the defaults for server threads and completion ports for the application.
        /// </summary>
        /// <param name="services">The services to extend.</param>
        /// <param name="minimumCompletionPortThreads">The minimum completion ports to set. Default is 0 which ignores this operation.</param>
        /// <returns>Returns the services collection.</returns>
        /// <exception cref="ArgumentNullException">Exception is thrown if <paramref name="services" /> is null.</exception>
        public static IServiceCollection ConfigureServerThreads(this IServiceCollection services, int minimumCompletionPortThreads = 0)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            if (minimumCompletionPortThreads > 0)
            {
                // setup threading
                ThreadPool.GetMinThreads(out int workerThreads, out int completionPortThreads);
                ThreadPool.SetMinThreads(workerThreads * 2, completionPortThreads > minimumCompletionPortThreads ? completionPortThreads : minimumCompletionPortThreads);
                Log.Debug("Current Minimum Threads to workerThreads={0}, completion Ports={1}", workerThreads, completionPortThreads);
                Log.Debug("Setting Minimum Threads to workerThreads={0}, completion Ports={1}", workerThreads * 2, completionPortThreads > minimumCompletionPortThreads ? completionPortThreads : minimumCompletionPortThreads);
            }

            return services;
        }

        /// <summary>
        /// Changes the cookie handling policy for the web application.
        /// </summary>
        /// <param name="services">The services to extend.</param>
        /// <param name="cookiePolicyOptions">An optional cookie policy. If none specified, the common samesite cookie handling logic shall be implemented.</param>
        /// <returns>Returns the services collection.</returns>
        /// <exception cref="ArgumentNullException">Exception is thrown if <paramref name="services" /> is null.</exception>
        public static IServiceCollection ConfigureCookiePolicies(this IServiceCollection services, CookiePolicyOptions cookiePolicyOptions = null)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            // set up SameSite handling for .NET 3.1 apps.
            if (cookiePolicyOptions == null)
            {
                cookiePolicyOptions = new CookiePolicyOptions
                {
                    // This lambda determines whether user consent for non-essential cookies is needed for a given request.
                    CheckConsentNeeded = context => true,
                    MinimumSameSitePolicy = SameSiteMode.None,
                    Secure = CookieSecurePolicy.SameAsRequest
                };

                // Handling SameSite cookie according to https://docs.microsoft.com/en-us/aspnet/core/security/samesite?view=aspnetcore-3.1
                HandleSameSiteCookieCompatibility(cookiePolicyOptions);
            }

            return services;
        }

        /// <summary>
        /// Configures the web server security.
        /// </summary>
        /// <param name="services">The services.</param>
        /// <param name="webServerSecurityOptions">The options.</param>
        /// <param name="development">Contains a value indicating whether the application is in a dev environment.</param>
        /// <returns>Returns the service collection.</returns>
        /// <exception cref="ArgumentNullException">
        /// Exception thrown if <paramref name="services" /> or <paramref name="webServerSecurityOptions" /> are null.
        /// </exception>
        public static IServiceCollection AddWebServerSecurity(this IServiceCollection services, WebServerSecurityOptions webServerSecurityOptions, bool development = false)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            if (webServerSecurityOptions == null)
            {
                throw new ArgumentNullException(nameof(webServerSecurityOptions));
            }

            if (webServerSecurityOptions.EnableCookieRefreshTokenHandling)
            {
                services.AddLogoutBackchannelManagement(webServerSecurityOptions);
            }

            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
            JwtSecurityTokenHandler.DefaultMapInboundClaims = webServerSecurityOptions.DefaultMapInboundClaims;

            if (webServerSecurityOptions.ForceSsl)
            {
                // forcing SSL...
                services.Configure<MvcOptions>(options => { options.Filters.Add(new RequireHttpsAttribute()); });
            }

            services.ConfigureApplicationCookie(configure =>
            {
                configure.Cookie.SecurePolicy = !development ? CookieSecurePolicy.Always : CookieSecurePolicy.SameAsRequest;
            });

            // setup HSTS settings
            services.AddHsts(options =>
            {
                options.IncludeSubDomains = true;
                options.MaxAge = development ? TimeSpan.FromMinutes(60) : TimeSpan.FromDays(365);
            });

            // add authentication...
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = OpenIdConnectDefaults.AuthenticationScheme;
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
                options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })
            .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
            {
                options.Cookie.Name = webServerSecurityOptions.ClientId;
                options.Cookie.SecurePolicy = development ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;

                options.SlidingExpiration = true;

                // Expire the session of 20 minutes of inactivity
                if (webServerSecurityOptions.SlidingSessionTimeoutMinutes > 0)
                {
                    options.ExpireTimeSpan = TimeSpan.FromMinutes(webServerSecurityOptions.SlidingSessionTimeoutMinutes);
                }

                options.Cookie.IsEssential = true;
                options.EventsType = typeof(CookieEventHandler);
            })
            .AddOpenIdConnect(
                OpenIdConnectDefaults.AuthenticationScheme,
                options =>
                {
                    options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.Authority = webServerSecurityOptions.AuthorityUri.ToString();
                    options.ClientId = webServerSecurityOptions.ClientId;
                    options.ClientSecret = webServerSecurityOptions.Secret;
                    options.RequireHttpsMetadata = webServerSecurityOptions.ForceSsl;

                    options.ResponseType = webServerSecurityOptions.ClientResponseType;
                    options.ResponseMode = webServerSecurityOptions.ClientResponseMode;

                    // persist in cookie
                    options.SaveTokens = true;

                    // always validate token issuer
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true
                    };

                    // add the resource to requested scope if defined.
                    if (!string.IsNullOrWhiteSpace(webServerSecurityOptions.ApiResourceName))
                    {
                        options.Scope.Add(webServerSecurityOptions.ApiResourceName);
                    }

                    // add any additional scopes requested. These could be "offline_access" for example.
                    webServerSecurityOptions.Scopes?.ForEach(scope =>
                    {
                        options.Scope.Add(scope);
                    });

                    // this will populate the user claims from user info endpoint.
                    options.GetClaimsFromUserInfoEndpoint = true;

                    options.Events = new OpenIdConnectEvents
                    {
                        // set session ticket expiration to the defined minutes. Default is 60 minutes.
#pragma warning disable CS1998 // Async method lacks 'await' operators and will run synchronously
                        OnTicketReceived = async (context) =>
#pragma warning restore CS1998 // Async method lacks 'await' operators and will run synchronously
                        {
                            context.Properties.ExpiresUtc = DateTime.UtcNow.AddMinutes(webServerSecurityOptions.AuthenticationTicketExpirationMinutes);
                        },

                        // when a message is received...
                        OnMessageReceived = messageContext =>
                        {
                            Log.Debug(Properties.Resources.DebugOpenIdMessageRecievedMessageText, JsonConvert.SerializeObject(messageContext.ProtocolMessage));
                            return Task.CompletedTask;
                        },

                        OnAuthorizationCodeReceived = async codeContext =>
                        {
                            Log.Debug("OnAuthorizationCodeReceived: {0}", codeContext.TokenEndpointRequest.Code);
                        },

                        // This event is called after the OIDC middleware received the auhorisation code, redeemed it for an access token and a refresh token,
                        // and validated the identity token
                        OnTokenResponseReceived = validatedContext =>
                        {
                            Log.Debug("Validation OnTokenResponseReceived");

                            if (validatedContext != null)
                            {
                                // store both access and refresh token in the claims - hence in the cookie
                                ClaimsIdentity identity = (validatedContext?.Principal?.Identity ?? validatedContext.HttpContext?.User?.Identity) as ClaimsIdentity;

                                if (!string.IsNullOrEmpty(validatedContext?.TokenEndpointResponse.AccessToken))
                                {
                                    Log.Debug("OnTokenValidated: AccessToken = {0}", validatedContext.TokenEndpointResponse.AccessToken);

                                    if (identity != null)
                                    {
                                        identity.AddClaim(new Claim("access_token", validatedContext.TokenEndpointResponse.AccessToken));
                                    }
                                    else
                                    {
                                        Log.Debug("Identity not found in OnTokenResponseReceived, cannot add access_token claim.");
                                    }
                                }

                                string refreshToken = !string.IsNullOrEmpty(validatedContext.TokenEndpointResponse.RefreshToken) ?
                                    validatedContext.TokenEndpointResponse.RefreshToken :
                                    AsyncHelper.RunSync(() => validatedContext.HttpContext.GetTokenAsync("refresh_token"));

                                if (!string.IsNullOrEmpty(refreshToken))
                                {
                                    Log.Debug("OnTokenValidated: RefreshToken = {0}", refreshToken);

                                    if (identity != null)
                                    {
                                        identity.AddClaim(new Claim("refresh_token", refreshToken));
                                    }
                                    else
                                    {
                                        Log.Debug("Identity not found in OnTokenResponseReceived, cannot add refresh_token claim.");
                                    }
                                }

                                // so that we don't issue a session cookie but one with a fixed expiration
                                validatedContext.Properties.IsPersistent = true;

                                // align expiration of the cookie with expiration of the access token
                                if (validatedContext.ProtocolMessage?.AccessToken != null)
                                {
                                    var accessToken = new JwtSecurityToken(validatedContext.ProtocolMessage.AccessToken);
                                    validatedContext.Properties.ExpiresUtc = accessToken.ValidTo;
                                }
                            }

                            return Task.CompletedTask;
                        }
                    };
                });

            // add application authorization with fallback policy.
            services.AddAuthorization(options =>
            {
                options.FallbackPolicy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .Build();
            });

            // Configure the Default CORS configuration.
            services.AddCors(options =>
            {
                options.AddPolicy(
                    Constants.CorsPolicyName,
                    policy =>
                    {
                        policy.AllowAnyMethod();
                        policy.AllowAnyHeader();

                        // if origins defined, restrict them.
                        if (webServerSecurityOptions.AllowedOrigins.Any())
                        {
                            policy.WithOrigins(webServerSecurityOptions.AllowedOrigins.ToArray())
                                .SetIsOriginAllowedToAllowWildcardSubdomains()
                                .AllowCredentials();
                        }
                        else
                        {
                            // otherwise allow any, but most browsers will not allow loading of content.
                            policy.AllowAnyOrigin();
                        }

                        // For CSV or any file download need to expose the headers, otherwise in JavaScript response.getResponseHeader('Content-Disposition')
                        // retuns undefined https://stackoverflow.com/questions/58452531/im-not-able-to-access-response-headerscontent-disposition-on-client-even-aft
                        policy.WithExposedHeaders("Content-Disposition");
                    });
            });

            return services;
        }

        /// <summary>
        /// This extension adds a discovery cache singlton for use by cookie services tracking federated sign-out and backchannel logout calls.
        /// </summary>
        /// <param name="services">The services to extend.</param>
        /// <param name="authorityUri">The Identity Provider Authority URI.</param>
        /// <remarks>Do not call directly if calling <see cref="AddWebServerSecurity(IServiceCollection, WebServerSecurityOptions, bool)" />.</remarks>
        /// <exception cref="ArgumentNullException">Exception is thrown if <paramref name="services" /> or <paramref name="authorityUri" /> are null.</exception>
        public static void AddDiscoveryCache(this IServiceCollection services, Uri authorityUri)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            if (authorityUri == null)
            {
                throw new ArgumentNullException(nameof(authorityUri));
            }

            // setup Http client injectable.
            services.AddHttpClient();

            // add injection of Discovery
            services.AddSingleton<IDiscoveryCache>(r =>
            {
                var factory = r.GetRequiredService<IHttpClientFactory>();
                return new DiscoveryCache(authorityUri.ToString(), () => factory.CreateClient());
            });
        }

        /// <summary>
        /// Adds the logout backchannel handlers for cookie authenticated Web apps as well as refresh token handling.
        /// </summary>
        /// <param name="services">The services.</param>
        /// <param name="options">The options.</param>
        /// <param name="redisConfig">Contains an optional redis configuration string.</param>
        /// <returns>Returns the service collection.</returns>
        /// <remarks>Do not call directly if calling <see cref="AddWebServerSecurity(IServiceCollection, WebServerSecurityOptions, bool)" />.</remarks>
        /// <exception cref="ArgumentNullException">Exception thrown if <paramref name="services" /> or <paramref name="options" /> are null.</exception>
        public static IServiceCollection AddLogoutBackchannelManagement(this IServiceCollection services, IdentityProviderOptions options, string redisConfig = "")
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            // the cookie event handler requires distributed cache, so add here.

            // add distributed cache
            if (!string.IsNullOrWhiteSpace(redisConfig))
            {
                services.AddRedisClientCache(options =>
                {
                    options.Configuration = redisConfig;
                });
            }
            else
            {
                services.AddDistributedMemoryCache();
            }

            services.AddSingleton(new CookieHandlerOptions
            {
                AuthorityUri = options.AuthorityUri,
                ClientId = options.ClientId,
                Secret = options.Secret,
                UseDiscovery = options.UseDiscovery
            });

            services.AddTransient<CookieEventHandler>();
            services.AddSingleton<LogoutSessionManager>();

            services.AddDiscoveryCache(options.AuthorityUri);

            return services;
        }

        #region Private Cookie Policy Methods

        /// <summary>
        /// This method is called to handle the Chrome SameSite issue.
        /// </summary>
        /// <param name="userAgent">Contains the user agent string for the request.</param>
        /// <returns>Returns a value indicating whether disallow same site none.</returns>
        private static bool DisallowsSameSiteNone(string userAgent)
        {
            // Method taken from https://devblogs.microsoft.com/aspnet/upcoming-samesite-cookie-changes-in-asp-net-and-asp-net-core/ Cover all iOS based
            // browsers here. This includes:
            // - Safari on iOS 12 for iPhone, iPod Touch, iPad
            // - WkWebview on iOS 12 for iPhone, iPod Touch, iPad
            // - Chrome on iOS 12 for iPhone, iPod Touch, iPad All of which are broken by SameSite=None, because they use the iOS networking stack.
            return (userAgent.Contains("CPU iPhone OS 12", StringComparison.InvariantCultureIgnoreCase) ||
                userAgent.Contains("iPad; CPU OS 12", StringComparison.InvariantCultureIgnoreCase)) ||

            // Cover Mac OS X based browsers that use the Mac OS networking stack. This includes:
            // - Safari on Mac OS X. This does not include:
            // - Chrome on Mac OS X Because they do not use the Mac OS networking stack.
            (userAgent.Contains("Macintosh; Intel Mac OS X 10_14", StringComparison.InvariantCultureIgnoreCase) &&
                userAgent.Contains("Version/", StringComparison.InvariantCultureIgnoreCase) && userAgent.Contains("Safari", StringComparison.InvariantCultureIgnoreCase)) ||

            // Cover Chrome 50-69, because some versions are broken by SameSite=None, and none in this range require it.
            // Note: this covers some pre-Chromium Edge versions, but pre-Chromium Edge does not require SameSite=None.
            (userAgent.Contains("Chrome/5", StringComparison.InvariantCultureIgnoreCase) || userAgent.Contains("Chrome/6", StringComparison.InvariantCultureIgnoreCase));
        }

        /// <summary>
        /// Handles SameSite cookie issue the default list of user-agents that disallow SameSite None.
        /// </summary>
        /// <param name="options">Contains the cookie policy options.</param>
        /// <returns>Returns new cookie policy options.</returns>
        private static CookiePolicyOptions HandleSameSiteCookieCompatibility(CookiePolicyOptions options)
        {
            // Reference according to the https://docs.microsoft.com/en-us/aspnet/core/security/samesite?view=aspnetcore-3.1. reference was taken from https://devblogs.microsoft.com/aspnet/upcoming-samesite-cookie-changes-in-asp-net-and-asp-net-core/
            return HandleSameSiteCookieCompatibility(options, DisallowsSameSiteNone);
        }

        /// <summary>
        /// Handles SameSite cookie issue according to the docs The default list of user-agents that disallow SameSite None.
        /// </summary>
        /// <param name="options">Contains existing cookie policies.</param>
        /// <param name="disallowsSameSiteNone">
        /// If you don't want to use the default user-agent list implementation, the method sent in this parameter will be run against the user-agent and if
        /// returned true, SameSite value will be set to Unspecified.
        /// </param>
        /// <returns>Returns a new Cookie policy.</returns>
        private static CookiePolicyOptions HandleSameSiteCookieCompatibility(CookiePolicyOptions options, Func<string, bool> disallowsSameSiteNone)
        {
            // reference https://docs.microsoft.com/en-us/aspnet/core/security/samesite?view=aspnetcore-3.1 reference was taken from
            // https://devblogs.microsoft.com/aspnet/upcoming-samesite-cookie-changes-in-asp-net-and-asp-net-core/ The default user-agent list used can be found
            // at: https://devblogs.microsoft.com/aspnet/upcoming-samesite-cookie-changes-in-asp-net-and-asp-net-core/
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            options.MinimumSameSitePolicy = SameSiteMode.Unspecified;
            options.OnAppendCookie = cookieContext => CheckSameSite(cookieContext.Context, cookieContext.CookieOptions, disallowsSameSiteNone);
            options.OnDeleteCookie = cookieContext => CheckSameSite(cookieContext.Context, cookieContext.CookieOptions, disallowsSameSiteNone);

            return options;
        }

        /// <summary>
        /// This method is used to check the same site and set Same Site based on browser.
        /// </summary>
        /// <param name="httpContext">Contains the context.</param>
        /// <param name="options">Contains cookie options.</param>
        /// <param name="disallowsSameSiteNone">Contains a function used to disallow.</param>
        private static void CheckSameSite(HttpContext httpContext, CookieOptions options, Func<string, bool> disallowsSameSiteNone)
        {
            if (options.SameSite == SameSiteMode.None)
            {
                var userAgent = httpContext.Request.Headers["User-Agent"].ToString();
                if (disallowsSameSiteNone(userAgent))
                {
                    options.SameSite = SameSiteMode.Unspecified;
                }
            }
        }

        #endregion
    }
}