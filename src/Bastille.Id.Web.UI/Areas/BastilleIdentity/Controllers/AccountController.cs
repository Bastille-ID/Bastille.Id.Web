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

namespace Bastille.Id.Web.UI.Areas.BastilleIdentity.Controllers
{
    using System.Collections.Generic;
    using System.Threading.Tasks;
    using Bastille.Id.Web;
    using Bastille.Id.Web.AppServices;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Authentication.Cookies;
    using Microsoft.AspNetCore.Authentication.OAuth;
    using Microsoft.AspNetCore.Authentication.OpenIdConnect;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.Extensions.Options;

    /// <summary>
    /// Controller used in web apps to manage accounts.
    /// </summary>
    [NonController]
    [AllowAnonymous]
    [Area("BastilleIdentity")]
    [Route("[area]/[controller]/[action]")]
    public class AccountController : Controller
    {
        /// <summary>
        /// Contains the identity options.
        /// </summary>
        private readonly IOptions<BastilleIdentityOptions> options;

        /// <summary>
        /// Initializes a new instance of the <see cref="AccountController" /> class.
        /// </summary>
        /// <param name="bastilleIdentityOptions">The bastille identity options.</param>
        public AccountController(IOptions<BastilleIdentityOptions> bastilleIdentityOptions)
        {
            this.options = bastilleIdentityOptions;
        }

        /// <summary>
        /// Handles user sign in.
        /// </summary>
        /// <param name="scheme">Authentication scheme.</param>
        /// <returns>Challenge generating a redirect to Azure AD to sign in the user.</returns>
        [HttpGet("{scheme?}")]
        public IActionResult SignIn([FromRoute] string scheme)
        {
            scheme ??= OpenIdConnectDefaults.AuthenticationScheme;
            string redirectUrl = this.Url.Content("~/");
            return this.Challenge(new AuthenticationProperties { RedirectUri = redirectUrl }, scheme);
        }

        /// <summary>
        /// Challenges the user.
        /// </summary>
        /// <param name="redirectUri">Redirect URI.</param>
        /// <param name="scope">Scopes to request.</param>
        /// <param name="loginHint">Login hint.</param>
        /// <param name="domainHint">Domain hint.</param>
        /// <param name="claims">Claims.</param>
        /// <param name="policy">AAD B2C policy.</param>
        /// <returns>Challenge generating a redirect to Azure AD to sign in the user.</returns>
        [HttpGet("{scheme?}")]
        public IActionResult Challenge(
            string redirectUri,
            string scope,
            string loginHint,
            string domainHint,
            string claims,
            string policy)
        {
            string scheme = OpenIdConnectDefaults.AuthenticationScheme;

            Dictionary<string, string> items = new Dictionary<string, string>
            {
                { Constants.Claims, claims },
                { Constants.Policy, policy },
            };

            Dictionary<string, object> parameters = new Dictionary<string, object>
            {
                { Constants.LoginHint, loginHint },
                { Constants.DomainHint, domainHint },
            };

            OAuthChallengeProperties oauthChallengeProperties = new OAuthChallengeProperties(items, parameters);
            oauthChallengeProperties.Scope = scope?.Split(' ');
            oauthChallengeProperties.RedirectUri = redirectUri;

            return this.Challenge(oauthChallengeProperties, scheme);
        }

        /// <summary>
        /// Represents an event that is raised when the sign-out operation is complete.
        /// </summary>
        /// <param name="scheme">Authentication scheme.</param>
        /// <returns>Sign out result.</returns>
        [HttpGet("{scheme?}")]
        public IActionResult SignOut([FromRoute] string scheme)
        {
            IActionResult actionResult;

            if (AppServicesAuthenticationInformation.IsAppServicesAuthenticationEnabled)
            {
                actionResult = this.LocalRedirect(AppServicesAuthenticationInformation.LogoutUrl);
            }
            else
            {
                scheme ??= OpenIdConnectDefaults.AuthenticationScheme;
                string callbackUrl = this.Url.Content("~/");
                actionResult = this.SignOut(
                    new AuthenticationProperties
                    {
                        RedirectUri = callbackUrl,
                    },
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    scheme);
            }

            return actionResult;
        }

        /// <summary>
        /// In B2C applications handles the Reset password policy.
        /// </summary>
        /// <param name="scheme">Authentication scheme.</param>
        /// <returns>Challenge generating a redirect to Azure AD B2C.</returns>
        [HttpGet("{scheme?}")]
        public IActionResult ResetPassword([FromRoute] string scheme)
        {
            scheme ??= OpenIdConnectDefaults.AuthenticationScheme;

            var redirectUrl = this.Url.Content("~/");
            var properties = new AuthenticationProperties { RedirectUri = redirectUrl };
            properties.Items[Constants.Policy] = this.options.Value?.ResetPasswordPolicyId;
            return this.Challenge(properties, scheme);
        }

        /// <summary>
        /// In B2C applications, handles the Edit Profile policy.
        /// </summary>
        /// <param name="scheme">Authentication scheme.</param>
        /// <returns>Challenge generating a redirect to Azure AD B2C.</returns>
        [HttpGet("{scheme?}")]
        public async Task<IActionResult> EditProfile([FromRoute] string scheme)
        {
            IActionResult actionResult = null;
            scheme ??= OpenIdConnectDefaults.AuthenticationScheme;
            AuthenticateResult authenticated = await this.HttpContext.AuthenticateAsync(scheme).ConfigureAwait(false);

            if (authenticated.Succeeded)
            {
                string redirectUrl = this.Url.Content("~/");
                AuthenticationProperties properties = new AuthenticationProperties { RedirectUri = redirectUrl };
                properties.Items[Constants.Policy] = this.options.Value?.EditProfilePolicyId;
                actionResult = this.Challenge(properties, scheme);
            }
            else
            {
                actionResult = this.Challenge(scheme);
            }

            return actionResult;
        }
    }
}