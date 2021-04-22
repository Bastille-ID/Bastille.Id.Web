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

namespace Bastille.Id.Web.UI
{
    using System;
    using Microsoft.AspNetCore.Authentication.Cookies;
    using Microsoft.AspNetCore.Http;
    using Microsoft.Extensions.DependencyInjection;

    /// <summary>
    /// Extension method on <see cref="IMvcBuilder" /> to add UI for applications that integrate with the Bastille.ID Identity Platform.
    /// </summary>
    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Adds a controller and Razor pages for the accounts management.
        /// </summary>
        /// <param name="builder">MVC builder.</param>
        /// <returns>MVC builder for chaining.</returns>
        public static IMvcBuilder AddIdentityUI(this IMvcBuilder builder)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            builder.ConfigureApplicationPartManager(apm =>
            {
                apm.FeatureProviders.Add(new BastilleIdentityAccountControllerFeatureProvider());
            });

            builder.Services.ConfigureAll<CookieAuthenticationOptions>(options =>
            {
                if (string.IsNullOrEmpty(options.AccessDeniedPath))
                {
                    options.AccessDeniedPath = new PathString("/BastilleIdentity/Account/AccessDenied");
                }
            });

            return builder;
        }
    }
}