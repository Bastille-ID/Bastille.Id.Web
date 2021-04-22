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
    using Microsoft.AspNetCore.Builder;

    /// <summary>
    /// This class contains extension methods to help with the configuration of a web applcation.
    /// </summary>
    public static class ApplicationBuilderExtensions
    {
        /// <summary>
        /// Adds the application security configuration to the Application builder on web app startup.
        /// </summary>
        /// <param name="app">The application builder to extend.</param>
        /// <param name="appSecurityOptions">The application security options.</param>
        /// <param name="headerPolicy">Contains an optional header policy to apply instead of the default built from settings in <paramref name="appSecurityOptions" />.</param>
        /// <returns>Returns the application builder.</returns>
        /// <exception cref="ArgumentNullException">Exception thrown if <paramref name="app" /> or <paramref name="appSecurityOptions" /> are null.</exception>
        public static IApplicationBuilder AddApplicationSecurity(this IApplicationBuilder app, ApplicationSecurityOptions appSecurityOptions, HeaderPolicyCollection headerPolicy = null)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            if (appSecurityOptions == null)
            {
                throw new ArgumentNullException(nameof(appSecurityOptions));
            }

            if (appSecurityOptions.ForceSsl)
            {
                app.UseHttpsRedirection();
            }

            // this will exclude localhost already, otherwise add HSTS header.
            app.UseHsts();

            // define the security headers policy
            var policyCollection = headerPolicy ?? new HeaderPolicyCollection()
                .AddXssProtectionBlock()
                .AddContentTypeOptionsNoSniff()
                .AddReferrerPolicyNoReferrer()
                .RemoveServerHeader()
                .AddContentSecurityPolicy(builder =>
                {
                    builder.AddDefaultSrc().Self().From(appSecurityOptions.CspAllowedOrigin).UnsafeInline().UnsafeEval();

                    if (!string.IsNullOrWhiteSpace(appSecurityOptions.CspAllowedOrigin))
                    {
                        builder.AddFrameAncestors().From(appSecurityOptions.CspAllowedOrigin);
                    }

                    builder.AddImgSrc().Self().From(appSecurityOptions.CspImageSources + " data:");
                    builder.AddObjectSrc().None();
                    builder.AddBaseUri().Self().From(appSecurityOptions.CspAllowedOrigin);
                });

            // add security headers to responses.
            app.UseSecurityHeaders(policyCollection);

            return app;
        }
    }
}