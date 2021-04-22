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
    using System.Collections.Generic;
    using System.Reflection;
    using Bastille.Id.Web.UI.Areas.BastilleIdentity.Controllers;
    using Microsoft.AspNetCore.Mvc.ApplicationParts;
    using Microsoft.AspNetCore.Mvc.Controllers;

    /// <summary>
    /// This class contains methods for populating web app features.
    /// </summary>
    /// <seealso cref="IApplicationFeatureProvider{ControllerFeature}" />
    internal class BastilleIdentityAccountControllerFeatureProvider : IApplicationFeatureProvider<ControllerFeature>
    {
        /// <summary>
        /// Updates the <paramref name="feature" /> instance.
        /// </summary>
        /// <param name="parts">The list of <see cref="T:Microsoft.AspNetCore.Mvc.ApplicationParts.ApplicationPart" /> instances in the application.</param>
        /// <param name="feature">The feature instance to populate.</param>
        /// <remarks>
        /// <see cref="T:Microsoft.AspNetCore.Mvc.ApplicationParts.ApplicationPart" /> instances in <paramref name="parts" /> appear in the same ordered
        /// sequence they are stored in <see cref="P:Microsoft.AspNetCore.Mvc.ApplicationParts.ApplicationPartManager.ApplicationParts" />. This ordering may be
        /// used by the feature provider to make precedence decisions.
        /// </remarks>
        public void PopulateFeature(IEnumerable<ApplicationPart> parts, ControllerFeature feature)
        {
            if (!feature.Controllers.Contains(typeof(AccountController).GetTypeInfo()))
            {
                feature.Controllers.Add(typeof(AccountController).GetTypeInfo());
            }
        }
    }
}