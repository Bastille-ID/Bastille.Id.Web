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

    /// <summary>
    /// This class contains settings for application security configuration.
    /// </summary>
    public class ApplicationSecurityOptions
    {
        /// <summary>
        /// Gets or sets a value indicating whether to always require SSL when optional.
        /// </summary>
        public bool ForceSsl { get; set; } = true;

        /// <summary>
        /// Gets or sets the CSP allowed origin.
        /// </summary>
        /// <value>The CSP allowed origin.</value>
        public string CspAllowedOrigin { get; set; } = "*";

        /// <summary>
        /// Gets or sets the CSP image sources.
        /// </summary>
        /// <value>The CSP image sources.</value>
        public string CspImageSources { get; set; } = "*";
    }
}