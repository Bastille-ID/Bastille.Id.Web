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

namespace Microsoft.Identity.Web.UI.Areas.MicrosoftIdentity.Pages.Account
{
    using System.Diagnostics;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.RazorPages;
    using Talegen.Common.Core.Errors;

    /// <summary>
    /// Model for the Error page.
    /// </summary>
    [AllowAnonymous]
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public class ErrorModel : PageModel
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ErrorModel" /> class.
        /// </summary>
        /// <param name="errorAccessor">Error message.</param>
        public ErrorModel(ErrorMessage errorAccessor)
        {
            this.Error = errorAccessor;
        }

        /// <summary>
        /// This API supports infrastructure and is not intended to be used directly from your code. This API may change or be removed in future releases.
        /// </summary>
        public string RequestId { get; set; }

        /// <summary>
        /// This API supports infrastructure and is not intended to be used directly from your code. This API may change or be removed in future releases.
        /// </summary>
        public bool ShowRequestId => !string.IsNullOrEmpty(this.RequestId);

        /// <summary>
        /// This API supports infrastructure and is not intended to be used directly from your code. This API may change or be removed in future releases.
        /// </summary>
        public ErrorMessage Error { get; }

        /// <summary>
        /// This API supports infrastructure and is not intended to be used directly from your code. This API may change or be removed in future releases.
        /// </summary>
        public void OnGet()
        {
            this.RequestId = Activity.Current?.Id ?? this.HttpContext.TraceIdentifier;
        }
    }
}