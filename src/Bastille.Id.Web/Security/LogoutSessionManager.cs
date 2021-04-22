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
    using System.Globalization;
    using System.Linq;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.Extensions.Caching.Distributed;
    using Vasont.AspnetCore.RedisClient;

    /// <summary>
    /// This class manages the logout session tracking.
    /// </summary>
    public class LogoutSessionManager
    {
        /// <summary>
        /// Contains the cache service used to store logged out sessions sent from the backchannel.
        /// </summary>
        private readonly IDistributedCache cache;

        /// <summary>
        /// Initializes a new instance of the <see cref="LogoutSessionManager" /> class.
        /// </summary>
        /// <param name="distributedCache">Contains the distributed cache mechanism.</param>
        public LogoutSessionManager(IDistributedCache distributedCache)
        {
            this.cache = distributedCache;
        }

        /// <summary>
        /// This method is used to add a logout session to the cache.
        /// </summary>
        /// <param name="sub">Contains the subject identity.</param>
        /// <param name="sid">Contains the session identity.</param>
        /// <param name="timeoutMinutes">Contains the timeout in minutes to store in cache.</param>
        /// <returns>Returns a task.</returns>
        public Task AddAsync(string sub, string sid, int timeoutMinutes)
        {
            if (string.IsNullOrWhiteSpace(sub))
            {
                throw new ArgumentNullException(nameof(sub));
            }

            if (string.IsNullOrWhiteSpace(sid))
            {
                throw new ArgumentNullException(nameof(sid));
            }

            if (timeoutMinutes <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(timeoutMinutes));
            }

            return this.AddStringAsync(sub, sid, timeoutMinutes);
        }

        /// <summary>
        /// This method is used to determine if a session was logged out.
        /// </summary>
        /// <param name="sub">Contains the subject identity.</param>
        /// <param name="sid">Contains the session identity.</param>
        /// <param name="cancellationToken">Contains a cancellation token.</param>
        /// <returns>Returns a value indicating whether the session was logged out.</returns>
        public async Task<bool> IsLoggedOutAsync(string sub, string sid, CancellationToken cancellationToken = default)
        {
            bool result;
            string key = $"logout_{sub}_{sid}";
            IAdvancedDistributedCache advancedCache = this.cache as IAdvancedDistributedCache;

            if (advancedCache != null)
            {
                result = (await advancedCache.FindKeysAsync(key, cancellationToken).ConfigureAwait(false)).Any();
            }
            else
            {
                result = !string.IsNullOrEmpty(await this.cache.GetStringAsync(key, cancellationToken).ConfigureAwait(false));
            }

            return result;
        }

        /// <summary>
        /// This method is used to add a logout session to the cache.
        /// </summary>
        /// <param name="sub">Contains the subject identity.</param>
        /// <param name="sid">Contains the session identity.</param>
        /// <param name="timeoutMinutes">Contains the timeout in minutes to store in cache.</param>
        /// <returns>Returns a task.</returns>
        private async Task AddStringAsync(string sub, string sid, int timeoutMinutes)
        {
            await this.cache.SetStringAsync(
                $"logout_{sub}_{sid}",
                DateTime.UtcNow.ToString(CultureInfo.CurrentCulture),
                new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(timeoutMinutes)
                }).ConfigureAwait(false);
        }
    }
}