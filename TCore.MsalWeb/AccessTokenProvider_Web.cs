using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using Microsoft.Identity.Client;

namespace TCore.MsalWeb
{
    class AccessTokenProviderWeb : WebApiInterop.IAccessTokenProvider
    {
        private string m_sScopeWebApi;
        private string m_sAppKey;
        private string m_sAuthority;
        private string m_sClientID;
        private string m_sRedirectUri;
        private HttpContext m_context;
        private HttpServerUtility m_server;

        public AccessTokenProviderWeb(HttpContext context,
            HttpServerUtility server,
            string sClientId,
            string sAuthority,
            string sAppKey,
            string sRedirectUri,
            string sScopeWebApi)
        {
            m_context = context;
            m_server = server;
            m_sScopeWebApi = sScopeWebApi;
            m_sAppKey = sAppKey;
            m_sAuthority = sAuthority;
            m_sClientID = sClientId;
            m_sRedirectUri = sRedirectUri;
        }

        /*----------------------------------------------------------------------------
            %%Function: GetUserId
            %%Qualified: TCore.MsalWeb.WebApiInterop.ProcessResponse

            convenient way to get the current user id (so we can get to the right
            TokenCache)
        ----------------------------------------------------------------------------*/
        string GetUserId()
        {
            if (ClaimsPrincipal.Current == null)
                return null;

            return ClaimsPrincipal.Current.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        }

        /*----------------------------------------------------------------------------
            %%Function: GetContextBase
            %%Qualified: TCore.MsalWeb.WebApiInterop.ProcessResponse

            get the HttpContextBase we can use for the SessionState (which is needed
            by our TokenCache implemented by MSALSessionCache
        ----------------------------------------------------------------------------*/
        HttpContextBase GetContextBase()
        {
            return m_context.GetOwinContext().Environment["System.Web.HttpContextBase"] as HttpContextBase;
        }

        /*----------------------------------------------------------------------------
            %%Function: GetAccessToken
            %%Qualified: TCore.MsalWeb.WebApiInterop.ProcessResponse

            Get an access token for accessing the WebApi. This will use 
            AcquireTokenSilentAsync to get the token. Since this is using the 
            same tokencache as we populated when the user logged in, we will
            get the access token from that cache. 
        ----------------------------------------------------------------------------*/
        public string GetAccessToken()
        {
            return GetAccessTokenForScope(new string[] { m_sScopeWebApi });
        }

        public string GetAccessTokenForScope(string[] rgsScopes)
        {
            // Retrieve the token with the specified scopes
            string userId = GetUserId();
            TokenCache tokenCache = new MSALSessionCache(userId, GetContextBase()).GetMsalCacheInstance();
            ConfidentialClientApplication cca = new ConfidentialClientApplication(m_sClientID, m_sAuthority,
                m_sRedirectUri, new ClientCredential(m_sAppKey), tokenCache, null);

            Task<IEnumerable<IAccount>> tskAccounts = cca.GetAccountsAsync();
            tskAccounts.Wait();

            IAccount account = tskAccounts.Result.FirstOrDefault();
            if (account == null)
                return null;

            Task<AuthenticationResult> tskResult =
                cca.AcquireTokenSilentAsync(rgsScopes, account, m_sAuthority, false);

            tskResult.Wait();
            return tskResult.Result.AccessToken;
        }

        /*----------------------------------------------------------------------------
            %%Function: FTokenCachePopulated
            %%Qualified: TCore.MsalWeb.WebApiInterop.ProcessResponse

            return true if our TokenCache has been populated for the current 
            UserId.  Since our TokenCache is currently only stored in the session, 
            if our session ever gets reset, we might get into a state where there
            is a cookie for auth (and will let us automatically login), but the
            TokenCache never got populated (since it is only populated during the
            actual authentication process). If this is the case, we need to treat
            this as if the user weren't logged in. The user will SignIn again, 
            populating the TokenCache.
        ----------------------------------------------------------------------------*/
        public bool FTokenCachePopulated()
        {
            return MSALSessionCache.CacheExists(GetUserId(), GetContextBase());
        }
    }

}
