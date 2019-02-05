using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Remoting;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;
using System.Web.SessionState;
using System.Web.UI;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;

namespace TCore.MsalWeb
{
    // Uses a combination of page and session variables to maintain authentication state
    // (session variables are used to allow single sign-in for multiple pages on the same
    // website)

    // The intended uses for this class is to connect Authentication (from MSAL) and Authorization
    // (from your local application).  
    //
    // MSAL will provide an identity and an authority.  YOU CANNOT TRUST JUST THE IDENTITY -- this is
    // meaningless without the authority. (Authority is also referred to as Tenant). 
    // If you intend to just use Microsoft Accounts (onedrive.com, live.com, etc.), then you 
    // will be using the Microsoft Consumer authority. (provded predefined in the class). Others
    // will require that you provide the GUID for that authority.
    //
    // Once the class establishes Authentication with Identity/Authority, this will delegate back
    // to the client the responsibility of loading specific privileges for this user. Those will
    // also be stored. The combination of Auth and Priv data will be stored in a client 
    // supplied AuthPrivs type.  (Setting of Auth data in this type will also be delegated
    // to the client via IAuthClient)

    // This core Auth class delegates all UI and actions to the caller through an IAuthClient
    // interface. This includes updating UI when auth information is available.

    public interface IAuthClient<TAuthPrivData>
    {
        void BeforeLogin(object sender, EventArgs e);
        void BeforeLogout(object sender, EventArgs e);
        TAuthPrivData CreateEmpty();
        void SetAuthenticated(bool fAuthenticated);
        bool AuthIsAuthenticated();
        bool AuthHasPrivileges();
    }

    public class Auth<TAuthPrivData>
    {
        private HttpRequest m_request;
        private string m_sAuthReturnAddress;
        private HttpContextBase m_contextBase;
        private IOwinContext m_owinContext;
        private StateBag m_viewState;
        private HttpSessionState m_session;
        private IAuthClient<TAuthPrivData> m_iclient;

        public Auth(
            HttpRequest request,
            HttpSessionState session,
            HttpContextBase contextBase,
            IOwinContext iOwinContext,
            StateBag viewState,
            string sReturnAddress,
            IAuthClient<TAuthPrivData> authClient)
        {
            m_sAuthReturnAddress = sReturnAddress;
            m_request = request;
            m_contextBase = contextBase;
            m_owinContext = iOwinContext;
            m_viewState = viewState;
            m_session = session;
            m_iclient = authClient;

            LoadCachedPrivs();
        }

        #region State Management
        /*----------------------------------------------------------------------------
        	%%Function: SetState
        	%%Qualified: TCore.MsalWeb.Auth<TUserData>.SetState<T>
        	
        ----------------------------------------------------------------------------*/
        void SetState<T>(string sState, T tValue)
        {
            m_viewState[sState] = tValue;
        }

        /*----------------------------------------------------------------------------
        	%%Function: TGetSessionState
        	%%Qualified: TCore.MsalWeb.Auth<TUserData>.TGetSessionState<T>
        	
        ----------------------------------------------------------------------------*/
        T TGetSessionState<T>(string sState, T tDefault)
        {
            T tValue = tDefault;

            if (m_session[sState] == null)
                m_session[sState] = tValue;
            else
                tValue = (T)m_session[sState];

            return tValue;
        }

        /*----------------------------------------------------------------------------
        	%%Function: SetSessionState
        	%%Qualified: TCore.MsalWeb.Auth<TUserData>.SetSessionState<T>
        	        	
        ----------------------------------------------------------------------------*/
        void SetSessionState<T>(string sState, T tValue)
        {
            m_session[sState] = tValue;
        }

        /*----------------------------------------------------------------------------
        	%%Function: TGetState
        	%%Qualified: TCore.MsalWeb.Auth<TUserData>.TGetState<T>
        	        	
        ----------------------------------------------------------------------------*/
        T TGetState<T>(string sState, T tDefault)
        {
            T tValue = tDefault;

            if (m_viewState[sState] == null)
                m_viewState[sState] = tValue;
            else
                tValue = (T)m_viewState[sState];

            return tValue;
        }
        #endregion

        #region Interogate Auth Information/State

        public TAuthPrivData AuthPrivData
        {
            get => TGetSessionState("privs", m_iclient.CreateEmpty());
            set => SetSessionState("privs", value);
        }

        public bool IsAuthenticated()
        {
            return IsSignedIn();
        }

        public bool IsLoggedIn => m_iclient.AuthHasPrivileges();

        public string Identity()
        {
            if (IsAuthenticated())
                return System.Security.Claims.ClaimsPrincipal.Current.FindFirst("preferred_username")?.Value;

            return null;
        }

        public string Tenant()
        {
            if (IsAuthenticated())
            {
                Regex rex = new Regex("https://login.microsoftonline.com/([^/]*)/");

                return rex.Match(System.Security.Claims.ClaimsPrincipal.Current.FindFirst("iss")?.Value).Groups[1].Value;
            }

            return null;
        }
        #endregion

        void LoadCachedPrivs()
        {
            if (!IsAuthenticated())
            {
                // make sure current privs aren't leaked from before
                TAuthPrivData data = m_iclient.CreateEmpty();

                AuthPrivData = data;
            }
        }

        /*----------------------------------------------------------------------------
        	%%Function: SignIn
        	%%Qualified: TCore.MsalWeb.Auth<TAuthPrivData>.SignIn
        
            Send an OpenID Connect sign-in request.
        ----------------------------------------------------------------------------*/
        public void SignIn(object sender, EventArgs e)
        {
            m_iclient.BeforeLogin(sender, e);

            if (!IsAuthenticated())
            {
                m_owinContext.Authentication.Challenge(
                    new AuthenticationProperties { RedirectUri = m_sAuthReturnAddress },
                    OpenIdConnectAuthenticationDefaults.AuthenticationType);
            }
        }

        /*----------------------------------------------------------------------------
        	%%Function: SignOut
        	%%Qualified: TCore.MsalWeb.Auth<TAuthPrivData>.SignOut
        	
            Send an OpenID Connect sign-out request.
        ----------------------------------------------------------------------------*/
        public void SignOut(object sender, EventArgs e)
        {
            m_iclient.BeforeLogout(sender, e);
            HttpContext.Current.GetOwinContext().Authentication.SignOut(
                OpenIdConnectAuthenticationDefaults.AuthenticationType,
                CookieAuthenticationDefaults.AuthenticationType);
        }

        /*----------------------------------------------------------------------------
        	%%Function: GetUserId
        	%%Qualified: WebApp._default.GetUserId
        	
            convenient way to get the current user id (so we can get to the right
            TokenCache)
        ----------------------------------------------------------------------------*/
        string GetUserId()
        {
            return ClaimsPrincipal.Current?.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        }

        /*----------------------------------------------------------------------------
        	%%Function: IsSignedIn
        	%%Qualified: WebApp._default.IsSignedIn
        	
            return true if the signin process is complete -- this includes making 
            sure there is an entry for this userid in the TokenCache
        ----------------------------------------------------------------------------*/
        public bool IsSignedIn()
        {
            return m_request.IsAuthenticated && FTokenCachePopulated();
        }

        /*----------------------------------------------------------------------------
        	%%Function: FTokenCachePopulated
        	%%Qualified: WebApp._default.FTokenCachePopulated
        	
        	return true if our TokenCache has been populated for the current 
            UserId.  Since our TokenCache is currently only stored in the session, 
            if our session ever gets reset, we might get into a state where there
            is a cookie for auth (and will let us automatically login), but the
            TokenCache never got populated (since it is only populated during the
            actual authentication process). If this is the case, we need to treat
            this as if the user weren't logged in. The user will SignIn again, 
            populating the TokenCache.
        ----------------------------------------------------------------------------*/
        bool FTokenCachePopulated()
        {
            return MSALSessionCache.CacheExists(GetUserId(), m_contextBase);
        }


    }
}
