using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
    // also be stored.

    // This core Auth class delegates all UI and actions to the caller through an IAuthClient
    // interface. This includes updating UI when auth information is available.

    public interface IAuthClient
    {

    }

    public class Auth
    {

    }
}
