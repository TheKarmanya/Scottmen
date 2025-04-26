using BaseClass;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Net.Http.Headers;
using ScottmenMainApi.Models.BLayer;
using ScottmenMainApi.Models.DLayer;
using static BaseClass.ReturnClass;

namespace ScottmenMainApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        readonly DlUser dl = new();
        readonly DlCommon dlCommon = new();
        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<UserLoginResponse> Authenticate([FromBody] UserLoginRequest ulr)
        {
            UserLoginResponse userLoginResponse = new();
            try
            {
                ReturnBool rb = new();
                LoginTrail ltr = new();
               

                    ltr.userAgent = Request.Headers[HeaderNames.UserAgent];
                    BrowserContext br = Utilities.DetectBrowser(ltr.userAgent);
                    ltr.clientOs = br.OS;
                    ltr.clientBrowser = br.BrowserName;
                    ltr.accessMode = VerifyAppKey(this.HttpContext);
                    //ltr.loginSource = "" ;
                    ltr.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
                    ltr.logCategory = EventLogCategory.AccountAccess;
                    ReturnBool tokenVerified = await dlCommon.VerifyRequestToken(ulr.requestToken!);
                    tokenVerified.status = true;
                    if (tokenVerified.status)
                        userLoginResponse = await dl.CheckUserLogin(ulr, ltr);
                    else
                        userLoginResponse.message = "Invalid Credential. Request has been tempered.";
               
            }
            catch (Exception ex)
            {
                WriteLog.Error("Login Error", ex);
                userLoginResponse.message = ex.Message;

            }
            return userLoginResponse;
        }

        /// <summary>
        /// Use this method for mobile App authentication
        /// </summary>
        /// <param name="tokenModel"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpPost("refreshtoken")]
        public async Task<UserLoginResponseSessionExtension> RefreshToken(TokenModel tokenModel)
        {
            //=======Logic===========
            /* Check whether Token is valid or not
             * Retrive identity from DB to check whether the user id exist or not in the DB from the valid token 
             * check whether refresh token expiry is remaining or not, if no then proceed
             * create new jwt and refresh token with same logic
             * */
            return await RefreshSession(tokenModel, AccessMode.MobileApp);
        }

        /// <summary>
        /// Use this method to exten session of an authenticated user. For WebPortal only
        /// </summary>
        /// <param name="tokenModel"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpPost("refreshwebtoken")]
        public async Task<UserLoginResponseSessionExtension> ExtendWebSession(TokenModel tokenModel)
        {
            return await RefreshSession(tokenModel, AccessMode.WebPortal);
        }
        /// <summary>
        /// Refresh Session with valid token
        /// </summary>
        /// <param name="tokenModel"></param>
        /// <param name="accessMode"></param>
        /// <returns></returns>
        private async Task<UserLoginResponseSessionExtension> RefreshSession(TokenModel tokenModel, AccessMode accessMode)
        {
            UserLoginResponseSessionExtension userLoginResponse = new();
            //            if (accessMode == AccessMode.WebPortal)
            //            {
            //#pragma warning disable CS8600 // Converting null literal or possible null value to non-nullable type.
            //                string authHeaders = HttpContext.Request.Headers.FirstOrDefault(x => x.Key == "Authorization").Value.FirstOrDefault();
            //#pragma warning restore CS8600 // Converting null literal or possible null value to non-nullable type.
            //                if (authHeaders is not null || authHeaders != "")
            //                {
            //#pragma warning disable CS8602 // Dereference of a possibly null reference.
            //                    tokenModel.authToken = authHeaders.Replace("Bearer", "").TrimStart();
            //#pragma warning restore CS8602 // Dereference of a possibly null reference.
            //                }
            //            }

            if (tokenModel is null)
                userLoginResponse.message = "Invalid client request";
            else
            {
                var principalClaims = Helper.GetPrincipalFromExpiredToken(tokenModel.authToken);
                if (principalClaims == null)
                {
                    userLoginResponse.message = "Invalid access token or refresh token";
                }
                else
                {
#pragma warning disable CS8602 // Dereference of a possibly null reference.
                    string? userIdStr = principalClaims.FindFirst("userId")?.Value;
#pragma warning restore CS8602 // Dereference of a possibly null reference.
                    if (userIdStr != null || userIdStr != "")
                    {
                        LoginTrail ltr = new();
                        ltr.userAgent = Request.Headers[HeaderNames.UserAgent];
                        BrowserContext br = Utilities.DetectBrowser(ltr.userAgent);
                        ltr.clientOs = br.OS;
                        ltr.clientBrowser = br.BrowserName;
                        ltr.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
                        ltr.logCategory = EventLogCategory.LoginExtended;
                        ltr.currentAuthToken = tokenModel.authToken;
                        ltr.userId = Convert.ToInt64(userIdStr);
                        ltr.accessMode = VerifyAppKey(this.HttpContext);
                        if (ltr.accessMode == AccessMode.WebPortal && ltr.accessMode == accessMode)
                        {
                            UserLoginResponse ulr = await dl.GetAuthenticationTokenDetails(ltr.currentAuthToken);
                            bool extendSession = false;
                            if (ulr.refreshToken != tokenModel.refreshToken || ulr.refreshTokenExpiryTime <= DateTime.Now)
                            {
                                userLoginResponse.message = "Invalid access token or refresh token";
                            }
                            else
                                extendSession = true;

                            if (extendSession)
                                userLoginResponse = await dl.ExtendUserLoginSession(ltr, principalClaims);
                        }
                        else
                            userLoginResponse.message = "Invalid token.";
                    }
                    else
                        userLoginResponse.message = "Invaild token supplied";
                }
            }
            return userLoginResponse;
        }
        /// <summary>
        /// Identify Accessmode based on HTTP Header App Key
        /// </summary>
        /// <returns></returns>
        private AccessMode VerifyAppKey(HttpContext httpContext)
        {
#pragma warning disable CS8600 // Converting null literal or possible null value to non-nullable    type.
            string headers = httpContext.Request.Headers.FirstOrDefault(x => x.Key == "appkey").Value.FirstOrDefault();
#pragma warning restore CS8600 // Converting null literal or possible null value to non-nullable type.
            //string headers = GetHttpHeader(this.HttpContext.Request, "appkey");
            ReturnBool rbKey = Utilities.GetAppSettings("AppSettings", "MobileAppKey");
            string appKey = rbKey.status ? rbKey.message : "appkey";
            if (headers == appKey)
                return AccessMode.MobileApp;
            else
                return AccessMode.WebPortal;
        }

        /// <summary>
        /// Log out user
        /// </summary>
        /// <returns></returns>
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        [HttpGet("logout")]
        public async Task<ReturnBool> LogOutUser()
        {
#pragma warning disable CS8600 // Converting null literal or possible null value to non-nullable type.
            string authHeaders = HttpContext.Request.Headers.FirstOrDefault(x => x.Key == "Authorization").Value.FirstOrDefault();
#pragma warning restore CS8600 // Converting null literal or possible null value to non-nullable type.
            if (authHeaders is not null || authHeaders != "")
            {
#pragma warning disable CS8602 // Dereference of a possibly null reference.
                authHeaders = authHeaders.Replace("Bearer", "").TrimStart();
#pragma warning restore CS8602 // Dereference of a possibly null reference.
            }
            LoginTrail ltr = new();
            ltr.userAgent = Request.Headers[HeaderNames.UserAgent];
            BrowserContext br = Utilities.DetectBrowser(ltr.userAgent);

            ltr.clientOs = br.OS;
            ltr.clientBrowser = br.BrowserName;
            ltr.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            ltr.logCategory = EventLogCategory.LogOut;
            ltr.currentAuthToken = authHeaders;
            return await dl.LogOutUser(ltr);
        }

        [HttpPost("Checkemailforlogin")]
        public async Task<ReturnBool> CheckUserAccountExist([FromBody] UserLoginWithOTP ulr)
        {
            //string captchaVerificationUrl = Utilities.GetAppSettings("CaptchaVerificationURL", "URL").message;
            ReturnBool rbBuild = Utilities.GetAppSettings("Build", "Version");
            string buildType = rbBuild.message;
            string accessPath = "URL";
            string captchaVerificationUrl = Utilities.GetAppSettings("CaptchaVerificationURL", buildType, accessPath).message;
            ReturnBool rb = await dlCommon.VerifyCaptchaAsync(captchaID: ulr.captchaId, userEnteredCaptcha: ulr.userEnteredCaptcha, captchaVerificationUrl);
            //rb.status = true;
            UserLoginResponse userLoginResponse = new();
            if (rb.status)
            {
                rb.status = false;
                ReturnDataTable dt1 = await dl.CheckUserAccountForLogin(ulr.emailId);
                if (dt1.status)
                {
                    // Block Industrialist login
                    //if (ulr.emailId.ToLower().Trim() == "abhishek96")
                    //{
                    //    rb.message = "Valid Email Id";
                    //    rb.status = true;
                    //    rb.message1 = dt1.table.Rows[0]["role_id"].ToString();
                    //    rb.value = dt1.table.Rows[0]["userId"].ToString();
                    //    rb.error = dt1.table.Rows[0]["isUserMigrate"].ToString();
                    //}
                    //else if (dt1.table.Rows[0]["role_id"].ToString().Trim() == "04")
                    //{
                    //    rb.message = "Unauthorized User, only Department User can login.";
                    //    rb.status = false;
                    //    rb.value = "401";
                    //}
                    //else
                    //{
                    rb.message = "Valid Email Id";
                    rb.status = true;
                    rb.message1 = dt1.table.Rows[0]["role_id"].ToString();
                    rb.value = dt1.table.Rows[0]["userId"].ToString();
                    rb.error = dt1.table.Rows[0]["isUserMigrate"].ToString();
                    // }

                }
                else
                    rb.message = "Invalid User Id";

            }
            else
                rb.message = rb.message;

            return rb;
        }
        [HttpPost("sendotpforlogin")]
        public async Task<ReturnString> SendOtpForLogin([FromBody] UserLoginWithOTP ulr)
        {
            //string captchaVerificationUrl = Utilities.GetAppSettings("CaptchaVerificationURL", "URL").message;
            //ReturnBool rb = await dlCommon.VerifyCaptchaAsync(captchaID: ulr.captchaId, userEnteredCaptcha: ulr.userEnteredCaptcha, captchaVerificationUrl);
            ////rb.status = true;
            //UserLoginResponse userLoginResponse = new();
            ReturnString rs = new();
            //if (rb.status)
            //{
            rs = await dl.SendOtpForLogin(ulr.emailId, ulr.id);
            if (rs.status)
                rs.message = "OTP has been sent!!";
            //}
            //else
            //    rs.message = rb.message;

            return rs;
        }

        [AllowAnonymous]
        [HttpPost("authenticatewithotp")]
        public async Task<UserLoginResponse> AuthenticateWithOTP([FromBody] SendOtp ulr)
        {
            // string captchaVerificationUrl = Utilities.GetAppSettings("CaptchaVerificationURL", "URL").message;
            // ReturnBool rb = await dlCommon.VerifyCaptchaAsync(captchaID: ulr.captchaId, userEnteredCaptcha: ulr.userEnteredCaptcha, captchaVerificationUrl);
            //rb.status = true;
            UserLoginResponse userLoginResponse = new();
            //if (rb.status)
            //{
            LoginTrail ltr = new();
            ltr.userAgent = Request.Headers[HeaderNames.UserAgent];
            BrowserContext br = Utilities.DetectBrowser(ltr.userAgent);

            ltr.clientOs = br.OS;
            ltr.clientBrowser = br.BrowserName;
            ltr.accessMode = VerifyAppKey(this.HttpContext);


            ReturnBool rb = new();
            
            //ltr.loginSource = "";
            ltr.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            ltr.logCategory = EventLogCategory.AccountAccess;
            //ReturnBool tokenVerified = await dlCommon.VerifyRequestToken(ulr.requestToken!);
            //if (tokenVerified.status)
            userLoginResponse = await dl.CheckUserLoginwithOTP(ulr, ltr);
            //else
            //    userLoginResponse.message = "Invalid Credential. Request has been tempered.";

            //if(!userLoginResponse.isLoginSuccessful)
            //{
            //    UserLoginResponseFailure userLoginResponseFailure = new UserLoginResponseFailure();
            //    userLoginResponseFailure.message = userLoginResponse.message;
            //    return  userLoginResponseFailure;
            //}
            //
            //else
            //    userLoginResponse.message = rb.message;
            return userLoginResponse;
        }

        [HttpGet("GenerateRequestToken")]
        public async Task<ReturnString> GenerateRequestToken()
        {
            return await dlCommon.GenerateRequestToken();
        }

        /// <summary>
        /// Log out user
        /// </summary>
        /// <returns></returns>
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        [HttpGet("getuniqueid")]
        public async Task<ReturnBool> GetAuthUniqueId()
        {
            ReturnBool rb = new();
            string authHeaders = HttpContext.Request.Headers.FirstOrDefault(x => x.Key == "Authorization").Value.FirstOrDefault();

            if (authHeaders is not null || authHeaders != "")
                authHeaders = authHeaders.Replace("Bearer", "").TrimStart();
            string uniquId = await dl.GetAuthenticationUniqueId(authHeaders);
            if (uniquId != string.Empty)
            {
                rb.value = uniquId;
                rb.status = true;
            }
            return rb;
        }
        /// <summary>
        /// test SWS login With Url
        /// </summary>
        /// <returns></returns>

        [HttpPost("dycryptswslogintoken")]
        public async Task<ReturnBool> Getswslogintoken(swsToken swsToken)
        {
            ReturnBool rb = new();
            //string authHeaders = HttpContext.Request.Headers.FirstOrDefault(x => x.Key == "Authorization").Value.FirstOrDefault();

            //if (authHeaders is not null || authHeaders != "")
            //    authHeaders = authHeaders.Replace("Bearer", "").TrimStart();
            rb = await dl.DecryptSWSDepartmentlogin(swsToken.token);
            //if (uniquId != string.Empty)
            //{
            //    rb.value = uniquId;
            //    rb.status = true;
            //}
            return rb;
        }

        
    }
}
