using BaseClass;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Net.Http.Headers;
using ScottmenMainApi.Models.BLayer;
using ScottmenMainApi.Models.DLayer;
using System.Security.Claims;
using static BaseClass.ReturnClass;

namespace ScottmenMainApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        DlUser dl = new();
        readonly DlCommon dlCommon = new();
        [HttpPost("CheckUserAccountExist")]
        public async Task<ReturnBool> CheckUserAccountExist([FromBody] UserLoginRequest ulr)
        {
            ReturnClass.ReturnBool rb = await dl.CheckUserAccountExist(ulr.emailId);
            ReturnClass.ReturnBool rbReturn = new();
            if (rb.status)
            {
                rbReturn.message = "This Email Id has already been registered. Please try with different Email Id";
                rbReturn.status = true;
            }
            return rbReturn;
        }

        [HttpPost("RegisterNewUser")]
        public async Task<ReturnString> RegisterNewAccount([FromBody] BlUser blUser)
        {
            ReturnBool rbBuild = Utilities.GetAppSettings("Build", "Version");
            string buildType = rbBuild.message;
            string accessPath = "URL";
            string captchaVerificationUrl = Utilities.GetAppSettings("CaptchaVerificationURL", buildType, accessPath).message;
            ReturnBool rbCaptcha = await dlCommon.VerifyCaptchaAsync(captchaID: blUser.captchaId, userEnteredCaptcha: blUser.userEnteredCaptcha, captchaVerificationUrl);
            ReturnString rbReturn = new();
            //rbCaptcha.status = true;
            if (rbCaptcha.status)
            {
                string userAgent = Request.Headers[HeaderNames.UserAgent];
                BrowserContext br = Utilities.DetectBrowser(userAgent);
                blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
                blUser.clientOs = br.OS;
                blUser.clientBrowser = br.BrowserName;

                ReturnString rb = await dl.RegisterIndustrialUserAsync(blUser);
                if (rb.status)
                {
                    rbReturn.message = "Done. Please verify your contact details now";
                    rbReturn.value = rb.value;
                    rbReturn.msgId = rb.msgId;
                    rbReturn.status = rb.status;
                    rbReturn.secondryId = rb.secondryId;
                }
                else
                    rbReturn.message = "Failed to register your account. Please try later " + rbReturn.value;
            }
            else
                rbReturn.message = rbCaptcha.message;
            return rbReturn;
        }

        [HttpPost("verifynewcontact")]
        public async Task<ReturnBool> VerifyContactDetailsNewUser([FromBody] BlUser blUser)
        {
            ReturnClass.ReturnBool rb = new();
            string verifiedMsgType = "Email";
            bool isEmailVerified = true;
            if (blUser.isEmailVerified == YesNo.Yes)
            {
                rb = await dl.VerifyContactDetailsNewUserAsync(blUser, ContactVerifiedType.Email);
                if (rb.status == false)
                    isEmailVerified = false;
            }
            if (blUser.isMobileVerified == YesNo.Yes && isEmailVerified == true)
            {
                rb = await dl.VerifyContactDetailsNewUserAsync(blUser, ContactVerifiedType.Mobile);
                verifiedMsgType = "Mobile number";

            }
            ReturnClass.ReturnBool rbReturn = new();
            if (blUser.isEmailVerified == YesNo.No && blUser.isMobileVerified == YesNo.No)
            {
                rb.message = "OTP should not be empty.";
            }
            if (rb.status)
            {
                rbReturn.message = "Your " + verifiedMsgType + " has been verified successfully. Now you need to create your password";
                rbReturn.status = true;
            }
            else
                rbReturn.message = rb.message;
            return rbReturn;
        }

        [HttpPost("SetNewPassword")]
        public async Task<ReturnBool> UpdateNewUserPassword([FromBody] BlUser blUser)
        {
            blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            return await dl.UpdateNewUserPasswordAsync(blUser);
        }
        [HttpPost("ChangePassword")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnBool> ChangePassword([FromBody] BlUser blUser)
        {
            long userId = Convert.ToInt64(User.FindFirst("userId")?.Value);
            blUser.roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            string authHeaders = HttpContext.Request.Headers.FirstOrDefault(x => x.Key == "Authorization").Value.FirstOrDefault().Replace("Bearer", "", StringComparison.CurrentCultureIgnoreCase).TrimStart();
            long sessionId = await dl.GetSessionId(authHeaders);
            blUser.registrationId = userId;
            if (sessionId > 0)
                return await dl.ChangeUserPassword(blUser, sessionId);
            else
                return new ReturnBool { message = "Invalid Session. Failed to Change your password" };
        }
        [HttpPost("sendotp")]
        public async Task<ReturnString> SendOTP([FromBody] SendOtp blUser)
        {

            blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            ReturnString rb = await dl.SendOTP(blUser);
            if (rb.status)
                rb.message = "OTP has been sent. Please verify your contact details now";
            return rb;
        }
        [HttpPost("resendotp")]
        public async Task<ReturnString> ReSendOTP([FromBody] SendOtp blUser)
        {

            blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            ReturnString rb = await dl.ReSendOTP(blUser);
            if (rb.status)
                rb.message = "OTP has been resent. Please verify your contact details now";
            return rb;
        }
        [HttpPost("verifyotp")]
        public async Task<ReturnBool> VerifyPublicOTP([FromBody] SendOtp blUser)
        {

            blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            ReturnBool rb = await dl.VerifyPublicOTP(blUser.msgId, (Int32)blUser.OTP, blUser.mobileNo.ToString());
            if (rb.status)
                rb.message = "OTP has been verified.";
            return rb;
        }
        [HttpPost("getforgetdetail")]
        public async Task<ReturnString> UserAccountExist([FromBody] SendOtp send)
        {
            ReturnClass.ReturnString rs = await dl.CheckUserAccountExist(send);
            if (!rs.status)
                rs.message = rs.message;

            return rs;
        }
        [HttpPost("forgotpassword")]
        public async Task<ReturnBool> UpdateForgotPassword([FromBody] BlUser blUser)
        {
            blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            return await dl.ResetForgotPassword(blUser);


        }

        [HttpPost("sendemailotp")]
        public async Task<ReturnString> SendEmaildOTP([FromBody] SendOtp blUser)
        {

            blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            ReturnString rb = await dl.SendEmailOTP(blUser);
            if (rb.status)
                rb.message = "OTP has been sent. Please verify your Email details now";
            return rb;
        }

        [HttpPost("resendemailotp")]
        public async Task<ReturnString> ReSendEmailOTP([FromBody] SendOtp blUser)
        {

            blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            ReturnString rb = await dl.ReSendEmailOTP(blUser);
            if (rb.status)
                rb.message = "OTP has been resent. Please verify your Email details now";
            return rb;
        }

        [HttpPost("verifyemailotp")]
        public async Task<ReturnBool> VerifyPublicEmailOTP([FromBody] SendOtp blUser)
        {

            blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            ReturnBool rb = await dl.VerifyPublicEmailOTP(blUser.msgId!, (Int32)blUser.OTP!, blUser.emailId!.ToString());
            if (rb.status)
                rb.message = "Email OTP has been verified.";
            return rb;
        }

        /// <summary>
        /// Send Email 
        /// </summary>
        /// <param name="blProject"></param>
        /// <returns></returns>
        [HttpPost("testemail")]
        // [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnBool> SendEmaild([FromBody] emailSenderClass sendEmail)
        {
            Email email = new();
            return await email.SendEmailViaURLAsync(sendEmail);
        }

        /// <summary>
        /// Sandesh message sender method
        /// </summary>       
        /// <returns></returns>
        [HttpPost("sendsandesh")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnClass.ReturnBool> SendSandesh(sandeshMessageBody sandeshMessageBody)
        {
            ReturnClass.ReturnBool rb = new();
            if (sandeshMessageBody.contact!.Length != 10)
            {
                rb.message = "Invalid Mobile Number";
                return rb;
            }
            sandeshMessageBody.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            DlCommon dlCommon = new DlCommon();
            //sandeshMessageBody.TemplateId = 0;
            rb = await dlCommon.SendSandesh(sandeshMessageBody);
            if (rb.status)
            {
                rb.status = true;
                rb.value = rb.message;
            }
            return rb;
        }


        [HttpGet("sendadminotp")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnString> SendAdminOTP()
        {
            ReturnString rs = new();
            long userId = Convert.ToInt64(User.FindFirst("userId")?.Value);
            string clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            int roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            if (roleId == (int)UserRole.Administrator)
            {
                rs = await dl.SendAdminOTP(userId, clientIp);
                if (rs.status)
                    rs.message = "OTP has been sent. Please verify your contact details now";
            }
            else
                rs.message = "User not authorized to access the report";
            return rs;
        }
        [HttpPost("resendadminotp/{msgid}")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnString> ReSendAdminOTP(string msgid)
        {
            ReturnString rs = new();
            long userId = Convert.ToInt64(User.FindFirst("userId")?.Value);
            string clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            int roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            if (roleId == (int)UserRole.Administrator)
            {
                rs = await dl.ReSendAdminOTP(userId, clientIp, msgid);
                if (rs.status)
                    rs.message = "OTP has been sent again. Please verify your contact details now";
            }
            else
                rs.message = "User not authorized to access the report";
            return rs;
        }
        [HttpPost("verifyadminotp")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnBool> VerifyAdminOTP([FromBody] SendOtp blUser)
        {
            long userId = Convert.ToInt64(User.FindFirst("userId")?.Value);
            int roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            ReturnBool rb = new();
            if (roleId == (int)UserRole.Administrator)
            {

                rb = await dl.VerifyAdminOTP(blUser, userId);
                if (rb.status)
                    rb.message = "OTP has been verified.";
            }
            else
                rb.message = "User not authorized to access the report";

            return rb;


        }
        [HttpPost("passwordreset")]
        public async Task<ReturnBool> UpdatePsswordMD5ToSha256([FromBody] UserResetPassword blUser)
        {
            blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            ReturnBool tokenVerified = await dlCommon.VerifyRequestToken(blUser.requestToken!);
            tokenVerified.status = true;
            if (tokenVerified.status)
                tokenVerified = await dl.ResetMD5PasswordtoSha256(blUser);
            else
                tokenVerified.message = "Invalid Credential. Request has been tempered.";
            return tokenVerified;
        }

        [HttpPost("getforgetuseriddetail")]
        public async Task<ReturnString> UserAccountExistByMobile([FromBody] SendOtp send)
        {
            ReturnClass.ReturnString rs = await dl.CheckUserAccountExistByMobile(send);
            if (!rs.status)
                rs.message = "invalid Mobile Number ";

            return rs;
        }

        [HttpPost("verifyotpforuserid")]
        public async Task<ReturnBool> VerifyOTPForUserId([FromBody] SendOtp blUser)
        {

            blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            ReturnBool rb = await dl.VerifyForgetOTPUserId(blUser.msgId, (Int32)blUser.OTP, blUser.mobileNo.ToString(), blUser.userId, blUser.emailId);
            if (rb.status)
                rb.message = "OTP has been verified.";
            return rb;
        }

        [HttpPost("saveemployee")]
        // [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnString> SaveEmployee([FromBody] Employee bl)
        {
            bl.userId = 0;//Convert.ToInt64(User.FindFirst("userId")?.Value);
            //bl.roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            bl.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{

            return await dl.SaveEmployee(bl);

            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }
        [HttpPost("updateemployee")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnString> UpdateEmployee([FromBody] Employee bl)
        {
            bl.userId = 0;//Convert.ToInt64(User.FindFirst("userId")?.Value);
            //bl.roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            bl.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{

            return await dl.UpdateEmployee(bl);

            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }
        [HttpGet("employeelist/{id?}/{active?}")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnDataTable> GetemployeeList(long id = 0, Int16 active = 1)
        {
            //long userId = Convert.ToInt64(User.FindFirst("userId")?.Value);
            //int roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            // blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{
            return await dl.GetEmployee(id, active);
            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }


        [HttpPost("saveunit")]
        // [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnBool> SaveUnit([FromBody] UnitMaster bl)
        {
            bl.userId = 0;//Convert.ToInt64(User.FindFirst("userId")?.Value);
            //bl.roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            bl.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{
            return await dl.SaveUnitMaster(bl);

            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }
        [HttpPost("updateunit")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnBool> UpdateUnit([FromBody] UnitMaster bl)
        {
            bl.userId = 0;//Convert.ToInt64(User.FindFirst("userId")?.Value);
            //bl.roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            bl.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{

            return await dl.UpdateUnitMaster(bl);

            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }
        [HttpGet("unitlist/{id?}/{active?}")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnDataTable> GetUnitList(long id = 0, Int16 active = 1)
        {
            //long userId = Convert.ToInt64(User.FindFirst("userId")?.Value);
            //int roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            // blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{
            return await dl.GetUnit(id, active);
            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }

        [HttpPost("saveitem")]
        // [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnBool> SaveItemMaster([FromBody] ItemMaster bl)
        {
            bl.userId = 0;//Convert.ToInt64(User.FindFirst("userId")?.Value);
            //bl.roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            bl.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{

            return await dl.SaveItemMaster(bl);

            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }

        [HttpPost("updateitem")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnBool> UpdateItem([FromBody] ItemMaster bl)
        {
            bl.userId = 0;//Convert.ToInt64(User.FindFirst("userId")?.Value);
                          //bl.roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            bl.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{

            return await dl.UpdateItemMaster(bl);

            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }

        [HttpGet("itemlist/{id?}/{active?}/{itemtype?}")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnDataTable> GetItemList(long id = 0, Int16 active = 1, Int16 itemtype = 0)
        {
            //long userId = Convert.ToInt64(User.FindFirst("userId")?.Value);
            //int roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            // blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{
            return await dl.GetItem(id, active, itemtype);
            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }
        [HttpGet("vendorwiselist/{vendorid?}")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnDataTable> VendorWiseItems(long vendorid = 0)
        {
            //long userId = Convert.ToInt64(User.FindFirst("userId")?.Value);
            //int roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            // blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{
            return await dl.GetVendorWiseItems(vendorid);
            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }


        [HttpPost("savevendor")]
        // [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnString> SaveVendor([FromBody] Vendor bl)
        {
            bl.userId = 0;//Convert.ToInt64(User.FindFirst("userId")?.Value);
            //bl.roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            bl.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{

            return await dl.SaveVendor(bl);

            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }

        [HttpPost("updatevendor")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnString> UpdateVendor([FromBody] Vendor bl)
        {
            bl.userId = 0;//Convert.ToInt64(User.FindFirst("userId")?.Value);
                          //bl.roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            bl.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{

            return await dl.UpdateVendor(bl);

            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }

        [HttpGet("vendorlist/{id?}/{active?}")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnDataSet> GetVendorList(long id = 0, Int16 active = 1)
        {
            //long userId = Convert.ToInt64(User.FindFirst("userId")?.Value);
            //int roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            // blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{
            return await dl.GetVendor(id, active);
            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }
        [HttpPost("savebrand")]
        // [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnBool> SaveBrand([FromBody] BrandMaster bl)
        {
            bl.userId = 0;//Convert.ToInt64(User.FindFirst("userId")?.Value);
            //bl.roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            bl.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{
            return await dl.SavebrandMaster(bl);

            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }
        [HttpPost("updatebrand")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnBool> Updatebrand([FromBody] BrandMaster bl)
        {
            bl.userId = 0;//Convert.ToInt64(User.FindFirst("userId")?.Value);
            //bl.roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            bl.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{

            return await dl.UpdateBrandMaster(bl);

            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }
        [HttpGet("brandlist/{id?}/{active?}")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnDataTable> GetBrandList(long id = 0, Int16 active = 1)
        {
            //long userId = Convert.ToInt64(User.FindFirst("userId")?.Value);
            //int roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            // blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{
            return await dl.GetBrand(id, active);
            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }

        [HttpPost("unloadingatepass")]
        // [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnString> SaveUnloading([FromBody] UnloadingEntry bl)
        {
            bl.userId = 0;//Convert.ToInt64(User.FindFirst("userId")?.Value);
            //bl.roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            bl.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{

            return await dl.SaveUnloadingEntry(bl);

            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }

        [HttpPost("updateunloading")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnString> UpdateUnloading([FromBody] UnloadingEntry bl)
        {
            bl.userId = 0;//Convert.ToInt64(User.FindFirst("userId")?.Value);
                          //bl.roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            bl.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{

            return await dl.UpdateUnloadingEntry(bl);

            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }
        [HttpPost("updateunloadingexittime")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnString> UpdateUnloadingExitTime([FromBody] UnloadingEntry bl)
        {
            bl.userId = 0;//Convert.ToInt64(User.FindFirst("userId")?.Value);
                          //bl.roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            bl.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)            //{

            return await dl.UpdateUnloadingExitTime(bl);

            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }

        [HttpPost("unloadinglist")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnDataSet> GetunloadingList(GatePassSearch gatePassSearch)
        {
            //long userId = Convert.ToInt64(User.FindFirst("userId")?.Value);
            //int roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            // blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{
            return await dl.GetUnloadingGatePassList(gatePassSearch);
            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }


        [HttpPost("loadingatepass")]
        // [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnString> SaveLoading([FromBody] LoadingEntry bl)
        {
            bl.userId = 0;//Convert.ToInt64(User.FindFirst("userId")?.Value);
            //bl.roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            bl.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{
            return await dl.SaveLoadingEntry(bl);
            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }

        [HttpPost("updateloading")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnString> UpdateLoading([FromBody] LoadingEntry bl)
        {
            bl.userId = 0;//Convert.ToInt64(User.FindFirst("userId")?.Value);
                          //bl.roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            bl.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{

            return await dl.UpdateLoadingEntry(bl);

            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }
        [HttpPost("updateloadingexittime")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnString> UpdateLoadingExitTime([FromBody] LoadingEntry bl)
        {
            bl.userId = 0;//Convert.ToInt64(User.FindFirst("userId")?.Value);
                          //bl.roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            bl.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)            //{

            return await dl.UpdateLoadingExitTime(bl);

            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }

        [AllowAnonymous]
        [HttpPost("loadinglist")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnDataSet> GetLoadingList(GatePassSearch gatePassSearch)
        {
            long userId = Convert.ToInt64(User.FindFirst("userId")?.Value);
            int roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            // blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{
            return await dl.GetLoadingGatePassList(gatePassSearch);
            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }

        [HttpPost("visitorgatepass")]
        // [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnString> SaveVisitor([FromBody] VisitorEntry bl)
        {
            bl.userId = 0;//Convert.ToInt64(User.FindFirst("userId")?.Value);
            //bl.roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            bl.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{

            return await dl.SaveVisitorEntry(bl);

            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }

        [HttpPost("updatevisitor")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnString> UpdateVisitor([FromBody] VisitorEntry bl)
        {
            bl.userId = 0;//Convert.ToInt64(User.FindFirst("userId")?.Value);
                          //bl.roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            bl.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{

            return await dl.UpdateVisitorEntry(bl);

            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }
        [HttpPost("updatevisitorexittime")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnString> UpdateVisitorExitTime([FromBody] VisitorEntry bl)
        {
            bl.userId = 0;//Convert.ToInt64(User.FindFirst("userId")?.Value);
                          //bl.roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            bl.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)            //{

            return await dl.UpdateVisitorExitTime(bl);

            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }

        [HttpPost("visitorlist")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnDataSet> GetvisitorList(GatePassSearch gatePassSearch)
        {
            //long userId = Convert.ToInt64(User.FindFirst("userId")?.Value);
            //int roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            // blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{
            return await dl.GetVisitorGatePassList(gatePassSearch);
            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }


        [HttpPost("pendingstock")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnDataSet> GetRowMaterialListToStock(GatePassSearch gatePassSearch)
        {
            //long userId = Convert.ToInt64(User.FindFirst("userId")?.Value);
            //int roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            // blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{
            return await dl.GetRowMaterialListToStock(gatePassSearch);
            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }
        [HttpPost("addstock")]
        // [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnString> SaveRowMaterialInStock([FromBody] List<ItemStock> itemStock)
        {
            itemStock[0].userId = itemStock[0].userId == null ? 0 : itemStock[0].userId;//Convert.ToInt64(User.FindFirst("userId")?.Value);
                                                                                        // itemStock[0].roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            itemStock[0].clientIp = itemStock[0].clientIp == null ? "" : Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{

            return await dl.SaveRowMaterialInStock(itemStock);

            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }

        [HttpPost("stocklist")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnDataSet> GetStockList(ItemStockSearch itemStockSearch)
        {
            //long userId = Convert.ToInt64(User.FindFirst("userId")?.Value);
            //int roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            // blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{
            return await dl.GetStockList(itemStockSearch);
            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }

        [HttpPost("saveblendingprocess")]
        // [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnString> SaveBlendingProcessAsync([FromBody] Blending blending)
        {
            blending.userId = 0;//Convert.ToInt64(User.FindFirst("userId")?.Value);
                                // itemStock[0].roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            blending.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{

            return await dl.SaveBlendingProcess(blending);

            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }

        [HttpPost("blendingprocesslist")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnDataSet> GetBlendingProcessList(Blending blending)
        {
            //long userId = Convert.ToInt64(User.FindFirst("userId")?.Value);
            //int roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            // blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{
            return await dl.GetBlendingProcessList(blending);
            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }

        [HttpPost("issuepackageitems")]
        // [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnString> IssueMaterialForPackageing([FromBody] IssueMaterial issueMaterial)
        {
            issueMaterial.userId = 0;//Convert.ToInt64(User.FindFirst("userId")?.Value);
                                     // itemStock[0].roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            issueMaterial.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{

            return await dl.IssuePackagingMaterial(issueMaterial);

            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }
        [HttpPost("returnissueditems")]
        // [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnString> ReturnIssuedItems([FromBody] IssueMaterial issueMaterial)
        {
            issueMaterial.userId = 0;//Convert.ToInt64(User.FindFirst("userId")?.Value);
                                     // itemStock[0].roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            issueMaterial.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{
            return await dl.ReturnIssuedItem(issueMaterial);
            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }

        [HttpPost("issueditemlist")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnDataSet> GetIssuedItemList(IssueMaterial issueMaterial)
        {
            //long userId = Convert.ToInt64(User.FindFirst("userId")?.Value);
            //int roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            // blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{
            return await dl.GetItemIssueList(issueMaterial);
            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }

        [HttpPost("savefinishedproduct")]
        // [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnString> SaveFinishedProduct([FromBody] FinishedProduct finishedProduct)
        {
            finishedProduct.userId = 0;//Convert.ToInt64(User.FindFirst("userId")?.Value);
                                       // itemStock[0].roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            finishedProduct.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{

            return await dl.SavefinishedProduct(finishedProduct);

            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }

        [HttpPost("finishedproductlist")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnDataSet> GetFinishedProductList(FinishedProduct finishedProduct)
        {
            //long userId = Convert.ToInt64(User.FindFirst("userId")?.Value);
            //int roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            // blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{
            return await dl.GetFinishedProductList(finishedProduct);
            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }

        [HttpPost("savedispatch")]
        // [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnString> SaveDispatch([FromBody] Dispatch dispatch)
        {
            dispatch.userId = 0;//Convert.ToInt64(User.FindFirst("userId")?.Value);
                                // itemStock[0].roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            dispatch.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{

            return await dl.SaveDispatch(dispatch);

            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }
        [HttpPost("dispatchlist")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnDataSet> GetDispatchListList(DispatchSearch dispatch)
        {
            //long userId = Convert.ToInt64(User.FindFirst("userId")?.Value);
            //int roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            // blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{
            return await dl.GetDispatchList(dispatch);
            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }

    }
}
