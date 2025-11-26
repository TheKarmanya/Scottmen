using BaseClass;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Net.Http.Headers;
using ScottmenMainApi.Models.BLayer;
using ScottmenMainApi.Models.DLayer;
using System.Net.Mail;
using System.Security.Claims;
using System.Text.RegularExpressions;
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

        [HttpPost("verifyotp")]
        public async Task<ReturnBool> VerifyPublicOTP([FromBody] SendOtp blUser)
        {

            blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            ReturnBool rb = await dl.VerifyPublicOTP(blUser.msgId, (Int32)blUser.OTP, blUser.mobileNo.ToString());
            if (rb.status)
                rb.message = "OTP has been verified.";
            return rb;
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
        [HttpPost("removestock")]
        // [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnBool> removeRowMaterialInStock([FromBody] ItemStock itemStock)
        {
            itemStock.userId = itemStock.userId == null ? 0 : itemStock.userId;//Convert.ToInt64(User.FindFirst("userId")?.Value);
                                                                               // itemStock[0].roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            itemStock.clientIp = itemStock.clientIp == null ? "" : Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{

            return await dl.RemoveItemfromStockAsync((long)itemStock.itemStockId!);

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
        [HttpPost("afterblending")]
        // [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnString> AfterBlendingProcessAsync([FromBody] Blending blending)
        {
            blending.userId = 0;//Convert.ToInt64(User.FindFirst("userId")?.Value);
                                // itemStock[0].roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            blending.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{

            return await dl.AfterBlendngDeepEntry(blending);

            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }
        [HttpPost("removeblendingprocess")]
        // [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnBool> removeBlendingProcessAsync([FromBody] RemobeBlendingProcess blending)
        {
            blending.userId = blending.userId == null ? 0 : blending.userId;//Convert.ToInt64(User.FindFirst("userId")?.Value);
                                                                            // itemStock[0].roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            blending.clientIp = blending.clientIp == null ? "" : Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{

            return await dl.RemoveItemfromBlendingProcess((long)blending.batchId!, (Int16)blending.itemId!);

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

        [HttpPost("removeissuepackageitems")]
        // [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnBool> removeIssuePackageitemsAsync([FromBody] RemoveIssueMaterial issueMaterial)
        {
            issueMaterial.userId = issueMaterial.userId == null ? 0 : issueMaterial.userId;//Convert.ToInt64(User.FindFirst("userId")?.Value);
                                                                                           // itemStock[0].roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            issueMaterial.clientIp = issueMaterial.clientIp == null ? "" : Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{

            return await dl.RemoveItemfromIssuedItem((long)issueMaterial.issueId!, (Int16)issueMaterial.itemId!);

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
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        //[AllowAnonymous]
        public async Task<ReturnDataSet> GetDispatchListList(DispatchSearch dispatch)
        {
            long userId = Convert.ToInt64(User.FindFirst("userId")?.Value);
            int roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            string clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{
            return await dl.GetDispatchList(dispatch);
            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }
        [HttpGet("finishedproductfordispatch")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnDataTable> GetFinishedProductForDispatch()
        {
            //long userId = Convert.ToInt64(User.FindFirst("userId")?.Value);
            //int roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            // blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{
            return await dl.GetFinishProductForDispatch();
            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }


        [HttpPost("savewastedetails")]
        // [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnString> SaveWasteDetails([FromBody] WasteDetail wasteDetail)
        {
            wasteDetail.userId = 0;//Convert.ToInt64(User.FindFirst("userId")?.Value);
                                   // itemStock[0].roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            wasteDetail.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{
            return await dl.SaveWasteDetail(wasteDetail);
            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }
        [HttpPost("wastelist")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnDataSet> GetWasteList(WasteDetail wasteDetail)
        {
            //long userId = Convert.ToInt64(User.FindFirst("userId")?.Value);
            //int roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            // blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{
            return await dl.GetWasteList(wasteDetail);
            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }

        [HttpGet("getrecipe/{brandid}")]
        public async Task<ReturnDataTable> GetRecipe(Int64 brandid)
        {
            ReturnDataTable dt1 = await dl.GetRecipe(brandid);
            return dt1;
        }
        [HttpPost("finishedproductsummery")]
        public async Task<ReturnDataTable> Getfinishedproduct(SearchDetail searchDetail)
        {
            ReturnDataTable dt1 = await dl.GetFinishedSummery(searchDetail);
            return dt1;
        }

        [HttpPost("createuserlogin")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnBool> CreateUserLogin(UserLogin user)
        {
            ReturnBool rb = new();
            //long userId = Convert.ToInt64(User.FindFirst("userId")?.Value);
            //int roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            // blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{
            DlCommon dlCommon = new();
            rb = await dlCommon.SaveUserLogin(user);
            rb.message = "Something went wrong..Please try again..";
            if (rb.status)
                rb.message = "Login-ID has been Updated..";
            return rb;
            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }
        [HttpPost("useractivation")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnBool> UserLoginActivation(UserLogin user)
        {
            ReturnBool rb = new();
            //long userId = Convert.ToInt64(User.FindFirst("userId")?.Value);
            //int roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            // blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{
            DlCommon dlCommon = new();
            rb = await dlCommon.UserActivation(user);
            rb.message = "Something went wrong..Please try again..";
            if (rb.status)
            {
                if (user.isActive == (Int16)IsActive.Yes)
                    rb.message = "Login-ID has been Activated..";
                else if (user.isActive == (Int16)IsActive.No)
                    rb.message = "Login-ID has been Deactivated..";
            }
            return rb;
            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }
        [HttpGet("userlist")]
        [AllowAnonymous]
        public async Task<ReturnDataTable> GetUserLoginList()
        {
            DlCommon dlCommon = new();
            long userId = Convert.ToInt64(User.FindFirst("userId")?.Value);
            int roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            string clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            ReturnDataTable dt1 = await dlCommon.GetUserList();
            return dt1;
        }

        [HttpPost("resetpassword")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnBool> RestePassword(UserLogin user)
        {
            ReturnBool rb = new();
            //long userId = Convert.ToInt64(User.FindFirst("userId")?.Value);
            //int roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            // blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{
            DlCommon dlCommon = new();
            rb = await dlCommon.ResetPassword(user);
            rb.message = "Something went wrong..Please try again..";
            if (rb.status)
                rb.message = "Password Successfully Reset..";
            return rb;
            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }

        [HttpPost("savemailtemplate")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnBool> SaveMailTemplate(MailTemplate mailTemplate)
        {
            ReturnBool rb = new();
            //long userId = Convert.ToInt64(User.FindFirst("userId")?.Value);
            //int roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            // blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{
            DlCommon dlCommon = new();
            rb = await dl.SaveMailTemplate(mailTemplate);
            rb.message = "Something went wrong..Please try again..";
            if (rb.status)
                rb.message = "Mail Template Saved...";
            return rb;
            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }

        [HttpPost("updatemailtemplate")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnBool> UpdateMailTemplate(MailTemplate mailTemplate)
        {
            ReturnBool rb = new();
            //long userId = Convert.ToInt64(User.FindFirst("userId")?.Value);
            //int roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            // blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{
            DlCommon dlCommon = new();
            rb = await dl.UpdateMailTemplate(mailTemplate);
            rb.message = "Something went wrong..Please try again..";
            if (rb.status)
                rb.message = "Mail Template Updated...";
            return rb;
            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }

        [HttpPost("getmailtemplate")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnDataTable> GetMailTemplate(MailTemplate mailTemplate)
        {
            ReturnBool rb = new();
            //long userId = Convert.ToInt64(User.FindFirst("userId")?.Value);
            //int roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            // blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{            
            return await dl.GetMailTemplate(mailTemplate);
            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }




        [HttpPost("savepurchaseorder")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnBool> SavePurchaseOrder(PurchaseOrder purchaseOrder)
        {
            ReturnBool rb = new();
            //long userId = Convert.ToInt64(User.FindFirst("userId")?.Value);
            //int roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            // blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{
            DlCommon dlCommon = new();
            rb = await dl.SavePurchaseOrder(purchaseOrder);
            rb.message = "Something went wrong..Please try again..";
            if (rb.status)
                rb.message = "Purchase Order Saved...";
            return rb;
            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }

        [HttpPost("updatepurchaseorder")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnBool> UpdatePurchaseOrder(PurchaseOrder purchase)
        {
            ReturnBool rb = new();
            //long userId = Convert.ToInt64(User.FindFirst("userId")?.Value);
            //int roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            // blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{
            DlCommon dlCommon = new();
            rb = await dl.UpdatePurchaseOrder(purchase);
            rb.message = "Something went wrong..Please try again..";
            if (rb.status)
                rb.message = "Purchase Order Updated...";
            return rb;
            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }

        [HttpPost("getpurchaseorder")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnDataTable> GetPurchaseOrder(PurchaseOrder purchase)
        {
            ReturnBool rb = new();
            //long userId = Convert.ToInt64(User.FindFirst("userId")?.Value);
            //int roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            // blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{            
            return await dl.GetPurchaseOrder(purchase);
            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }
        [HttpPost("remainingpurchaseorder")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnDataTable> GetRemainingPurchaseOrder(PurchaseOrder purchase)
        {
            ReturnBool rb = new();
            //long userId = Convert.ToInt64(User.FindFirst("userId")?.Value);
            //int roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            // blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{            
            return await dl.GetRemainingPurchaseOrder(purchase);
            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }
        

        [HttpPost("sendemail")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnBool> SendMail(SendMailAddress sendMailAddress)
        {
            ReturnBool rb = new();
            //long userId = Convert.ToInt64(User.FindFirst("userId")?.Value);
            //int roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            // blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{
            Email email = new();
            string ToAddress = CleanEmail(sendMailAddress.ToAddress!);
            if (!string.IsNullOrEmpty(sendMailAddress.ccAddress))
            {
                string ccMailId = CleanEmail(sendMailAddress.ccAddress!);
                rb = await email.SendAsync(ToAddress, sendMailAddress.emailSubject!, sendMailAddress.emailBody!, sendMailAddress.Attachments!,
                    ccMailId);
            }
            else
                rb = await email.SendAsync(ToAddress, sendMailAddress.emailSubject!, sendMailAddress.emailBody!, sendMailAddress.Attachments!);
            if (rb.status && sendMailAddress.purchaseOrderId > 0)
                rb = await dl.UpdateMailSentToVendor((long)sendMailAddress.purchaseOrderId);
            await dl.SaveMailedData(sendMailAddress, rb.status);

            rb.message = "Something went wrong..Please try again..";
            if (rb.status)
                rb.message = "Mail has been Sent.";
            return rb;
            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }
        string CleanEmail(string email)
        {
            // Remove invisible/Unicode control characters
            return Regex.Replace(email, @"[^\u0000-\u007F]+", "");
        }
        [HttpPost("getdeepvalue")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnDataTable> GetDeepingValue(VatDeepCaluclation vatDeep)
        {
            ReturnBool rb = new();
            //long userId = Convert.ToInt64(User.FindFirst("userId")?.Value);
            //int roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            // blUser.clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            // ReturnString rs = new();
            //if (roleId == (int)UserRole.Administrator)
            //{            
            return await dl.GetDeepCalculation(vatDeep);
            //}
            //else
            //    rb.message = "User not authorized to access the report";
        }


    }
}
