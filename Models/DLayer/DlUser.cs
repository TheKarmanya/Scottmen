using BaseClass;
using MySqlConnector;
using ScottmenMainApi.Models.BLayer;
using ScottmenMainApi.Models.DLayer;
using System;
using System.Data;
using System.Data.Common;
using System.Diagnostics.Metrics;
using System.Net;
using System.Reflection.Emit;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Channels;
using System.Text.RegularExpressions;
using System.Transactions;
using System.Web;
using static BaseClass.ReturnClass;
using static ScottmenMainApi.Models.BLayer.BlCommon;

namespace ScottmenMainApi.Models.DLayer
{
    public class DlUser
    {
        readonly DBConnection db = new();
        readonly DBConnection db1 = new(DBConnectionList.TransactionIndustryDB);
        ReturnClass.ReturnBool rb = new();
        ReturnClass.ReturnDataTable dt = new();
        DlCommon dlCommon = new();
        public object HttpContext { get; private set; }
        #region Industrial Profile Registration
        /// <summary>
        /// Register New Industrial User
        /// </summary>
        /// <param name="bl"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnString> RegisterIndustrialUserAsync(BlUser bl)
        {
            ReturnClass.ReturnString rs = await GenerateUserRegistrationId();
            ReturnClass.ReturnBool rb = new ReturnClass.ReturnBool();
            bl.mobileNo = Convert.ToInt64(bl.mobileNo.ToString().Substring(bl.mobileNo.ToString().Length - 10));
            string mobileno = bl.mobileNo.ToString();
            Match match = Regex.Match(mobileno,
                              @"^[6-9]\d{9}$", RegexOptions.IgnoreCase);
            if (match.Success == false)
            {
                rs.status = false;
                rs.message = "Invalid Mobile Number";
                return rs;
            }
            match = Regex.Match(bl.emailId.ToString(),
                             @"^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+$", RegexOptions.IgnoreCase);
            if (match.Success == false)
            {
                rs.status = false;
                rs.message = "Given email id is not valid.";
                return rs;
            }
            DlCommon dlCommon = new();
            if (rs.status)
            {
                bl.registrationId = rs.id;
                bl.registrationUId = Utilities.CreateHash(rs.id.ToString(), HashingAlgorithmSupported.Sha256);
                bl.registrationCount = Convert.ToInt64(rs.value);
                string query = @"INSERT INTO userregistration (registrationId, registrationUId, applicantFirstName,applicantMiddleName,applicantLastName, emailId, mobileNo, password, clientIp, clientOs, clientBrowser,registrationCount,registrationYear)
                                    VALUES (@registrationId, @registrationUId, @applicantFirstName,@applicantMiddleName,@applicantLastName, @emailId, @mobileNo, @password, @clientIp, @clientOs, @clientBrowser,@registrationCount,@registrationYear)";
                MySqlParameter[] pm = new MySqlParameter[] {
                    new MySqlParameter("registrationId", MySqlDbType.Int64) { Value = bl.registrationId},
                    new MySqlParameter("registrationUId", MySqlDbType.String) { Value = bl.registrationUId},
                    new MySqlParameter("registrationCount", MySqlDbType.Int64) { Value = bl.registrationCount},
                    new MySqlParameter("registrationYear", MySqlDbType.Int32) { Value = DateTime.Now.Year},
                    new MySqlParameter("applicantFirstName", MySqlDbType.VarString) { Value = bl.applicantFirstName},
                    new MySqlParameter("applicantMiddleName", MySqlDbType.VarString) { Value = bl.applicantMiddleName},
                    new MySqlParameter("applicantLastName", MySqlDbType.VarString) { Value = bl.applicantLastName},
                    new MySqlParameter("emailId", MySqlDbType.VarString) { Value = bl.emailId},
                    new MySqlParameter("mobileNo", MySqlDbType.Int64) { Value = bl.mobileNo},
                    new MySqlParameter("password", MySqlDbType.String) { Value = bl.password},
                    new MySqlParameter("clientIp", MySqlDbType.String) { Value = bl.clientIp},
                    new MySqlParameter("clientOs", MySqlDbType.String) { Value = bl.clientOs},
                    new MySqlParameter("clientBrowser", MySqlDbType.String) { Value = bl.clientBrowser}
                };

                rb = await db.ExecuteQueryAsync(query, pm, "RegisterIndustrialUser");
                if (rb.status)
                {
                    rs.value = "";
                    SendOtp sendOTP = new();
                    sendOTP.emailId = bl.emailId;
                    sendOTP.mobileNo = bl.mobileNo;
                    sendOTP.msgType = "User Registration";
                    ReturnClass.ReturnString rs1 = new();
                    rs1 = await SendOTP(sendOTP);
                    rs.msgId = rs1.msgId;
                    rs.value = bl.registrationUId;
                    if (rs1.status)
                    {
                        sendOTP.msgId = rs1.msgId;
                        rs1 = await SendEmailOTP(sendOTP);
                    }
                }
                else
                    rs.message = "Failed to Register User";
            }

            else
                rs.message = "Failed to generate registration Id";

            return rs;
        }

        /// <summary>
        /// Verify Contact Details to complete registration process
        /// </summary>
        /// <param name="bl"></param>
        /// <param name="verifiedType"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnBool> VerifyContactDetailsNewUserAsync(BlUser bl, ContactVerifiedType verifiedType)
        {
            List<MySqlParameter> pm = new();
            string verifiedString = "";
            bool proceedForUpdate = false;

            bl.mobileNo = Convert.ToInt64(bl.mobileNo.ToString().Substring(bl.mobileNo.ToString().Length - 10));
            string mobileno = bl.mobileNo.ToString();
            Match match = Regex.Match(mobileno,
                              @"^[6-9]\d{9}$", RegexOptions.IgnoreCase);
            if (match.Success == false)
            {
                rb.status = false;
                rb.message = "Invalid Mobile Number";
                return rb;
            }
            match = Regex.Match(bl.emailId.ToString(),
                             @"^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+$", RegexOptions.IgnoreCase);
            if (match.Success == false)
            {
                rb.status = false;
                rb.message = "Given email id is not valid.";
                return rb;
            }

            //string smsServiceActive = Utilities.GetAppSettings("sandeshSmsConfig", "isActive").message;
            //string normalSMSServiceActive = Utilities.GetAppSettings("SmsConfiguration", "isActive").message;
            //string emailServiceActive = Utilities.GetAppSettings("EmailConfiguration", "isActive").message;

            if (verifiedType == ContactVerifiedType.Email && bl.isEmailVerified == YesNo.Yes)//&& emailServiceActive.ToUpper() == "TRUE"
            {
                rb = await VerifyOTP(bl.msgId, (Int16)ContactVerifiedType.Email, bl.emailOTP, bl.emailId);
                if (rb.status)
                {
                    proceedForUpdate = true;
                    verifiedString = @" isEmailVerified = @isEmailVerified, emailVerificationDate = @emailVerificationDate ";
                    pm.Add(new MySqlParameter("isEmailVerified", MySqlDbType.Int16) { Value = (Int16)bl.isEmailVerified });
                    pm.Add(new MySqlParameter("emailVerificationDate", MySqlDbType.DateTime) { Value = DateTime.Now });
                }
                else
                    proceedForUpdate = false;
            }
            if (verifiedType == ContactVerifiedType.Mobile && bl.isMobileVerified == YesNo.Yes)//&& smsServiceActive.ToUpper() == "TRUE"
            {
                rb = await VerifyOTP(bl.msgId, (Int16)ContactVerifiedType.Mobile, bl.smsOTP, bl.mobileNo.ToString());
                if (rb.status)
                {
                    proceedForUpdate = true;
                    verifiedString = @" isMobileVerified = @isMobileVerified, mobileVerificationDate = @mobileVerificationDate ";
                    pm.Add(new MySqlParameter("isMobileVerified", MySqlDbType.Int16) { Value = (Int16)bl.isMobileVerified });
                    pm.Add(new MySqlParameter("mobileVerificationDate", MySqlDbType.DateTime) { Value = DateTime.Now });
                }
                else
                    proceedForUpdate = false;
            }
            //if (smsServiceActive.ToUpper() == "FALSE" && smsServiceActive.ToUpper() == "FALSE")
            //{
            //    proceedForUpdate = true;
            //    verifiedString = @" isMobileVerified = @isMobileVerified, mobileVerificationDate = @mobileVerificationDate,
            //                        isEmailVerified = @isEmailVerified, emailVerificationDate = @emailVerificationDate  ";
            //    pm.Add(new MySqlParameter("isEmailVerified", MySqlDbType.Int16) { Value = (Int16)bl.isEmailVerified });
            //    pm.Add(new MySqlParameter("emailVerificationDate", MySqlDbType.DateTime) { Value = DateTime.Now });
            //    pm.Add(new MySqlParameter("isMobileVerified", MySqlDbType.Int16) { Value = (Int16)bl.isMobileVerified });
            //    pm.Add(new MySqlParameter("mobileVerificationDate", MySqlDbType.DateTime) { Value = DateTime.Now });

            //}
            if (proceedForUpdate)
            {
                string query = @"UPDATE userregistration 
                                 SET " + verifiedString +
                              @" WHERE registrationUId = @registrationUId";

                pm.Add(new MySqlParameter("registrationUId", MySqlDbType.String) { Value = bl.registrationUId });
                rb = await db.ExecuteQueryAsync(query, pm.ToArray(), "VerifyContactDetailsNewUserAsync");
                //if (rb.status)
                //{

                //}
            }
            else
            {
                rb.status = false;
                rb.message = "Invalid details provided.";
            }
            return rb;
        }
        /// <summary>
        /// Verify Email OTP
        /// isEmailOrMobileOTP=1:MobileOTP, IF isEmailOrMobileOTP=2 : Email OTP
        /// </summary>
        /// <returns>Industrial User Registration Id</returns>
        public async Task<ReturnClass.ReturnBool> VerifyOTP(string msgId, Int16 contactVerifiedType, Int32 OTP, string MobileOrEmailId)
        {
            ReturnClass.ReturnBool rb = new();
            string query = "", query1 = "";

            MySqlParameter[] pm = new MySqlParameter[]
           {
                new MySqlParameter("msgId", MySqlDbType.String) { Value = msgId},
                new MySqlParameter("mobileNo", MySqlDbType.String) { Value = MobileOrEmailId},
                new MySqlParameter("msgOtp", MySqlDbType.Int32) { Value = OTP},
                new MySqlParameter("emailId", MySqlDbType.String) { Value = MobileOrEmailId},
                 new MySqlParameter("OtpExpire", MySqlDbType.Int16) { Value = (Int16)OTPStatus.Expired},
           };
            if (contactVerifiedType == (Int16)ContactVerifiedType.Mobile)
            {

                MobileOrEmailId = MobileOrEmailId.ToString().Substring(MobileOrEmailId.ToString().Length - 10);
                string mobileno = MobileOrEmailId.ToString();

                Match match = Regex.Match(mobileno,
                             @"^[6-9]\d{9}$", RegexOptions.IgnoreCase);
                if (match.Success == false)
                {
                    rb.status = false;
                    rb.message = "Invalid Mobile Number";
                    return rb;
                }
                query = @"SELECT e.msgId,e.isOtpVerified,TIMESTAMPDIFF(SECOND, e.sendingDatetime, CURRENT_TIMESTAMP()) AS SMSSentTimeInSecond,
                            e.OTPAttemptLimit,e.msgOtp, e.emailId
                          FROM smssentdetail e
                          WHERE e.msgId = @msgId AND  e.mobileNo = @mobileNo";
                query1 = @"UPDATE smssentdetail SET OTPAttemptLimit= OTPAttemptLimit + 1 ";
            }
            else if (contactVerifiedType == (Int16)ContactVerifiedType.Email)
            {
                Match match = Regex.Match(MobileOrEmailId.ToString(),
                               @"^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+$", RegexOptions.IgnoreCase);
                if (match.Success == false)
                {
                    rb.status = false;
                    rb.message = "Given email id is not valid.";
                    return rb;
                }
                query = @"SELECT e.msgId,e.isOtpVerified,TIMESTAMPDIFF(SECOND, e.sendingDatetime, CURRENT_TIMESTAMP()) AS SMSSentTimeInSecond,
                                 e.OTPAttemptLimit,e.msgOtp
                          FROM emailsentdetail e
                          WHERE e.msgId = @msgId AND  e.emailId = @emailId ";
                query1 = @"UPDATE emailsentdetail SET OTPAttemptLimit= OTPAttemptLimit + 1 ";
            }

            dt = await db.ExecuteSelectQueryAsync(query, pm);
            Int32 OTPAttemptLimit = Convert.ToInt32(Utilities.GetAppSettings("SmsConfiguration", "OTPAttemptLimit").message);
            if (dt.table.Rows.Count > 0)
            {
                rb.value = dt.table.Rows[0]["isOtpVerified"].ToString();
                if (Convert.ToInt16(dt.table.Rows[0]["isOtpVerified"].ToString()) == (Int16)OTPStatus.Expired)
                {
                    rb.status = false;
                    rb.message = "OTP Expired.";
                    rb.value = dt.table.Rows[0]["isOtpVerified"].ToString();
                    return rb;
                }
                if (Convert.ToInt32(dt.table.Rows[0]["msgOtp"].ToString()) == OTP)
                {
                    rb.value = dt.table.Rows[0]["msgId"].ToString();
                    Int32 smsVerificationLimit = Convert.ToInt32(Utilities.GetAppSettings("SmsConfiguration", "SMSVerificationLimit").message);

                    if (Convert.ToInt32(dt.table.Rows[0]["SMSSentTimeInSecond"].ToString()) > smsVerificationLimit)//&& contactVerifiedType == (Int16)ContactVerifiedType.Mobile
                    {
                        query1 += @" , isOtpVerified=@OtpExpire  WHERE msgId = @msgId AND  mobileNo = @mobileNo ";
                        await db.ExecuteQueryAsync(query1, pm.ToArray(), "UPADATEOTPExpired");
                        rb.status = false;
                        rb.message = "OTP Expired.";
                        rb.value = dt.table.Rows[0]["isOtpVerified"].ToString();
                        return rb;
                    }

                    if (Convert.ToInt16(dt.table.Rows[0]["isOtpVerified"].ToString()) == (Int16)YesNo.Yes)
                    {
                        rb.status = false;
                        rb.message = "Invalid OTP Details.";
                        rb.value = "0";
                        return rb;
                    }
                    if (Convert.ToInt16(dt.table.Rows[0]["isOtpVerified"].ToString()) == (Int16)YesNo.No)
                    {
                        rb.status = true;
                        rb.value = dt.table.Rows[0]["emailId"].ToString();
                    }

                }
                else
                {
                    if ((Convert.ToInt16(dt.table.Rows[0]["OTPAttemptLimit"].ToString()) + 1) >= OTPAttemptLimit)
                        query1 += @" , isOtpVerified=@OtpExpire  WHERE msgId = @msgId AND  mobileNo = @mobileNo ";
                    else
                        query1 += @" WHERE msgId = @msgId AND  mobileNo = @mobileNo ";


                    rb = await db.ExecuteQueryAsync(query1, pm.ToArray(), "UPADATEOTPAttemptLimit");
                    if (rb.status)
                        rb.message = @"Invalid OTP, You have tried " + (Convert.ToInt16(dt.table.Rows[0]["OTPAttemptLimit"].ToString()) + 1).ToString()
                                    + @" attempts out of " + OTPAttemptLimit.ToString() + @".";
                    rb.status = false;
                    rb.value = dt.table.Rows[0]["isOtpVerified"].ToString();
                }
            }
            else
                rb.message = "Invalid OTP.";

            return rb;
        }
        /// <summary>
        /// Update Password to complete the registration process
        /// </summary>
        /// <param name="bl"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnBool> UpdateNewUserPasswordAsync(BlUser bl)
        {
            if (bl.password.Length > 7)
            {
                MySqlParameter[] pm = new MySqlParameter[]
                {
                new MySqlParameter("registrationUId", MySqlDbType.String) { Value = bl.registrationUId},
                new MySqlParameter("password", MySqlDbType.String) { Value = bl.password},
                new MySqlParameter("isVerified", MySqlDbType.Int16) { Value = YesNo.Yes},
                };
                string query = @" SELECT u.emailId,u.mobileNo FROM userregistration u
                              WHERE u.registrationUId = @registrationUId";

                dt = await db.ExecuteSelectQueryAsync(query, pm);
                if (dt.table.Rows.Count > 0)
                {
                    bl.emailId = dt.table.Rows[0]["emailId"].ToString();
                    bl.mobileNo = Convert.ToInt64(dt.table.Rows[0]["mobileNo"].ToString());
                }
                else
                {
                    rb.message = "Invalid Details Provided.";
                    return rb;
                }

                query = @" UPDATE userregistration 
                              SET password = @password
                              WHERE registrationUId = @registrationUId
                        AND (isMobileVerified = @isVerified OR isEmailVerified = @isVerified)";
                using (TransactionScope ts = new TransactionScope(TransactionScopeAsyncFlowOption.Enabled))
                {
                    rb = await db.ExecuteQueryAsync(query, pm, "UpdateNewUserPasswordAsync(update1) ");
                    if (rb.status)
                    {
                        query = @" INSERT INTO userlogin(userFirstName,userMiddleName,userLastName, userId, emailId, password, clientIp, userTypeCode, userRole )
                               SELECT u.applicantFirstName,u.applicantMiddleName,u.applicantLastName, u.registrationId, u.emailId, u.password, @clientIp, @userTypeCode, @userRole
                               FROM userregistration u 
                               WHERE u.registrationUId = @registrationUId";
                        MySqlParameter[] pmUser = new MySqlParameter[]
                        {
                    new MySqlParameter("registrationUId", MySqlDbType.String) { Value = bl.registrationUId},
                    new MySqlParameter("userTypeCode", MySqlDbType.Int16) { Value = (Int16)UserTypeCode.NotApplicable},
                    new MySqlParameter("userRole", MySqlDbType.Int16) { Value = (Int16)UserRole.OnlineUser},
                    new MySqlParameter("clientIp", MySqlDbType.VarChar) { Value = bl.clientIp},
                        };
                        rb = await db.ExecuteQueryAsync(query, pmUser, "UpdateNewUserPasswordAsync(insert)");
                    }
                    if (rb.status)
                    {
                        ts.Complete();
                        rb.message = "Your Account has been created successfully. Now you can login with your credentials and avail Single Window services.";
                    }
                    else
                        rb.message = "Failed to create your account. Please try later";
                }
                #region Send SMS and E-MAIL
                string webURL = Utilities.GetAppSettings("SmsConfiguration", "webURL").message;
                //SMS & sandesh SMS
                sandeshMessageBody smb = new();
                smb.contact = bl.mobileNo.ToString();
                smb.isOTP = false;
                smb.OTP = 0;
                smb.clientIp = bl.clientIp;
                smb.templateId = (Int32)SmsEmailTemplate.INDSWS_UserIdRetrieval;
                SMSParam smsParam = new();
                smsParam.value1 = bl.emailId;
                smsParam.value2 = webURL;
                DlCommon dlcommon = new();
                await dlcommon.SendSandesh(smb, smsParam);
                //Email
                SendEmail sendEmail = new();
                sendEmail.emailId = bl.emailId;
                sendEmail.templateId = (Int32)SmsEmailTemplate.INDSWS_UserIdRetrieval;
                await dlcommon.SendEmail(sendEmail, smsParam);
                #endregion
            }
            else
            {
                rb.message = "Password must be at least 8 characters";
            }
            return rb;
        }

        /// <summary>
        /// Returns Registration Id in the format P(3) YYYY NNN NNN N
        /// </summary>
        /// <returns>Industrial User Registration Id</returns>
        private async Task<ReturnClass.ReturnString> GenerateUserRegistrationId()
        {
            ReturnClass.ReturnString rs = new();
            string query = @"SELECT IFNULL(MAX(u.registrationCount),0)+1 AS  registrationCount
                             FROM userregistration u
                             WHERE u.registrationYear = YEAR(CURDATE());";

            dt = await db.ExecuteSelectQueryAsync(query);
            if (dt.table.Rows.Count > 0)
            {
                // ID Format = P(3) YYYY NNN NNN N
                string id = ((int)PrefixId.Visitor).ToString() + DateTime.Now.Year.ToString() + dt.table.Rows[0]["registrationCount"].ToString().PadLeft(7, '0');
                rs.id = Convert.ToInt64(id);
                rs.value = dt.table.Rows[0]["registrationCount"].ToString();
                rs.status = true;
            }
            return rs;
        }
        /// <summary>
        /// Verify Mobile number of Industrialist
        /// </summary>
        /// <param name="bl"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnBool> VerifyMobileNumber(BlUser bl)
        {
            string query = @"UPDATE userregistration u
                             SET u.isMobileVerified = @isMobileVerified, u.mobileVerificationDate = @mobileVerificationDate
                             WHERE u.registrationId = @registrationId ;";
            MySqlParameter[] pm = new MySqlParameter[]
            {
                new MySqlParameter("registrationId", MySqlDbType.Int64) { Value = bl.registrationId },
                new MySqlParameter("isMobileVerified", MySqlDbType.Int16) { Value = (int) YesNo.Yes},
                new MySqlParameter("mobileVerificationDate", MySqlDbType.VarChar) { Value = bl.mobileVerificationDate },
            };
            rb = await db.ExecuteQueryAsync(query, pm, "VerifyMobileNumber");
            return rb;
        }
        /// <summary>
        /// Verify Email Account of Industrialist
        /// </summary>
        /// <param name="bl"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnBool> VerifyEmailAccount(BlUser bl)
        {
            string query = @"UPDATE userregistration u
                             SET u.isEmailVerified = @isEmailVerified, u.emailVerificationDate = @emailVerificationDate
                             WHERE u.registrationId = @registrationId ;";
            MySqlParameter[] pm = new MySqlParameter[]
            {
                new MySqlParameter("registrationId", MySqlDbType.Int64) { Value = bl.registrationId },
                new MySqlParameter("isEmailVerified", MySqlDbType.Int16) { Value = (int) YesNo.Yes},
                new MySqlParameter("emailVerificationDate", MySqlDbType.VarChar) { Value = bl.mobileVerificationDate },
            };
            rb = await db.ExecuteQueryAsync(query, pm, "VerifyMobileNumber");
            return rb;
        }
        #endregion

        /// <summary>
        /// Check whether emailId is registered or not
        /// </summary>
        /// <param name="emailId"></param>
        /// <returns>Returns True when Account exists</returns>
        public async Task<ReturnClass.ReturnBool> CheckUserAccountExist(string? emailId)
        {
            string query = @"SELECT u.userId 
                             FROM userlogin u
                             WHERE u.emailId = @emailId ; ";
            MySqlParameter[] pm = new MySqlParameter[]
            {
                new MySqlParameter("emailId", MySqlDbType.VarChar) { Value = emailId},
            };
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            if (dt.table.Rows.Count > 0)
            {
                rb.status = true;
                rb.value = dt.table.Rows[0]["userId"].ToString();
            }
            else
                rb.message = "Invalid Email-Id";

            return rb;
        }

        public async Task<ReturnDataTable> CheckUserAccountForLogin(string? emailId)
        {
            string query = @"SELECT u.userId ,u.userRole AS  swsRoleId,1 AS isUserMigrate,'00' AS role_id
                             FROM userlogin u
                             WHERE u.emailId = @emailId ; ";
            Match match = Regex.Match(emailId.ToString(),
                             @"^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+$", RegexOptions.IgnoreCase);

            if (!match.Success)
            {
                query = @"SELECT  DISTINCT  l.login_id  AS userId,l.Role_Id AS swsRoleId,l.isUserMigrate,rl.Role_Id AS role_id
                                FROM  industry_user_registration.user_login l
                                INNER JOIN role rl ON rl.Role_Id=   l.Role_Id 
                                INNER jOIN industry_user_registration.userregistration ur ON ur.login_id=l.Login_Id
                                WHERE l.login_id=@emailId  AND  l.Active =@active AND  ur.verified=@active 
                                UNION all
                                SELECT DISTINCT l.Login_Id AS userId, 4 AS swsRoleId,l.isUserMigrate,l.role_id
                                FROM user_login l
                                INNER JOIN employees emp ON emp.emp_id = l.Login_Id
                                inner JOIN emp_office_mapping e ON  e.Emp_Id=emp.emp_id AND  e.active=@approved
                                inner JOIN office f ON  f.office_code =e.Office_Code   
                                INNER JOIN role r ON  r.role_id=l.role_id
                                WHERE  (l.User_Name=@emailId OR  l.Login_Id =@emailId) AND  l.Active =@active";
            }
            MySqlParameter[] pm = new MySqlParameter[]
            {
                new MySqlParameter("emailId", MySqlDbType.VarChar) { Value = emailId},
                new MySqlParameter("active", MySqlDbType.VarChar) { Value = "Y"},
                new MySqlParameter("approved", MySqlDbType.VarChar) { Value = "A"},
            };
            if (match.Success)
                dt = await db.ExecuteSelectQueryAsync(query, pm);
            else
                dt = await db1.ExecuteSelectQueryAsync(query, pm);


            if (dt.table.Rows.Count <= 0)
            {
                dt.status = false;
                dt.message = "Invalid User Id";
            }
            return dt;
        }

        #region Login Trail
        /// <summary>
        /// Create Login Trail
        /// </summary>
        /// <param name="ltr"></param>
        /// <returns>Session ID</returns>
        private async Task<ReturnClass.ReturnBool> CreateLoginTrail(LoginTrail ltr)
        {
            //=====Proceed only if the account is registered======
            if (ltr.userId > 0)
            {
                #region Creating Trail only when fresh login initiated
                if (ltr.logCategory == EventLogCategory.AccountAccess)
                {
                    ReturnClass.ReturnBool rbCounter = await UpdateLoginCounter(ltr.userId, ltr.isLoginSuccessful);
                    ltr.attemptCount = Convert.ToInt32(rbCounter.value);
                    string query = @" INSERT INTO logintrail(loginId, loginSource, clientIp, clientOs, clientBrowser, userAgent, accessMode, 
                                                    isLoginSuccessful, userId, attemptCount, authToken, refreshToken, refreshTokenExpiryTime)
                                            VALUES (@loginId, @loginSource, @clientIp, @clientOs, @clientBrowser, @userAgent, @accessMode, 
                                                    @isLoginSuccessful, @userId, @attemptCount,@authToken, @refreshToken, @refreshTokenExpiryTime) ";
                    MySqlParameter[] pm = new MySqlParameter[]
                    {
                        new MySqlParameter("loginId", MySqlDbType.VarChar) { Value = ltr.loginId },
                        new MySqlParameter("loginSource", MySqlDbType.VarChar) { Value = ltr.loginSource },
                        new MySqlParameter("clientIp", MySqlDbType.VarChar) { Value = ltr.clientIp },
                        new MySqlParameter("clientOs", MySqlDbType.VarChar) { Value = ltr.clientOs },
                        new MySqlParameter("clientBrowser", MySqlDbType.VarChar) { Value = ltr.clientBrowser },
                        new MySqlParameter("userAgent", MySqlDbType.VarChar) { Value = ltr.userAgent },
                        new MySqlParameter("accessMode", MySqlDbType.Int16) { Value = (int)ltr.accessMode },
                        new MySqlParameter("isLoginSuccessful", MySqlDbType.Int16) { Value = (int)ltr.isLoginSuccessful },
                        new MySqlParameter("userId", MySqlDbType.Int64) { Value = ltr.userId },
                        new MySqlParameter("attemptCount", MySqlDbType.Int16) { Value = ltr.attemptCount },
                        new MySqlParameter("authToken", MySqlDbType.VarChar) { Value = ltr.currentAuthToken },
                        new MySqlParameter("refreshToken", MySqlDbType.VarChar) { Value = ltr.refreshToken },
                        new MySqlParameter("refreshTokenExpiryTime", MySqlDbType.DateTime) { Value = ltr.refreshTokenExpiryTime },
                    };
                    rb = await db.ExecuteQueryAsync(query, pm, "CreateLoginTrail", true);
                }
                else if (ltr.logCategory == EventLogCategory.LoginExtended)
                {
                    string query = @" UPDATE logintrail 
                                      SET refreshToken = @refreshToken, refreshTokenExpiryTime = @refreshTokenExpiryTime, authToken = @newAuthToken,
                                          isSessionExtended = @isSessionExtended, sessionExtensionCount = @sessionExtensionCount
                                      WHERE authToken = @currentAuthToken ";
                    MySqlParameter[] pm = new MySqlParameter[]
                    {
                        new MySqlParameter("currentAuthToken", MySqlDbType.VarChar) { Value = ltr.currentAuthToken },
                        new MySqlParameter("newAuthToken", MySqlDbType.VarChar) { Value = ltr.newAuthToken },
                        new MySqlParameter("refreshToken", MySqlDbType.VarChar) { Value = ltr.refreshToken },
                        new MySqlParameter("refreshTokenExpiryTime", MySqlDbType.DateTime) { Value = ltr.refreshTokenExpiryTime },
                        new MySqlParameter("isSessionExtended", MySqlDbType.Int16) { Value = (int)ltr.isSessionExtended },
                        new MySqlParameter("sessionExtensionCount", MySqlDbType.Int32) { Value = ltr.sessionExtensionCount},
                    };
                    rb = await db.ExecuteQueryAsync(query, pm, "CreateLoginTrail (update) : ", true);
                }
                #endregion

                #region Event Log of Account Access
                if (rb.status)
                {
                    EventLog el = new();
                    el.logCategory = ltr.logCategory;
                    el.clientIp = ltr.clientIp;
                    el.sessionId = Convert.ToInt64(rb.value);
                    el.clientOs = ltr.clientOs;
                    el.clientBrowser = ltr.clientBrowser;
                    el.userAgent = ltr.userAgent;
                    el.userId = ltr.userId;
                    await CreateEventLog(el, ltr);
                }
                #endregion
            }
            return rb;
        }
        /// <summary>
        /// Count login Failure with in defined limit
        /// </summary>
        /// <param name="userId"></param>
        /// <returns>Failure login count</returns>
        private async Task<ReturnClass.ReturnString> CountLoginFailure(long userId)
        {
            int failedCount = 0;
            ReturnClass.ReturnString rs = new();

            string query = @"SELECT ul.failedAttemptCount, MINUTE(TIMEDIFF(NOW(), ul.lastLogin)) AS lastFailedAttemptMinute, 
                                    ul.disabledTime, ul.isDisabled
                             FROM userlogincounter ul
                             WHERE ul.userId = @userId; ";
            MySqlParameter[] pm = new MySqlParameter[]
            {
                new MySqlParameter("userId", MySqlDbType.Int64) { Value = userId}
            };
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            if (dt.table.Rows.Count > 0)
            {
                int lastCounter = Convert.ToInt16(dt.table.Rows[0]["failedAttemptCount"].ToString());
                int lastFailedAttemptMinute = Convert.ToInt16(dt.table.Rows[0]["lastFailedAttemptMinute"].ToString());
                bool isDisabled = dt.table.Rows[0]["isDisabled"].ToString() == "1";

                if (lastCounter > 0 && lastFailedAttemptMinute <= (int)FailedAttempt.Minutes)
                {
                    failedCount = lastCounter;
                }
                if (isDisabled)
                {
                    rs.secondryId = dt.table.Rows[0]["disabledTime"].ToString();
                    rs.msgId = dt.table.Rows[0]["isDisabled"].ToString();
                }
                rs.status = true;
            }
            rs.value = failedCount.ToString();
            return rs;
        }

        /// <summary>
        /// Manage Login Counter and Disables User if the limit reaches
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="isLoginSuccessful"></param>
        /// <returns></returns>
        private async Task<ReturnClass.ReturnBool> UpdateLoginCounter(long userId, YesNo isLoginSuccessful)
        {
            int failedCount = 0;
            List<MySqlParameter> pm = new()
            {
                new MySqlParameter("userId", MySqlDbType.Int64) { Value = userId }
            };

            ReturnClass.ReturnString rsCount = await CountLoginFailure(userId);
            YesNo isAccountDisabled = YesNo.No;
            string disabledTime = string.Empty;
            if (isLoginSuccessful == YesNo.No)
            {
                failedCount = Convert.ToInt16(rsCount.value) + 1;
                if (failedCount >= (int)FailedAttempt.Limit)
                {
                    //======Disable Login======
                    isAccountDisabled = YesNo.Yes;
                    if (rsCount.msgId == "1")
                    {
                        try
                        {
                            DateTime dt = Convert.ToDateTime(rsCount.secondryId);
                            disabledTime = dt.ToString("yyyy-MM-dd HH:mm:ss");
                        }
                        catch
                        {
                            disabledTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                        }
                    }
                    else
                        disabledTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                }
            }

            pm.Add(new MySqlParameter("failedAttemptCount", MySqlDbType.Int16) { Value = failedCount });
            pm.Add(new MySqlParameter("isDisabled", MySqlDbType.Int16) { Value = (int)isAccountDisabled });
            if (disabledTime == "")
                pm.Add(new MySqlParameter("disabledTime", MySqlDbType.VarChar) { Value = DBNull.Value });
            else
                pm.Add(new MySqlParameter("disabledTime", MySqlDbType.VarChar) { Value = disabledTime });

            string query = @"INSERT INTO userlogincounter(userId, failedAttemptCount)
                                         VALUES(@userId, @failedAttemptCount)";
            if (rsCount.status)
            {
                query = @"UPDATE userlogincounter u
                          SET u.failedAttemptCount = @failedAttemptCount, isDisabled = @isDisabled, disabledTime=@disabledTime 
                          WHERE u.userId = @userId; ";
            }
            rb = await db.ExecuteQueryAsync(query, pm.ToArray(), "UpdateFailureCount");
            rb.value = failedCount.ToString();
            return rb;
        }

        /// <summary>
        /// Enable / Disable login based on login counter
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="isDisabled"></param>
        /// <returns></returns>
        private async Task<ReturnClass.ReturnBool> EnableDisableLogin(long userId, YesNo isDisabled)
        {
            string query = @"UPDATE userlogin u
                             SET u.isDisabled = @isDisabled
                             WHERE u.userId = @userId ;";
            MySqlParameter[] pm = new MySqlParameter[]
            {
                new MySqlParameter("userId", MySqlDbType.Int64) { Value = userId },
                new MySqlParameter("isDisabled", MySqlDbType.Int16) { Value = (int)isDisabled },
            };
            rb = await db.ExecuteQueryAsync(query, pm, "EnableDisableLogin");
            return rb;
        }
        #endregion

        #region Authentication
        /// <summary>
        /// Check User credentials and issues authentication token on sucess. Use it for fresh login
        /// </summary>
        /// <param name="ulreq"></param>
        /// <param name="ltr"></param>
        /// <returns></returns>
        public async Task<UserLoginResponse> CheckUserLogin(UserLoginRequest ulreq, LoginTrail ltr)
        {
            UserLoginResponse ul = new();
            try
            {

                bool allowLogin = true;
                Int64 swsProjectId = 0;
                List<MySqlParameter> pm = new();
                pm.Add(new MySqlParameter("isActive", MySqlDbType.Int16) { Value = (int)IsActive.Yes });
                pm.Add(new MySqlParameter("emailId", MySqlDbType.VarChar) { Value = ulreq.emailId });
                pm.Add(new MySqlParameter("active", MySqlDbType.VarChar) { Value = "Y" });
                pm.Add(new MySqlParameter("approved", MySqlDbType.VarChar) { Value = "A" });
                pm.Add(new MySqlParameter("Industrialist", MySqlDbType.Int16) { Value = (Int16)UserRole.OnlineUser });
                pm.Add(new MySqlParameter("forceChangePassword", MySqlDbType.VarChar) { Value = "N" });
                string query = "";
                Match match = Regex.Match(ulreq.emailId.ToString(),
                             @"^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+$", RegexOptions.IgnoreCase);
                if (match.Success)
                {
                    query = @"SELECT '' AS emp_id,IFNULL(CONCAT(ul.userFirstName,' ',ul.userMiddleName,' ',
                                ul.userLastName),ul.userName) AS userName,ul.userFirstName,
                                ul.userMiddleName,ul.userLastName,ul.userId ,ul.userId AS loginId, ul.emailId,ul.password,
                                ul.forceChangePassword, uc.isDisabled, ul.userRole,
                                ul.isNationalSingleWindowUser,
                                IFNULL(TIMESTAMPDIFF(MINUTE, uc.disabledTime, NOW()),0) disabledMinutes, 0 AS openOTP,1 AS isDashboardMigrated
                                 FROM userlogin ul
                                 LEFT JOIN userlogincounter uc ON uc.userId = ul.userId
                                 WHERE ul.isActive = @isActive AND ul.emailId = @emailId ; ";
                }

                dt = await db.ExecuteSelectQueryAsync(query, pm.ToArray());


                if (dt.table.Rows.Count > 0)
                {
                    bool isDisabled = dt.table.Rows[0]["isDisabled"].ToString() == "1";
                    ltr.userId = Convert.ToInt64(dt.table.Rows[0]["userId"].ToString());
                    if (isDisabled)
                    {
                        int disabledMinutes = Convert.ToInt32(dt.table.Rows[0]["disabledMinutes"].ToString());
                        if (disabledMinutes > (int)FailedAttempt.Limit)
                            allowLogin = true;
                        else
                            allowLogin = false;
                    }
                    string passwordTbl = Utilities.CreateHash(ulreq.requestToken + dt.table.Rows[0]["password"].ToString(), HashingAlgorithmSupported.Sha256);

                    // if (dt.table.Rows[0]["password"].ToString().Trim() == ulreq.password.Trim())
                    if (1 == 1)
                    {
                        if (allowLogin)
                        {
                            ul.isLoginSuccessful = true;
                            ltr.isLoginSuccessful = YesNo.Yes;
                            ul.emailId = ulreq.emailId;
                            ul.userName = dt.table.Rows[0]["userName"].ToString();
                            ul.userFirstName = dt.table.Rows[0]["userFirstName"].ToString();
                            ul.userMiddleName = dt.table.Rows[0]["userMiddleName"].ToString();
                            ul.userLastName = dt.table.Rows[0]["userLastName"].ToString();
                            ul.forceChangePassword = dt.table.Rows[0]["forceChangePassword"].ToString() == "1";
                            ul.isNationalSingleWindowUser = dt.table.Rows[0]["isNationalSingleWindowUser"].ToString() == "1";
                            // ul.userTypeCode = Convert.ToInt16(dt.table.Rows[0]["userTypeCode"].ToString());
                            ul.primaryRole = Convert.ToInt16(dt.table.Rows[0]["userRole"].ToString());
                            ul.openOTP = Convert.ToInt16(dt.table.Rows[0]["openOTP"].ToString());
                            ul.isDashboardMigrated = Convert.ToInt16(dt.table.Rows[0]["isDashboardMigrated"].ToString());
                            ul.emp_id = dt.table.Rows[0]["emp_id"].ToString();
                            ul.userId = ltr.userId;
                            if (ltr.isSingleWindowUser == (Int16)YesNo.Yes) //&& ul.primaryRole==(Int16)UserRole.OnlineUser
                            {
                                ul.swsRedirectURL = ltr.swsRedirectURL;
                                ul.isSingleWindowUser = ltr.isSingleWindowUser;
                                ul.isDashboardMigrated = (Int16)YesNo.No;
                            }
                            //Utilities utilities = new Utilities();
                            //ReturnClass.ReturnBool rb1 = Utilities.GetAppSettings("AppSettings", "EncIndustryAESKey");
                            //if (rb1.status)
                            //{
                            //    ul.loginId = utilities.EncryptAES(dt.table.Rows[0]["loginId"].ToString(), rb1.message);
                            //}
                            ul.userFirstName = ul.userFirstName == string.Empty ? ul.userName! : ul.userFirstName!;
                            #region Create JWT Token
                            List<Claim> claims = new();
                            // Possible null reference argument.
                            claims.Add(new Claim(ClaimTypes.Name, ul.userFirstName, ul.userMiddleName, ul.userLastName));
                            claims.Add(new Claim("userId", ltr.userId.ToString()));
                            claims.Add(new Claim("userTypeCode", ul.userTypeCode.ToString()));
                            claims.Add(new Claim(ClaimTypes.Role, ul.primaryRole.ToString()));

                            //claims.Add(new Claim("isNationalSingleWindowUser", userLoginResponse.isNationalSingleWindowUser.ToString()));
                            ltr.currentAuthToken = ul.authToken = Helper.CreateAuthenticationToken(claims);
                            ltr.refreshToken = ul.refreshToken = Helper.GenerateRefreshToken();

                            ReturnClass.ReturnBool rbMin = Utilities.GetAppSettings("AppSettings", "SessionDurationInMinutes");
                            int TokenExpiry = rbMin.status ? Convert.ToInt32(rbMin.message) : 60;
                            ul.refreshTokenExpiryTime = ltr.refreshTokenExpiryTime = DateTime.Now.AddMinutes(TokenExpiry);

                            if (ltr.accessMode == AccessMode.MobileApp)
                            {
                                rbMin = Utilities.GetAppSettings("AppSettings", "RefreshTokenExpiryInDaysForMobileApp");
                                TokenExpiry = rbMin.status ? Convert.ToInt32(rbMin.message) : 7;
                                ltr.refreshTokenExpiryTime = DateTime.Now.AddDays(TokenExpiry);
                            }
                            #endregion
                        }
                        else
                            ul.message = "Your account has been disabled for " + ((int)FailedAttempt.Minutes).ToString() + " minutes, due to multiple failed login attempt.";
                    }

                    if (ltr.isLoginSuccessful == YesNo.No)
                    {
                        int failedCount = 0;
                        ReturnClass.ReturnString rsCount = await CountLoginFailure(ltr.userId);
                        failedCount = Convert.ToInt16(rsCount.value) + 1;

                        if (isDisabled || failedCount >= (int)FailedAttempt.Limit)
                            ul.message = "Your account has been disabled for " + ((int)FailedAttempt.Minutes).ToString() + " minutes, due to multiple failed login attempt.";
                        else
                            ul.message = "Invalid credentials. This is your " + failedCount
                                      + " failed attempt. Your account will be locked for " + ((int)FailedAttempt.Minutes).ToString()
                                      + " minutes in case of " + ((int)FailedAttempt.Limit).ToString() + " successive failed attempts.";
                    }
                }
                else
                    ul.message = "Invalid login";
                #region Login trail
                ltr.loginId = ulreq.emailId;
                await CreateLoginTrail(ltr);
                #endregion


            }
            catch (Exception ex)
            {
                WriteLog.Error("CheckUserLogin - ", ex);
            }
            return ul;
        }
        /// <summary>
        /// Use it for refresh login
        /// </summary>
        /// <param name="ltr"></param>
        /// <param name="principalClaims"></param>
        /// <returns></returns>
        public async Task<UserLoginResponseSessionExtension> ExtendUserLoginSession(LoginTrail ltr, ClaimsPrincipal principalClaims)
        {
            UserLoginResponseSessionExtension ul = new();
            bool allowLogin = false;

            List<MySqlParameter> pm = new()
            {
                new MySqlParameter("isActive", MySqlDbType.Int16) { Value = (int)IsActive.Yes },
                new MySqlParameter("authToken", MySqlDbType.VarString) { Value = ltr.currentAuthToken }
            };

            string query = @"SELECT lt.userId, lt.refreshToken, lt.refreshTokenExpiryTime, uc.isDisabled, 
		                            TIMESTAMPDIFF(MINUTE, uc.disabledTime, NOW()) disabledMinutes, lt.isSessionRevoked,
                                    IFNULL(sessionExtensionCount, 0) sessionExtensionCount
                             FROM logintrail lt
                             INNER JOIN userlogincounter uc ON uc.userId = lt.userId
                             INNER JOIN userlogin ul ON ul.userId = lt.userId
                             WHERE ul.isActive = @isActive AND lt.authToken = @authToken ; ";

            dt = await db.ExecuteSelectQueryAsync(query, pm.ToArray());
            if (dt.table.Rows.Count > 0)
            {
                long userId = Convert.ToInt64(dt.table.Rows[0]["userId"].ToString());
                int sessionExtensionCount = Convert.ToInt32(dt.table.Rows[0]["sessionExtensionCount"].ToString()) + 1;
                if (userId == ltr.userId)
                {
                    //========Check for Session Revokation. Proceed only if session is not revoked========
                    // Yes = 1, No = 0
                    if (dt.table.Rows[0]["isSessionRevoked"].ToString() == "0")
                    {
                        bool isDisabled = dt.table.Rows[0]["isDisabled"].ToString() == "1";
                        if (isDisabled)
                        {
                            int disabledMinutes = Convert.ToInt32(dt.table.Rows[0]["disabledMinutes"].ToString());
                            if (disabledMinutes > (int)FailedAttempt.Limit)
                                allowLogin = true;
                        }
                        else
                            allowLogin = true;
                        if (allowLogin)
                        {
                            ul.isLoginSuccessful = true;
                            ltr.isLoginSuccessful = YesNo.Yes;

                            ul.authToken = Helper.CreateAuthenticationToken(principalClaims.Claims.ToList());
                            ul.refreshToken = Helper.GenerateRefreshToken();

                            ltr.newAuthToken = ul.authToken;
                            ltr.refreshToken = ul.refreshToken;

                            ltr.isSessionExtended = YesNo.Yes;
                            ltr.sessionExtensionCount = sessionExtensionCount;

                            ReturnClass.ReturnBool rbMin = new();
                            if (ltr.accessMode == AccessMode.WebPortal)
                            {
                                rbMin = Utilities.GetAppSettings("AppSettings", "SessionDurationInMinutes");
                                int TokenExpiry = rbMin.status ? Convert.ToInt32(rbMin.message) : 30;
                                ltr.refreshTokenExpiryTime = DateTime.Now.AddMinutes(TokenExpiry);
                            }
                            else if (ltr.accessMode == AccessMode.MobileApp)
                            {
                                rbMin = Utilities.GetAppSettings("AppSettings", "RefreshTokenExpiryInDaysForMobileApp");
                                int TokenExpiry = rbMin.status ? Convert.ToInt32(rbMin.message) : 1;
                                ltr.refreshTokenExpiryTime = DateTime.Now.AddDays(TokenExpiry);
                            }
                            ul.refreshTokenExpiryTime = ltr.refreshTokenExpiryTime;
                        }
                        else
                            ul.message = "Your account has been disabled for " + ((int)FailedAttempt.Limit).ToString() + " due to multiple failed login attempt.";
                    }
                    else
                        ul.message = "Your Session has been revoked";
                }
                else
                    ul.message = "Invalid Token";
            }
            else
                ul.message = "Invalid Token";
            #region Login trail
            await CreateLoginTrail(ltr);
            #endregion
            return ul;
        }
        /// <summary>
        /// Log Out user.
        /// </summary>
        /// <param name="ltr"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnBool> LogOutUser(LoginTrail ltr)
        {
            string query = @"SELECT lt.sessionId
                             FROM  logintrail lt
                             WHERE authToken = @authToken AND lt.isSessionRevoked=@isSessionRevoked ";
            MySqlParameter[] sp = new MySqlParameter[]
            {
                new MySqlParameter("authToken", MySqlDbType.VarString) { Value = ltr.currentAuthToken },
                new MySqlParameter("isSessionRevoked", MySqlDbType.VarString) { Value = (int)YesNo.No}
            };
            ReturnClass.ReturnDataTable dt = await db.ExecuteSelectQueryAsync(query, sp);
            if (dt.table.Rows.Count > 0)
            {
                query = @" UPDATE logintrail 
                           SET isSessionRevoked = @isSessionRevoked, logOutTime = NOW()
                           WHERE authToken = @authToken ";
                MySqlParameter[] pm = new MySqlParameter[]
                {
                    new MySqlParameter("isSessionRevoked", MySqlDbType.Int16) { Value = YesNo.Yes },
                    new MySqlParameter("authToken", MySqlDbType.VarString) { Value = ltr.currentAuthToken },
                };
                EventLog el = new();
                el.logCategory = ltr.logCategory;
                el.clientIp = ltr.clientIp;
                el.sessionId = Convert.ToInt64(dt.table.Rows[0]["sessionId"].ToString());
                el.clientOs = ltr.clientOs;
                el.clientBrowser = ltr.clientBrowser;
                el.userAgent = ltr.userAgent;
                el.userId = ltr.userId;
                await CreateEventLog(el, ltr);
                rb = await db.ExecuteQueryAsync(query, pm, "LogOutUser");
                if (rb.status)
                    rb.message = "Successfully logged out";
            }
            else
                rb.message = "Invalid Session. Unable to logout";
            return rb;
        }

        public async Task<UserLoginResponse> CheckUserLoginwithOTP(SendOtp ulreq, LoginTrail ltr)
        {
            UserLoginResponse ul = new();
            Int64 swsProjectId = 0;
            try
            {
                string buildVersion = Utilities.GetAppSettings("Build", "Version").message;
                if (buildVersion.ToLower() == "production")
                    rb = await VerifyPublicOTP(ulreq.msgId, (int)ulreq.OTP, ulreq.mobileNo.ToString());
                else
                    rb.status = true;
                if (!rb.status)
                {
                    ul.message = rb.message;
                    ul.userLastName = rb.value;
                    return ul;
                }
                bool allowLogin = true;
                List<MySqlParameter> pm = new();
                pm.Add(new MySqlParameter("isActive", MySqlDbType.Int16) { Value = (int)IsActive.Yes });
                pm.Add(new MySqlParameter("emailId", MySqlDbType.VarChar) { Value = ulreq.emailId });
                pm.Add(new MySqlParameter("approved", MySqlDbType.VarChar) { Value = "A" });
                pm.Add(new MySqlParameter("active", MySqlDbType.VarChar) { Value = "Y" });
                string query = "";
                Match match = Regex.Match(ulreq.emailId.ToString(),
                            @"^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+$", RegexOptions.IgnoreCase);

                if (match.Success)
                {
                    query = @"SELECT '' AS emp_id,IFNULL(CONCAT(ul.userFirstName,' ',ul.userMiddleName,' ',
                                ul.userLastName),ul.userName) AS userName,ul.userFirstName,
                                ul.userMiddleName,ul.userLastName,ul.userId ,ul.userId AS loginId, ul.emailId,
                                ul.forceChangePassword, uc.isDisabled, ul.userRole,
                                ul.isNationalSingleWindowUser,
                                IFNULL(TIMESTAMPDIFF(MINUTE, uc.disabledTime, NOW()),0) disabledMinutes, 0 AS openOTP,1 AS isDashboardMigrated
                                 FROM userlogin ul
                                 LEFT JOIN userlogincounter uc ON uc.userId = ul.userId
                                 WHERE ul.isActive = @isActive AND ul.emailId = @emailId ; ";
                }
                else if (ulreq.nswsRequest)
                {
                    query = @"SELECT DISTINCT '' AS emp_id,ur.applicant_name AS userName,ur.firstName AS userFirstName,ur.middleName AS userMiddleName, 
                                ur.lastName AS userLastName,ur.applicant_id AS userId,ur.login_id AS loginId,ur.applicant_email_id AS emailId, 
                                @forceChangePassword as forceChangePassword,0 AS isDisabled , 
                                @Industrialist AS userRole,1 AS isNationalSingleWindowUser 0 AS disabledMinutes , 0 AS openOTP,1 AS isDashboardMigrated
			                        FROM industry_user_registration.userregistration ur 
			                        INNER JOIN role rl ON rl.Role_Id= l.Role_Id 
	                         WHERE ur.login_id = @emailId AND ur.Active = @active AND  ur.verified = @active ";
                }
                else
                {
                    query = @"SELECT  DISTINCT '' AS emp_id,user_name AS userName,user_name AS userFirstName,'' AS userMiddleName, 
                                '' AS userLastName,ur.applicant_id AS userId,l.login_id AS loginId,ur.applicant_email_id AS emailId, 
                                l.Change_Password as forceChangePassword,0 AS isDisabled , 
                                rl.Role_Id AS userRole,0 AS isNationalSingleWindowUser,
                                 0 AS disabledMinutes, rl.isOTPRequired AS openOTP,rl.isDashboardMigrated
                                    FROM  industry_user_registration.user_login l 
                        INNER JOIN role rl ON rl.Role_Id= l.Role_Id 
                         INNER jOIN industry_user_registration.userregistration ur ON ur.login_id=l.Login_Id 
                        WHERE  l.login_id=@emailId  AND  l.Active =@active AND  ur.verified=@active 
                         UNION all
                         SELECT DISTINCT emp.emp_id,emp.Emp_Name AS userName,emp.Emp_Name AS userFirstName, 
                         '' AS userMiddleName,'' AS userLastName,
                         l.Login_Id AS userId,l.Login_Id AS loginId,emp.Emp_Email_Id AS emailId,   
                           l.Change_Password as forceChangePassword,0 AS isDisabled,  
                         l.Role_Id_New AS userRole,
                          0 AS isNationalSingleWindowUser, 
                         0 AS disabledMinutes, r.isOTPRequired AS openOTP ,r.isDashboardMigrated
                         FROM user_login l 
                         INNER JOIN employees emp ON emp.emp_id = l.Login_Id 
                         inner JOIN  emp_office_mapping e ON  e.Emp_Id=emp.emp_id AND  e.active=@approved 
                         inner JOIN  office f ON  f.office_code =e.Office_Code 
                         INNER JOIN role r ON  r.role_id=l.role_id 
                         WHERE  (l.User_Name=@emailId OR  l.Login_Id =@emailId) AND  l.Active =@active  ";

                }
                if (match.Success)
                    dt = await db.ExecuteSelectQueryAsync(query, pm.ToArray());
                else
                    dt = await db1.ExecuteSelectQueryAsync(query, pm.ToArray());
                if (dt.table.Rows.Count > 0)
                {
                    bool isDisabled = dt.table.Rows[0]["isDisabled"].ToString() == "1";
                    ltr.userId = Convert.ToInt64(dt.table.Rows[0]["userId"].ToString());
                    if (isDisabled)
                    {
                        int disabledMinutes = Convert.ToInt32(dt.table.Rows[0]["disabledMinutes"].ToString());
                        if (disabledMinutes > (int)FailedAttempt.Limit)
                            allowLogin = true;
                        else
                            allowLogin = false;
                    }
                    //if (ulreq.password == dt.table.Rows[0]["password"].ToString())
                    //{
                    if (allowLogin)
                    {
                        ul.isLoginSuccessful = true;
                        ltr.isLoginSuccessful = YesNo.Yes;
                        ul.userName = dt.table.Rows[0]["userName"].ToString();
                        ul.userFirstName = dt.table.Rows[0]["userFirstName"].ToString();
                        ul.userMiddleName = dt.table.Rows[0]["userMiddleName"].ToString();
                        ul.userLastName = dt.table.Rows[0]["userLastName"].ToString();
                        ul.forceChangePassword = dt.table.Rows[0]["forceChangePassword"].ToString() == "1";
                        ul.isNationalSingleWindowUser = dt.table.Rows[0]["isNationalSingleWindowUser"].ToString() == "1";
                        //ul.userTypeCode = Convert.ToInt16(dt.table.Rows[0]["userTypeCode"].ToString());
                        ul.primaryRole = Convert.ToInt16(dt.table.Rows[0]["userRole"].ToString());
                        ul.openOTP = Convert.ToInt16(dt.table.Rows[0]["openOTP"].ToString());
                        ul.isDashboardMigrated = Convert.ToInt16(dt.table.Rows[0]["isDashboardMigrated"].ToString());
                        ul.emp_id = dt.table.Rows[0]["emp_id"].ToString();
                        ul.userId = ltr.userId;
                        if (ltr.isSingleWindowUser == (Int16)YesNo.Yes) //&& ul.primaryRole==(Int16)UserRole.OnlineUser
                        {
                            ul.swsRedirectURL = ltr.swsRedirectURL;
                            ul.isSingleWindowUser = ltr.isSingleWindowUser;
                            ul.isDashboardMigrated = (Int16)YesNo.No;
                        }
                        Utilities utilities = new Utilities();
                        ReturnClass.ReturnBool rb1 = Utilities.GetAppSettings("AppSettings", "EncIndustryAESKey");
                        if (rb1.status)
                        {
                            ul.loginId = utilities.EncryptAES(dt.table.Rows[0]["loginId"].ToString(), rb1.message);
                        }

                        if ((Int16)UserRole.ServiceProviderDepartmentalUser == ul.primaryRole || (Int16)UserRole.IndustryNodalUser == ul.primaryRole)//&& ul.userTypeCode== (Int16)UserTypeCode.NodalOfficer
                        {
                            query = @"SELECT sp.stateId,sp.swsProjectId,sp.districtId,sp.deptNameEnglish,sp.deptNameLocal,sp.deptShortName FROM 
												swsregisteredprojects sp WHERE sp.officeEmail=@emailId ; ";
                            dt = await db.ExecuteSelectQueryAsync(query, pm.ToArray());
                            List<UserProjectResponse> userProjectResponse = new List<UserProjectResponse>();
                            if (dt.table.Rows.Count > 0)
                            {
                                userProjectResponse.Add(new UserProjectResponse());
                                userProjectResponse[0].stateId = Convert.ToInt16(dt.table.Rows[0]["stateId"].ToString());
                                userProjectResponse[0].swsProjectId = Convert.ToInt64(dt.table.Rows[0]["swsProjectId"].ToString());
                                userProjectResponse[0].districtId = Convert.ToInt16(dt.table.Rows[0]["districtId"].ToString());
                                userProjectResponse[0].deptNameEnglish = dt.table.Rows[0]["deptNameEnglish"].ToString();
                                userProjectResponse[0].deptNameLocal = dt.table.Rows[0]["deptNameLocal"].ToString();
                                userProjectResponse[0].deptShortName = dt.table.Rows[0]["deptShortName"].ToString();
                                ul.userProjectResponse = userProjectResponse;
                            }
                        }

                        #region Create JWT Token
                        List<Claim> claims = new();
                        // Possible null reference argument.
                        claims.Add(new Claim(ClaimTypes.Name, ul.userFirstName, ul.userMiddleName, ul.userLastName));

                        claims.Add(new Claim("userId", ltr.userId.ToString()));
                        claims.Add(new Claim("userTypeCode", ul.userTypeCode.ToString()));

                        claims.Add(new Claim(ClaimTypes.Role, ul.primaryRole.ToString()));

                        //claims.Add(new Claim("isNationalSingleWindowUser", userLoginResponse.isNationalSingleWindowUser.ToString()));
                        ltr.currentAuthToken = ul.authToken = Helper.CreateAuthenticationToken(claims);
                        ltr.refreshToken = ul.refreshToken = Helper.GenerateRefreshToken();

                        ReturnClass.ReturnBool rbMin = Utilities.GetAppSettings("AppSettings", "SessionDurationInMinutes");
                        int TokenExpiry = rbMin.status ? Convert.ToInt32(rbMin.message) : 60;
                        ul.refreshTokenExpiryTime = ltr.refreshTokenExpiryTime = DateTime.Now.AddMinutes(TokenExpiry);

                        if (ltr.accessMode == AccessMode.MobileApp)
                        {
                            rbMin = Utilities.GetAppSettings("AppSettings", "RefreshTokenExpiryInDaysForMobileApp");
                            TokenExpiry = rbMin.status ? Convert.ToInt32(rbMin.message) : 7;
                            ltr.refreshTokenExpiryTime = DateTime.Now.AddDays(TokenExpiry);
                        }
                        #endregion
                    }
                    else
                        ul.message = "Your account has been disabled for " + ((int)FailedAttempt.Minutes).ToString() + " minutes, due to multiple failed login attempt.";
                    //}

                    if (ltr.isLoginSuccessful == YesNo.No)
                    {
                        int failedCount = 0;
                        ReturnClass.ReturnString rsCount = await CountLoginFailure(ltr.userId);
                        failedCount = Convert.ToInt16(rsCount.value) + 1;

                        if (isDisabled || failedCount >= (int)FailedAttempt.Limit)
                            ul.message = "Your account has been disabled for " + ((int)FailedAttempt.Minutes).ToString() + " minutes, due to multiple failed login attempt.";
                        else
                            ul.message = "Invalid credentials. This is your " + failedCount
                                      + " failed attempt. Your account will be locked for " + ((int)FailedAttempt.Minutes).ToString()
                                      + " minutes in case of " + ((int)FailedAttempt.Limit).ToString() + " successive failed attempts.";
                    }
                }
                else
                    ul.message = "Invalid login";
                #region Login trail
                ltr.loginId = ulreq.emailId;
                await CreateLoginTrail(ltr);
                #endregion




            }
            catch (Exception ex)
            {
                WriteLog.Error("CheckUserLoginWithOTP - ", ex);
            }
            return ul;
        }
        #endregion
        public async Task<UserLoginResponse> GetAuthenticationTokenDetails(string? authToken)
        {
            UserLoginResponse ulr = new();
            string query = @" SELECT lt.refreshToken, lt.refreshTokenExpiryTime
                              FROM logintrail lt
                              WHERE lt.authToken = @authToken AND lt.isSessionRevoked=@isSessionRevoked ; ";
            MySqlParameter[] pm = new MySqlParameter[]
            {
                new MySqlParameter("authToken", MySqlDbType.VarString) { Value = authToken},
                new MySqlParameter("isSessionRevoked", MySqlDbType.VarString) { Value = (int)YesNo.No},
            };
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            if (dt.table.Rows.Count > 0)
            {
                ulr.refreshToken = dt.table.Rows[0]["refreshToken"].ToString();
                ulr.refreshTokenExpiryTime = Convert.ToDateTime(dt.table.Rows[0]["refreshTokenExpiryTime"].ToString());
            }
            return ulr;
        }
        /// <summary>
        /// Generates Event Log
        /// </summary>
        /// <param name="el"></param>
        /// <param name="ltr"></param>
        /// <returns></returns>
        private static async Task<ReturnClass.ReturnBool> CreateEventLog(EventLog el, LoginTrail ltr)
        {
            DlCommon dl = new();
            #region Event Log of Account Access
            if (el.logCategory == EventLogCategory.LoginExtended && ltr.isLoginSuccessful == YesNo.Yes)
            {
                el.logDescription = "Your login session has been extended. Request from " + el.clientIp;
                el.logLevel = EventLogLevel.Info;
            }
            else if (el.logCategory == EventLogCategory.AccountAccess)
            {
                if (ltr.isLoginSuccessful == YesNo.Yes)
                {
                    el.logDescription = "Your account has been accessed from " + el.clientIp;
                    el.logLevel = EventLogLevel.Info;
                }
                else
                {
                    if (ltr.attemptCount > (int)FailedAttempt.Limit)
                    {
                        el.logDescription = "Your account has been disabled due to multiple login failure";
                        el.logLevel = EventLogLevel.Error;
                    }
                    else
                    {
                        el.logDescription = "Failed login attempt from " + el.clientIp;
                        el.logLevel = EventLogLevel.Warning;
                    }
                }
            }
            else if (el.logCategory == EventLogCategory.LogOut)
            {
                el.logLevel = EventLogLevel.Info;
                el.logDescription = "Successfully logged out.";
            }
            return await dl.CreateEventLog(el);
            #endregion
        }
        public async Task<ReturnClass.ReturnBool> GetAccountDisabledTime(long userId)
        {
            ReturnClass.ReturnBool rb = new();
            string query = @"SELECT u.disabledTime 
                             FROM userlogincounter u
                             WHERE u.userId = @userId AND u.isDisabled = @isDisabled ";
            MySqlParameter[] pm = new MySqlParameter[]
            {
                new MySqlParameter("isDisabled", MySqlDbType.Int16) { Value = (int)YesNo.Yes},
                new MySqlParameter("userId", MySqlDbType.Int64) { Value = userId},
            };
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            if (dt.table.Rows.Count > 0)
            {
                rb.status = true;
                rb.value = dt.table.Rows[0]["disabledTime"].ToString();
            }
            return rb;
        }
        public async Task<ReturnClass.ReturnBool> ChangeUserPassword(BlUser blUser, long sessionId)
        {
            ReturnClass.ReturnBool rb = new ReturnClass.ReturnBool();
            Match match = Regex.Match(blUser.emailId.ToString(),
                            @"^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+$", RegexOptions.IgnoreCase);
            if (match.Success)
            {
                #region Change Password into SWS Chhattisgarh DB
                if (blUser.password.Length > 7)
                {
                    bool isPasswordCheckEnabled = Utilities.GetAppSettings("AppSettings", "PreviousPasswordLimit").message == "1";
                    bool passwordMatch = false;

                    //Match Old Password
                    try
                    {
                        int previousPasswordLimit = 1;
                        bool passwordMatch1 = await CheckPreviousPasswords((long)blUser.registrationId, blUser.oldPassword, previousPasswordLimit);
                        if (!passwordMatch1)
                        {
                            rb.message = "Old password should be Matched!!";
                            rb.status = false;
                            return rb;
                        }
                    }
                    catch { }

                    if (isPasswordCheckEnabled)
                    {
                        try
                        {
                            int previousPasswordLimit = Convert.ToInt16(Utilities.GetAppSettings("AppSettings", "PreviousPasswordLimit").message);
                            passwordMatch = await CheckPreviousPasswords((long)blUser.registrationId, blUser.password, previousPasswordLimit);
                        }
                        catch { }
                    }

                    if (!passwordMatch)
                    {
                        string query = @" INSERT INTO userloginlog
                                  SELECT * FROM userlogin u
                                  WHERE u.userId = @userId ";
                        MySqlParameter[] pmLog = new MySqlParameter[]
                        {
                    new MySqlParameter("userId", MySqlDbType.Int64) { Value = blUser.registrationId },
                        };
                        using (TransactionScope ts = new(TransactionScopeAsyncFlowOption.Enabled))
                        {
                            rb = await db.ExecuteQueryAsync(query, pmLog, "UpdateUserPassword(Log)");
                            if (rb.status)
                            {
                                query = @" UPDATE userlogin 
                                   SET password = @password, modificationType = @modificationType, clientIp = @clientIp
                                   WHERE userId = @userId ";
                                MySqlParameter[] pmUpdate = new MySqlParameter[]
                                {
                            new MySqlParameter("modificationType", MySqlDbType.String) { Value = "Password Changed" },
                            new MySqlParameter("password", MySqlDbType.String) { Value = blUser.password},
                            new MySqlParameter("userId", MySqlDbType.Int64) { Value = blUser.registrationId },
                            new MySqlParameter("clientIp", MySqlDbType.VarChar) { Value = blUser.clientIp}
                                };
                                rb = await db.ExecuteQueryAsync(query, pmUpdate, "UpdateUserPassword");

                                if (rb.status)
                                {

                                    EventLog el = new();
                                    el.logCategory = EventLogCategory.PasswordChanged;
                                    el.logDescription = "Your Password has been changed on " + DateTime.Now.ToString("dd/MM/yyyy hh:mm:ss tt") + " from " + el.clientIp;
                                    el.logLevel = EventLogLevel.Info;
                                    el.clientIp = blUser.clientIp;
                                    el.sessionId = sessionId;
                                    el.clientOs = blUser.clientOs;
                                    el.clientBrowser = blUser.clientBrowser;
                                    el.userAgent = blUser.userAgent;
                                    el.userId = (long)blUser.registrationId;
                                    await dlCommon.CreateEventLog(el);
                                    ts.Complete();
                                    rb.message = "Password has been changed successfully !!!";
                                }
                            }
                        }
                    }
                    else
                        rb.message = "Current password can not be the same as previous passwords";
                }
                else
                {
                    rb.message = "Password must be at least 8 characters";
                }
                #endregion
            }
            else
            {
                #region Change Password into Industries Old DB           
                rb = await ChangeOldIndustriesUsersPassword(blUser);
                #endregion
            }
            return rb;
        }

        /// <summary>
        /// Checks Previous (n) Password, Default value is 5
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="password"></param>
        /// <param name="previousPasswordLimit"></param>
        /// <returns></returns>
        private async Task<bool> CheckPreviousPasswords(long userId, string password, int previousPasswordLimit)
        {
            bool passwordMatched = false;
            previousPasswordLimit = previousPasswordLimit > 0 ? previousPasswordLimit : 5;
            string query = @" SELECT u.password 
                              FROM userlogin u
                              WHERE u.userId = @userId 
                              ORDER BY u.lastUpdate DESC 
                              LIMIT " + previousPasswordLimit.ToString();
            MySqlParameter[] pm = new MySqlParameter[]
            {
                new MySqlParameter("userId", MySqlDbType.Int64) { Value = userId},
            };
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            if (dt.table.Rows.Count > 0)
            {
                foreach (DataRow dr in dt.table.Rows)
                {
                    if (dr["password"].ToString() == password)
                    {
                        passwordMatched = true;
                        break;
                    }
                }
            }
            return passwordMatched;
        }

        /// <summary>
        /// Retutns Session ID Based on Auth Token
        /// </summary>
        /// <param name="authToken"></param>
        /// <returns></returns>
        public async Task<long> GetSessionId(string? authToken)
        {
            string query = @"SELECT lt.sessionId
                             FROM  logintrail lt
                             WHERE authToken = @authToken;";
            MySqlParameter[] sp = new MySqlParameter[]
            {
                new MySqlParameter("authToken", MySqlDbType.VarString) { Value = authToken },
            };
            dt = await db.ExecuteSelectQueryAsync(query, sp);
            if (dt.table.Rows.Count > 0)
                return Convert.ToInt64(dt.table.Rows[0]["sessionId"].ToString());
            else
                return 0;
        }

        /// <summary>
        /// Send OTP 
        /// </summary>
        /// <param name="bl"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnString> SendOTP(SendOtp bl)
        {
            ReturnClass.ReturnString rs = new();
            ReturnClass.ReturnBool rb = new ReturnClass.ReturnBool();

            bl.mobileNo = Convert.ToInt64(bl.mobileNo.ToString().Substring(bl.mobileNo.ToString().Length - 10));
            string mobileno = bl.mobileNo.ToString();

            Match match = Regex.Match(mobileno,
                              @"^[6-9]\d{9}$", RegexOptions.IgnoreCase);
            if (match.Success == false)
            {
                rs.status = false;
                rs.message = "Invalid Mobile Number";
                return rs;
            }
            dt = await CheckSMSSendDuration(mobileno, (Int16)SMSSendType.Send);
            if (dt.status)
            {
                rs.status = false;
                rs.value = dt.value;
                rs.message = dt.message;
                if (rs.value.ToString().Trim() != ((Int16)OTPStatus.Expired).ToString().Trim())
                {
                    rs.msgId = dt.type;
                    rs.secondryId = mobileno.ToString();
                }
                return rs;
            }
            DlCommon dlCommon = new();

            Utilities util = new Utilities();
            Int64 smsotp = util.GenRandomNumber(4);
            rs.secondryId = "Your Mobile OTP is " + smsotp.ToString();
            string smsServiceActive = Utilities.GetAppSettings("sandeshSmsConfig", "isActive").message;
            string normalSMSServiceActive = Utilities.GetAppSettings("SmsConfiguration", "isActive").message;
            string EmailServiceActive = Utilities.GetAppSettings("EmailConfiguration", "isActive").message;
            // Int32 SMSVerificationLimit = Convert.ToInt32(Utilities.GetAppSettings("SmsConfiguration", "SMSVerificationLimit").message) / 60;
            AlertMessageBody smsbody = new();
            SandeshResponse rbs = new();
            ReturnDataTable dtsmstemplate = await dlCommon.GetSMSEmailTemplate((Int32)SmsEmailTemplate.OTPSWS);
            sandeshMessageBody sandeshMessageBody = new();
            string smsTemplate = dtsmstemplate.table.Rows[0]["msgBody"].ToString()!;
            sandeshMessageBody.templateId = Convert.ToInt64(dtsmstemplate.table.Rows[0]["templateId"].ToString()!);
            if (sandeshMessageBody.templateId > 0)
            {
                #region create Parameter To send SMS
                object[] values = new object[] { smsotp.ToString() };
                sandeshMessageBody.message = DlCommon.GetFormattedMsg(smsTemplate, values);

                sandeshMessageBody.contact = mobileno;
                sandeshMessageBody.msgCategory = (Int16)SandeshmsgCategory.Info;
                sandeshMessageBody.msgPriority = (Int16)SandeshmsgPriority.HighVolatile;
                smsbody.smsBody = sandeshMessageBody.message;
                sandeshMessageBody.clientIp = bl.clientIp;
                sandeshMessageBody.isOTP = true;
                rs.secondryId = "0";
                SandeshSms sms = new SandeshSms();
                #endregion
                try
                {
                    #region Send sansesh SMS
                    if (smsServiceActive.ToUpper() == "TRUE")
                        rbs = await sms.callSandeshAPI(sandeshMessageBody);
                    #endregion

                    #region Send Normal SMS
                    if (normalSMSServiceActive.ToUpper() == "TRUE")
                        rbs = await sms.CallSMSAPI(sandeshMessageBody);
                    #endregion

                    #region Email OTP 
                    //New code To Send Email From 31.103
                    if (bl.emailId != string.Empty && EmailServiceActive.ToUpper() == "TRUE")
                    {
                        Email em = new();
                        emailSenderClass emailSenderClass = new();
                        emailSenderClass.emailSubject = "OTP Verification for SWS Chhattisgarh"!;
                        emailSenderClass.emailBody = sandeshMessageBody.message!;
                        emailSenderClass.emailToId = bl.emailId!;
                        emailSenderClass.emailToName = "";
                        await em.SendEmailViaURLAsync(emailSenderClass);
                    }
                    #endregion


                }
                catch (Exception ex)
                { }
            }

            #region Save OTP Details in DB
            smsbody.OTP = smsotp;
            smsbody.smsTemplateId = 0;
            smsbody.isOtpMsg = true;
            smsbody.applicationId = bl.id == null ? 0 : bl.id;
            smsbody.mobileNo = bl.mobileNo;
            smsbody.msgCategory = (Int16)MessageCategory.OTP;
            smsbody.clientIp = bl.clientIp;
            smsbody.smsLanguage = LanguageSupported.English;
            smsbody.emailToReceiver = bl.emailId;
            smsbody.emailSubject = "OTP Verification";
            smsbody.messageServerResponse = rbs.status;
            smsbody.actionId = 1;
            rb = await dlCommon.SendSmsSaveAsync(smsbody);
            if (rb.status)
            {
                rs.status = true;
                rs.msgId = rb.message;
            }
            #endregion


            return rs;
        }

        /// <summary>
        /// Re-Send OTP 
        /// </summary>
        /// <param name="bl"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnString> ReSendOTP(SendOtp bl)
        {
            ReturnClass.ReturnString rs = new();
            ReturnClass.ReturnBool rb = new ReturnClass.ReturnBool();
            bl.mobileNo = Convert.ToInt64(bl.mobileNo.ToString().Substring(bl.mobileNo.ToString().Length - 10));
            string mobileno = bl.mobileNo.ToString();

            Match match = Regex.Match(mobileno,
                              @"^[6-9]\d{9}$", RegexOptions.IgnoreCase);
            if (match.Success == false)
            {
                rs.status = false;
                rs.message = "Invalid Mobile Number";
                return rs;
            }
            DlCommon dlCommon = new();

            dt = await GetLastOTP(bl.msgId, mobileno.ToString());
            if (dt != null)
            {
                if (dt.status == false)
                {
                    rs.status = false;
                    rs.message = dt.message;
                    rs.value = dt.value;
                    return rs;
                }
                if (dt.table.Rows.Count > 0)
                {
                    rs.secondryId = "Your Mobile OTP is " + dt.table.Rows[0]["msgOtp"].ToString();
                    string smsServiceActive = Utilities.GetAppSettings("sandeshSmsConfig", "isActive").message;
                    string normalSMSServiceActive = Utilities.GetAppSettings("SmsConfiguration", "isActive").message;
                    SandeshResponse rbs = new();

                    #region create Parameter To send SMS
                    sandeshMessageBody sandeshMessageBody = new();
                    sandeshMessageBody.contact = mobileno;
                    sandeshMessageBody.msgCategory = (Int16)SandeshmsgCategory.Info;
                    sandeshMessageBody.msgPriority = (Int16)SandeshmsgPriority.HighVolatile;
                    sandeshMessageBody.message = dt.table.Rows[0]["msgBody"].ToString();
                    sandeshMessageBody.isOTP = true;
                    sandeshMessageBody.clientIp = bl.clientIp;
                    ReturnDataTable dtsmstemplate = await dlCommon.GetSMSEmailTemplate((Int32)SmsEmailTemplate.OTPSWS);
                    sandeshMessageBody.templateId = Convert.ToInt64(dtsmstemplate.table.Rows[0]["templateId"].ToString()!);

                    rs.secondryId = "0";
                    rs.value = dt.table.Rows[0]["repeatCounter"].ToString();
                    SandeshSms sms = new SandeshSms();
                    #endregion

                    #region Send sansesh SMS
                    if (smsServiceActive.ToUpper() == "TRUE")
                        rbs = await sms.callSandeshAPI(sandeshMessageBody);
                    #endregion

                    #region Send Normal SMS
                    if (normalSMSServiceActive.ToUpper() == "TRUE")
                        rbs = await sms.CallSMSAPI(sandeshMessageBody);
                    #endregion
                    // if (rbs.status.ToString() == "success")
                    rs.status = true;

                }

            }

            return rs;
        }


        /// <summary>
        /// 
        /// Verify Public Mobile OTP
        /// </summary>
        /// <returns>Verify OTP</returns>
        public async Task<ReturnClass.ReturnBool> VerifyPublicOTP(string msgId, Int32 OTP, string Mobile)
        {
            ReturnClass.ReturnBool rb = new();
            string query = "";
            Int32 repeatCounter = Convert.ToInt32(Utilities.GetAppSettings("SmsConfiguration", "ResendLimit").message);
            MySqlParameter[] pm = new MySqlParameter[]
           {
                new MySqlParameter("msgId", MySqlDbType.String) { Value = msgId},
                new MySqlParameter("mobileNo", MySqlDbType.String) { Value = Mobile},
                new MySqlParameter("msgOtp", MySqlDbType.Int32) { Value = OTP},
                new MySqlParameter("isOtpVerified", MySqlDbType.Int16) { Value = (Int16)OTPStatus.Verified},
                new MySqlParameter("notVerified", MySqlDbType.Int16) { Value = (Int16)OTPStatus.Pending},
           };
            Mobile = Mobile.ToString().Substring(Mobile.ToString().Length - 10);
            string mobileno = Mobile.ToString();

            Match match = Regex.Match(mobileno.ToString(),
                         @"^[6-9]\d{9}$", RegexOptions.IgnoreCase);
            if (match.Success == false)
            {
                rb.status = false;
                rb.message = "Invalid Mobile Number";
                return rb;
            }
            rb = await VerifyOTP(msgId, (Int16)ContactVerifiedType.Mobile, OTP, Mobile);
            if (rb.status)
            {
                query = @"UPDATE smssentdetail
                        SET isOtpVerified=@isOtpVerified,otpVerificationDate=NOW()
                             WHERE msgId = @msgId AND  mobileNo = @mobileNo  AND msgOtp=@msgOtp AND isOtpVerified= @notVerified;";
                rb = await db.ExecuteQueryAsync(query, pm.ToArray(), "VerifyOTP");
            }
            return rb;
        }

        /// <summary>
        /// 
        /// Retrive Last OTP
        /// </summary>
        /// <returns>Verify OTP</returns>
        private async Task<ReturnDataTable> GetLastOTP(string msgId, string Mobile)
        {

            string query = "";
            Int32 SMSResendDurationInSecond = Convert.ToInt32(Utilities.GetAppSettings("SmsConfiguration", "SMSResendDurationInSecond").message);
            Int32 repeatCounter = Convert.ToInt32(Utilities.GetAppSettings("SmsConfiguration", "ResendLimit").message);
            MySqlParameter[] pm = new MySqlParameter[]
           {
                new MySqlParameter("msgId", MySqlDbType.String) { Value = msgId},
                new MySqlParameter("mobileNo", MySqlDbType.String) { Value = Mobile},
                new MySqlParameter("isOtpVerified", MySqlDbType.Int16) { Value = (Int16)OTPStatus.Pending},
                new MySqlParameter("repeatCounter", MySqlDbType.Int16) { Value = repeatCounter},

           };
            Mobile = Mobile.ToString().Substring(Mobile.ToString().Length - 10);
            string mobileno = Mobile.ToString();

            Match match = Regex.Match(mobileno,
                         @"^[6-9]\d{9}$", RegexOptions.IgnoreCase);

            if (match.Success == false)
            {
                dt.status = false;
                dt.message = "Invalid Mobile Number";
                return dt;
            }
            query = @"SELECT e.msgId,e.msgBody,e.msgOtp,
                        TIMESTAMPDIFF(MINUTE, e.sendingDatetime, CURRENT_TIMESTAMP()) AS SMSSentTime,
                                   TIMESTAMPDIFF(SECOND, e.sendingDatetime, CURRENT_TIMESTAMP()) AS SMSSentTimeInSecond,
                                (e.repeatCounter + 1 ) AS repeatCounter,e.isOtpVerified
                             FROM smssentdetail e
                             WHERE e.msgId = @msgId AND  e.mobileNo = @mobileNo  AND e.repeatCounter < @repeatCounter";
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            if (dt.table.Rows.Count > 0)
            {
                if (Convert.ToInt16(dt.table.Rows[0]["isOtpVerified"].ToString()) == (Int16)OTPStatus.Pending)
                {

                    if (Convert.ToInt32(dt.table.Rows[0]["SMSSentTimeInSecond"].ToString()) > SMSResendDurationInSecond)
                    {
                        query = @"UPDATE smssentdetail SET
                                   sendingDatetime= CURRENT_TIMESTAMP(), repeatCounter= repeatCounter + 1                           
                             WHERE msgId = @msgId";
                        rb = await db.ExecuteQueryAsync(query, pm.ToArray(), "ResendOTP");

                        query = @"UPDATE emailsentdetail SET
                                   sendingDatetime= CURRENT_TIMESTAMP(), repeatCounter= repeatCounter + 1                           
                             WHERE msgId = @msgId";
                        rb = await db.ExecuteQueryAsync(query, pm.ToArray(), "ResendOTP");
                    }
                    else
                    {
                        dt.status = false;
                        dt.message = "SMS will be send after " + SMSResendDurationInSecond.ToString() + " Second.";
                        dt.value = dt.table.Rows[0]["isOtpVerified"].ToString();
                        dt.table.Rows.Clear();
                    }
                }
                else if (Convert.ToInt16(dt.table.Rows[0]["isOtpVerified"].ToString()) == (Int16)OTPStatus.Verified)
                {
                    dt.status = false;
                    dt.message = "Invalid OTP details provided.";
                    dt.value = dt.table.Rows[0]["isOtpVerified"].ToString();
                    dt.table.Rows.Clear();

                }
                else if (Convert.ToInt16(dt.table.Rows[0]["isOtpVerified"].ToString()) == (Int16)OTPStatus.Expired)
                {
                    dt.status = false;
                    dt.message = "OTP Expired.";
                    dt.value = dt.table.Rows[0]["isOtpVerified"].ToString();
                    dt.table.Rows.Clear();
                }
            }
            else
            {
                dt.status = false;
                dt.message = "Invalid OTP details provided.";
            }
            return dt;
        }

        /// <summary>
        /// 
        /// Retrive Last OTP by Mobile num only
        /// </summary>
        /// <returns>Verify OTP</returns>
        private async Task<ReturnDataTable> CheckSMSSendDuration(string Mobile, Int16 smsSendType)
        {

            string query = "";
            string durationType = (Int16)SMSSendType.Send == smsSendType ? "SMSVerificationLimit" : "SMSResendDurationInSecond";
            Int32 SMSResendDurationInSecond = Convert.ToInt32(Utilities.GetAppSettings("SmsConfiguration", durationType).message);
            Int32 repeatCounter = Convert.ToInt32(Utilities.GetAppSettings("SmsConfiguration", "ResendLimit").message);
            MySqlParameter[] pm = new MySqlParameter[]
           {
                new MySqlParameter("mobileNo", MySqlDbType.String) { Value = Mobile},
                new MySqlParameter("msgCategory", MySqlDbType.Int16) { Value = (Int16)MessageCategory.OTP},


           };
            Mobile = Mobile.ToString().Substring(Mobile.ToString().Length - 10);
            string mobileno = Mobile.ToString();

            Match match = Regex.Match(mobileno,
                         @"^[6-9]\d{9}$", RegexOptions.IgnoreCase);

            if (match.Success == false)
            {
                dt.status = false;
                dt.message = "Invalid Mobile Number";
                dt.value = "";
                return dt;
            }
            query = @"SELECT e.msgId,e.isOtpVerified,TIMESTAMPDIFF(SECOND, e.sendingDatetime, CURRENT_TIMESTAMP()) AS SMSSentTimeInSecond,
                            e.OTPAttemptLimit,e.msgOtp,e.repeatCounter
                          FROM smssentdetail e
                          WHERE   e.mobileNo = @mobileNo AND e.msgCategory=@msgCategory ORDER BY e.sendingDatetime DESC LIMIT 1 ";
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            if (dt.table.Rows.Count > 0)
            {
                dt.status = false;
                dt.value = dt.table.Rows[0]["isOtpVerified"].ToString();
                if (Convert.ToInt16(dt.table.Rows[0]["isOtpVerified"].ToString()) == (Int16)OTPStatus.Pending
                        && Convert.ToInt32(dt.table.Rows[0]["SMSSentTimeInSecond"].ToString()) < SMSResendDurationInSecond)
                {
                    dt.status = true;
                    durationType = (Int16)SMSSendType.Send == smsSendType ? (((SMSResendDurationInSecond - Convert.ToInt32(dt.table.Rows[0]["SMSSentTimeInSecond"].ToString())) / 60) + 1).ToString() + @" minutes." : SMSResendDurationInSecond.ToString() + @" second.";
                    //dt.message = "SMS will be send after " + durationType;
                    dt.message = "Please try again, After the validity of SMS expires.";
                    dt.type = dt.table.Rows[0]["msgId"].ToString();
                    dt.table.Rows.Clear();

                }
            }
            else
                dt.status = false;


            return dt;
        }

        /// <summary>
        /// Check whether emailId is registered or not with mobile number
        /// </summary>        
        /// <returns>Returns True when Account exists</returns>
        public async Task<ReturnClass.ReturnString> CheckUserAccountExist(SendOtp sendOtp)
        {
            ReturnString rs = new();
            string query = "";
            Match match = Regex.Match(sendOtp.emailId!.ToString(),
                          @"^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+$", RegexOptions.IgnoreCase);
            #region Check User Exists On SWS Chhattisgarh DB
            if (match.Success)
            {

                query = @"SELECT u.userId,sp.swsProjectId  AS id,u.userRole ,sp.deptNameEnglish AS Name
                             FROM userlogin u
                             JOIN swsregisteredprojects sp ON sp.officeEmail=u.emailId
                             WHERE u.emailId = @emailId AND sp.nodalOfficerMobile=@mobileNo ; ";
                MySqlParameter[] pm = new MySqlParameter[]
                {
                new MySqlParameter("emailId", MySqlDbType.VarChar) { Value = sendOtp.emailId},
                new MySqlParameter("mobileNo", MySqlDbType.VarChar) { Value = sendOtp.mobileNo.ToString()},
                };
                dt = await db.ExecuteSelectQueryAsync(query, pm);
                if (dt.table.Rows.Count > 0)
                {
                    rs.status = true;
                    rs.message = "Department Name :" + dt.table.Rows[0]["Name"].ToString();
                    rs.id = Convert.ToInt64(dt.table.Rows[0]["userId"].ToString());
                    rs.value = "projects";
                }
                else
                {
                    query = @"SELECT u.userId,sp.registrationId AS id,u.userRole ,
                                TRIM(CONCAT(sp.applicantFirstName ,' ', IFNULL(sp.applicantMiddleName,'') ,' ', IFNULL(sp.applicantLastName,''))) AS applicantName ,
                                sp.applicantFirstName,sp.applicantMiddleName,sp.applicantLastName
                             FROM userlogin u
                             JOIN userregistration sp ON sp.emailId=u.emailId AND sp.registrationId=u.userId
                              WHERE u.emailId =@emailId  AND sp.mobileNo=@mobileNo;";
                    dt = await db.ExecuteSelectQueryAsync(query, pm);
                    if (dt.table.Rows.Count > 0)
                    {
                        rs.status = true;
                        rs.message = "Applicant Name :" + dt.table.Rows[0]["applicantName"].ToString();
                        rs.id = Convert.ToInt64(dt.table.Rows[0]["userId"].ToString());
                        rs.value = "user";
                    }

                }

            }
            #endregion
            #region Check User Exists On Industry Chhattisgarh DB
            else
            {
                query = @"SELECT  DISTINCT user_name AS userName,ur.applicant_id AS userId ,
                                 " + (Int16)UserRole.OnlineUser + @"  AS userRole
                                   FROM  industry_user_registration.user_login l 
                         INNER JOIN role rl ON rl.Role_Id= l.Role_Id  
                         INNER jOIN industry_user_registration.userregistration ur ON ur.login_id=l.Login_Id 
                         WHERE  l.login_id=@emailId  AND  l.Active =@active AND  ur.verified=@active AND ur.applicant_mobile_no=@mobileNo
                         UNION all
                         SELECT DISTINCT emp.Emp_Name AS userName, l.Login_Id AS userId, 
                         " + (Int16)UserRole.IndustryNodalUser + @"  AS userRole
                         FROM user_login l 
                         INNER JOIN employees emp ON emp.emp_id = l.Login_Id 
                         inner JOIN  emp_office_mapping e ON  e.Emp_Id=emp.emp_id AND  e.active=@approved 
                         inner JOIN  office f ON  f.office_code =e.Office_Code 
                         INNER JOIN role r ON  r.role_id=l.role_id
                         WHERE  (l.User_Name=@emailId OR  l.Login_Id =@emailId) 
                        AND  l.Active =@active  AND emp.Emp_Mobile=@mobileNo ";

                MySqlParameter[] pm = new MySqlParameter[]
                {
                new MySqlParameter("emailId", MySqlDbType.VarChar) { Value = sendOtp.emailId},
                new MySqlParameter("mobileNo", MySqlDbType.VarChar) { Value = sendOtp.mobileNo.ToString()},
                new MySqlParameter("active", MySqlDbType.VarChar) { Value = "Y"},
                new MySqlParameter("approved", MySqlDbType.VarChar) { Value = "A"},
                };
                dt = await db1.ExecuteSelectQueryAsync(query, pm);
                if (dt.table.Rows.Count > 0)
                {
                    rs.status = true;
                    rs.id = Convert.ToInt64(dt.table.Rows[0]["userId"].ToString());
                    if (Convert.ToInt16(dt.table.Rows[0]["userRole"].ToString()) == (Int16)UserRole.IndustryNodalUser)
                    {
                        rs.value = "projects";
                        rs.message = "Department Name :" + dt.table.Rows[0]["userName"].ToString();
                    }
                    else
                    {
                        rs.value = "user";
                        rs.message = "Applicant Name :" + dt.table.Rows[0]["userName"].ToString();
                    }
                }
                else
                {

                    rs.status = false;
                    rs.message = "Invalid User Details, Either UserId or Mobile No. not matched.";
                    rs.value = "";


                }
            }
            #endregion
            if (rs.status)
            {
                sendOtp.msgType = " forgot password in ";
                ReturnString rs1 = await SendOTP(sendOtp);
                if (rs1.status)
                    rs.msgId = rs1.msgId;
                else
                {
                    rs.value = rs1.value;
                    rs.msgId = rs1.msgId;
                    rs.secondryId = rs1.secondryId;
                }

            }
            return rs;
        }

        public async Task<ReturnClass.ReturnBool> ResetForgotPassword(BlUser bl)
        {
            Match match = Regex.Match(bl.emailId.ToString(),
                           @"^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+$", RegexOptions.IgnoreCase);
            if (match.Success)
            {
                #region Reset Forgot Password into SWS Chhattisgarh DB
                if (bl.password.Length > 7)
                {
                    string query = @" UPDATE userregistration 
                              SET password = @password
                              WHERE registrationId = @registrationId AND emailId=@emailId AND mobileNo=@mobileNo ";
                    MySqlParameter[] pm = new MySqlParameter[]
                    {
                new MySqlParameter("registrationId", MySqlDbType.String) { Value = bl.registrationId},
                new MySqlParameter("password", MySqlDbType.String) { Value = bl.password},
                new MySqlParameter("emailId", MySqlDbType.String) { Value = bl.emailId},
                new MySqlParameter("mobileNo", MySqlDbType.String) { Value = bl.mobileNo},
                  new MySqlParameter("clientIp", MySqlDbType.VarChar) { Value = bl.clientIp},
                    };
                    using (TransactionScope ts = new(TransactionScopeAsyncFlowOption.Enabled))
                    {
                        rb = await db.ExecuteQueryAsync(query, pm, "ResetForgotPassword(update) ");
                        if (rb.status)
                        {
                            query = @" INSERT INTO userloginlog 
                               SELECT *
                               FROM userlogin u 
                               WHERE u.userId = @registrationId;";
                            rb = await db.ExecuteQueryAsync(query, pm, "ResetForgotPassword(userloginlog) ");
                            if (rb.status)
                            {
                                query = @" UPDATE userlogin u SET
                                u.password=@password ,u.clientIp=@clientIp                             
                               WHERE u.userId = @registrationId AND u.emailId=@emailId;";

                                rb = await db.ExecuteQueryAsync(query, pm, "UpdateforgotPasswordAsync(updateuserlogin)");
                            }
                            if (rb.status)
                            {
                                ts.Complete();
                                rb.message = "Your Password has been changed!!.";
                            }
                            else
                                rb.message = "Failed to change password. Please try later";
                        }
                    }
                }
                else
                {
                    rb.message = "Password must be at least 8 characters";
                }
                #endregion
            }
            else
            {
                #region Reset Forgot Password into OLD Industry DB
                rb = await ForgotOldIndustriesUsersPassword(bl);
                #endregion
            }
            return rb;
        }

        /// <summary>
        /// Check whether emailId is registered or not
        /// </summary>
        /// <param name="emailId"></param>
        /// <returns>Returns True when Account exists</returns>
        public async Task<ReturnClass.ReturnString> SendOtpForLogin(string? emailId, string userId)
        {
            Match match = Regex.Match(emailId!.ToString(),
                         @"^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+$", RegexOptions.IgnoreCase);
            string query = "";
            ReturnString rs = new();
            #region Check User Exists On SWS Chhattisgarh DB
            if (match.Success)
            {

                query = @"SELECT u.userId ,ur.mobileNo,'USER' AS USERTYPE
                             FROM userlogin u
                             JOIN userregistration ur ON ur.registrationId=u.userId AND u.emailId=ur.emailId
                             WHERE u.emailId = @emailId  AND u.userId=@userId; ";
                MySqlParameter[] pm = new MySqlParameter[]
                {
                new MySqlParameter("emailId", MySqlDbType.VarChar) { Value = emailId},
                new MySqlParameter("userId", MySqlDbType.Int64) { Value = userId},
                };
                dt = await db.ExecuteSelectQueryAsync(query, pm);
                if (dt.table.Rows.Count > 0)
                {
                    rs.status = true;
                    rs.value = dt.table.Rows[0]["userId"].ToString();
                    rs.secondryId = dt.table.Rows[0]["mobileNo"].ToString();
                }
                else
                {
                    query = @"SELECT u.userId ,ur.nodalOfficerMobile AS mobileNo,'NODAL' AS USERTYPE
                             FROM userlogin u
                             JOIN swsregisteredprojects ur ON  u.emailId=ur.officeEmail
                             WHERE u.emailId = @emailId AND u.userId=@userId; ";

                    dt = await db.ExecuteSelectQueryAsync(query, pm);
                    if (dt.table.Rows.Count > 0)
                    {
                        rs.status = true;
                        rs.value = dt.table.Rows[0]["userId"].ToString();
                        rs.secondryId = dt.table.Rows[0]["mobileNo"].ToString();
                    }
                }

            }
            #endregion
            #region Check User Exists On Industry Chhattisgarh DB
            else
            {
                query = @"SELECT  DISTINCT user_name AS userName,ur.applicant_id AS userId ,
                                " + (Int16)UserRole.OnlineUser + @" AS userRole, ur.applicant_mobile_no AS mobileNo
                                  FROM  industry_user_registration.user_login l 
                        INNER JOIN role rl ON rl.Role_Id= l.Role_Id  
                        INNER jOIN industry_user_registration.userregistration ur ON ur.login_id=l.Login_Id 
                        WHERE  l.login_id=@emailId  AND  l.Active =@active AND ur.verified=@active AND ur.login_id=@userId 
                        UNION all
                        SELECT DISTINCT emp.Emp_Name AS userName, l.Login_Id AS userId, 
                          " + (Int16)UserRole.IndustryNodalUser + @"  AS userRole, emp.Emp_Mobile AS mobileNo
                        FROM user_login l 
                        INNER JOIN employees emp ON emp.emp_id = l.Login_Id 
                        inner JOIN  emp_office_mapping e ON  e.Emp_Id=emp.emp_id AND  e.active=@approved
                         inner JOIN  office f ON  f.office_code =e.Office_Code 
                        INNER JOIN role r ON  r.role_id=l.role_id 
                         WHERE  (l.User_Name=@emailId OR  l.Login_Id =@userId) AND  l.Active =@active ";

                MySqlParameter[] pm = new MySqlParameter[]
                {
                new MySqlParameter("emailId", MySqlDbType.VarChar) { Value = emailId},
                new MySqlParameter("userId", MySqlDbType.VarChar) { Value = userId.ToString()},
                new MySqlParameter("active", MySqlDbType.VarChar) { Value = "Y"},
                new MySqlParameter("approved", MySqlDbType.VarChar) { Value = "A"},
                };
                dt = await db1.ExecuteSelectQueryAsync(query, pm);
                if (dt.table.Rows.Count > 0)
                {
                    rs.status = true;
                    rs.value = dt.table.Rows[0]["userId"].ToString();
                    rs.secondryId = dt.table.Rows[0]["mobileNo"].ToString();
                }
            }
            #endregion
            if (rs.status)
            {

                SendOtp sendOtp = new();
                sendOtp.mobileNo = Convert.ToInt64(rs.secondryId);
                sendOtp.msgType = " Login ";
                ReturnString rs1 = await SendOTP(sendOtp);
                if (rs1.status)
                    rs.msgId = rs1.msgId;
                else
                {
                    rs.message = rs1.message;
                    rs.status = rs1.status;
                    rs.value = rs1.value;
                    rs.secondryId = rs1.secondryId;
                }
            }
            return rs;
        }

        /// <summary>
        /// 
        /// Retrive Last OTP
        /// </summary>
        /// <returns>Verify OTP</returns>
        private async Task<ReturnDataTable> OTPExistsForUser(string Mobile)
        {

            string query = "";
            Int32 SMSResendDurationInSecond = Convert.ToInt32(Utilities.GetAppSettings("SmsConfiguration", "SMSResendDurationInSecond").message);
            Int32 repeatCounter = Convert.ToInt32(Utilities.GetAppSettings("SmsConfiguration", "ResendLimit").message);
            MySqlParameter[] pm = new MySqlParameter[]
           {
                new MySqlParameter("msgCategory", MySqlDbType.Int16) { Value = (Int16)MessageCategory.OTP},
                new MySqlParameter("mobileNo", MySqlDbType.String) { Value = Mobile},
                new MySqlParameter("isOtpVerified", MySqlDbType.Int16) { Value = (Int16)IsActive.No},
                new MySqlParameter("repeatCounter", MySqlDbType.Int16) { Value = repeatCounter},

           };
            Mobile = Mobile.ToString().Substring(Mobile.ToString().Length - 10);
            string mobileno = Mobile.ToString();

            Match match = Regex.Match(mobileno,
                         @"^[6-9]\d{9}$", RegexOptions.IgnoreCase);

            if (match.Success == false)
            {
                dt.status = false;
                dt.message = "Invalid Mobile Number";
                return dt;
            }
            query = @"SELECT e.msgId,e.msgBody,e.msgOtp,
                        TIMESTAMPDIFF(MINUTE, e.sendingDatetime, CURRENT_TIMESTAMP()) AS SMSSentTime,
                                   TIMESTAMPDIFF(SECOND, e.sendingDatetime, CURRENT_TIMESTAMP()) AS SMSSentTimeInSecond,
                                (e.repeatCounter + 1 ) AS repeatCounter
                             FROM smssentdetail e
                             WHERE e.msgId = @msgId AND  e.mobileNo = @mobileNo AND e.isOtpVerified=@isOtpVerified AND e.repeatCounter < @repeatCounter";
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            if (dt.table.Rows.Count > 0)
            {
                if (Convert.ToInt32(dt.table.Rows[0]["SMSSentTimeInSecond"].ToString()) > SMSResendDurationInSecond)
                {
                    query = @"UPDATE smssentdetail SET
                                   sendingDatetime= CURRENT_TIMESTAMP(), repeatCounter= repeatCounter + 1                           
                             WHERE msgId = @msgId";
                    rb = await db.ExecuteQueryAsync(query, pm.ToArray(), "ResendOTP");
                }
                else
                {
                    dt = new();
                    dt.message = "SMS will be send after " + SMSResendDurationInSecond.ToString() + " Second.";
                }
            }
            else
            {
                dt = new();
                dt.message = "OTP Expired.";
            }

            return dt;
        }

        /// <summary>
        /// Send EMAIL OTP 
        /// </summary>
        /// <param name="bl"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnString> SendEmailOTP(SendOtp bl)
        {
            ReturnClass.ReturnString rs = new();
            ReturnClass.ReturnBool rb = new ReturnClass.ReturnBool();
            Match match = Regex.Match(bl.emailId.ToString(),
                              @"^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+$", RegexOptions.IgnoreCase);
            if (match.Success == false)
            {
                rs.status = false;
                rs.message = "Given email id is not valid.";
                return rs;
            }
            dt = await CheckEmailSendDuration(bl.emailId.ToString(), (Int16)SMSSendType.Send);
            if (dt.status)
            {
                rs.status = false;
                rs.value = dt.value;
                rs.message = dt.message;
                if (rs.value.ToString().Trim() != ((Int16)OTPStatus.Expired).ToString().Trim())
                {
                    rs.msgId = dt.type;
                    rs.secondryId = bl.emailId.ToString();
                }
                return rs;
            }
            DlCommon dlCommon = new();
            Utilities util = new Utilities();
            Int64 emailotp = util.GenRandomNumber(4);
            //rs.secondryId = "Your email OTP is " + emailotp.ToString();
            string emailServiceActive = Utilities.GetAppSettings("EmailConfiguration", "isActive").message;
            Int32 SMSVerificationLimit = Convert.ToInt32(Utilities.GetAppSettings("SmsConfiguration", "SMSVerificationLimit").message) / 60;
            string buildVersion = Utilities.GetAppSettings("Build", "Version").message;
            AlertMessageBody smsbody = new();
            SandeshResponse rbs = new();

            ReturnDataTable dtsmstemplate = await dlCommon.GetSMSEmailTemplate((Int32)SmsEmailTemplate.OTPSWS);
            if (emailServiceActive.ToUpper() == "TRUE" && buildVersion.ToLower() == "production")
            {
                //Send EMAIL
                Email em = new Email();
                string smsTemplate = dtsmstemplate.table.Rows[0]["emailBody"].ToString()!;
                object[] values = new object[] { emailotp.ToString(), bl.msgType, SMSVerificationLimit.ToString() };
                string emailbody = DlCommon.GetFormattedMsg(smsTemplate, values);
                string emailSubject = "SWS Chhattisgarh - Email ID Verification For " + bl.msgType;
                rs.secondryId = "0";
                await em.SendAsync(bl.emailId, emailSubject, emailbody!, null);

                #region save OTP Detail in DB
                //smsbody.OTP = emailotp;
                smsbody.smsTemplateId = 1;
                smsbody.isOtpMsg = true;
                smsbody.applicationId = bl.id;
                smsbody.mobileNo = bl.mobileNo;
                smsbody.msgCategory = (Int16)MessageCategory.OTP;
                smsbody.clientIp = bl.clientIp;
                smsbody.smsLanguage = LanguageSupported.English;
                smsbody.emailToReceiver = bl.emailId;
                smsbody.emailSubject = "OTP Verification";
                smsbody.messageServerResponse = rbs.status;
                smsbody.emailOTP = emailotp;
                smsbody.emailBody = emailbody;
                smsbody.actionId = 1;

                if (bl.msgId == null || bl.msgId == String.Empty)
                    smsbody.msgId = await dlCommon.GenerateEmailMsgId();

                //smsbody.msgId = Guid.NewGuid().ToString();
                else
                    smsbody.msgId = bl.msgId;
                rb = await dlCommon.SendEmailSaveAsync(smsbody);
                if (rb.status)
                {
                    rs.msgId = rb.message;
                    rs.status = true;
                }
                #endregion

            }
            else
            {
                rs.msgId = "0";
                rs.status = false;
                rs.message = " Sorry, can't send E-mail at development stage..";
            }


            return rs;
        }
        /// <summary>
        /// 
        /// Retrive Last OTP by Mobile num only
        /// </summary>
        /// <returns>Verify OTP</returns>
        private async Task<ReturnDataTable> CheckEmailSendDuration(string emailId, Int16 smsSendType)
        {

            string query = "";
            string duratiobType = (Int16)SMSSendType.Send == smsSendType ? "SMSVerificationLimit" : "SMSResendDurationInSecond";

            Int32 SMSResendDurationInSecond = Convert.ToInt32(Utilities.GetAppSettings("SmsConfiguration", duratiobType).message);
            Int32 repeatCounter = Convert.ToInt32(Utilities.GetAppSettings("SmsConfiguration", "ResendLimit").message);
            MySqlParameter[] pm = new MySqlParameter[]
           {
                new MySqlParameter("emailId", MySqlDbType.String) { Value = emailId},
                new MySqlParameter("msgCategory", MySqlDbType.Int16) { Value = (Int16)MessageCategory.OTP},


           };

            query = @"SELECT e.msgId,e.isOtpVerified,TIMESTAMPDIFF(SECOND, e.sendingDatetime, CURRENT_TIMESTAMP()) AS SMSSentTimeInSecond,
                            e.OTPAttemptLimit,e.msgOtp,e.repeatCounter
                          FROM emailsentdetail e
                          WHERE   e.emailId = @emailId AND e.msgCategory=@msgCategory ORDER BY e.sendingDatetime DESC LIMIT 1 ";
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            if (dt.table.Rows.Count > 0)
            {
                dt.status = false;
                dt.value = dt.table.Rows[0]["isOtpVerified"].ToString();
                if (Convert.ToInt16(dt.table.Rows[0]["isOtpVerified"].ToString()) == (Int16)OTPStatus.Pending
                        && Convert.ToInt32(dt.table.Rows[0]["SMSSentTimeInSecond"].ToString()) < SMSResendDurationInSecond)
                {
                    dt.status = true;
                    duratiobType = (Int16)SMSSendType.Send == smsSendType ? (((SMSResendDurationInSecond - Convert.ToInt32(dt.table.Rows[0]["SMSSentTimeInSecond"].ToString())) / 60) + 1).ToString() + @" minutes." : SMSResendDurationInSecond.ToString() + @" second.";
                    dt.message = "Email will be send after " + duratiobType;
                    dt.type = dt.table.Rows[0]["msgId"].ToString();
                    dt.table.Rows.Clear();

                }
            }
            else
                dt.status = false;


            return dt;
        }

        /// <summary>
        /// Re-Send Email OTP 
        /// </summary>
        /// <param name="bl"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnString> ReSendEmailOTP(SendOtp bl)
        {
            ReturnClass.ReturnString rs = new();
            ReturnClass.ReturnBool rb = new ReturnClass.ReturnBool();
            string emailServiceActive = Utilities.GetAppSettings("EmailConfiguration", "isActive").message;
            string buildVersion = Utilities.GetAppSettings("Build", "Version").message;
            if (emailServiceActive.ToUpper() == "TRUE" && buildVersion.ToLower() == "production")
            {
                Match match = Regex.Match(bl.emailId.ToString(),
                                @"^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+$", RegexOptions.IgnoreCase);
                if (match.Success == false)
                {
                    rs.status = false;
                    rs.message = "Given email id is invalid.";
                    return rs;
                }
                DlCommon dlCommon = new();

                dt = await GetLastEmailOTP(bl.msgId, bl.emailId.ToString());
                if (dt != null)
                {
                    if (dt.status == false)
                    {
                        rs.status = false;
                        rs.message = dt.message;
                        rs.value = dt.value;
                        return rs;
                    }
                    if (dt.table.Rows.Count > 0)
                    {
                        SendEmail sendEmail = new();
                        sendEmail.emailId = bl.emailId;
                        sendEmail.message = dt.table.Rows[0]["msgBody"].ToString();
                        sendEmail.subject = "SWS Chhattisgarh- Resend OTP For Email Verification";
                        Email em = new();
                        await em.SendAsync(bl.emailId, sendEmail.subject!, sendEmail.message!, null);
                        rs.message = "Mail Sent.";
                        rs.status = true;
                        rs.value = dt.table.Rows[0]["repeatCounter"].ToString();
                    }
                    else
                    {
                        rs.status = false;
                        rs.message = "Invalid details Provided.";

                    }

                }
                else
                {
                    rs.status = false;
                    rs.message = "Invalid details Provided.";

                }
            }
            return rs;
        }
        /// <summary>
        /// 
        /// Retrive Last Email OTP
        /// </summary>
        /// <returns>Verify OTP</returns>
        private async Task<ReturnDataTable> GetLastEmailOTP(string msgId, string emailId)
        {

            string query = "";
            Int32 SMSResendDurationInSecond = Convert.ToInt32(Utilities.GetAppSettings("SmsConfiguration", "SMSResendDurationInSecond").message);
            Int32 repeatCounter = Convert.ToInt32(Utilities.GetAppSettings("SmsConfiguration", "ResendLimit").message);
            MySqlParameter[] pm = new MySqlParameter[]
           {
                new MySqlParameter("msgId", MySqlDbType.String) { Value = msgId},
                new MySqlParameter("emailId", MySqlDbType.String) { Value = emailId},
                new MySqlParameter("isOtpVerified", MySqlDbType.Int16) { Value = (Int16)OTPStatus.Pending},
                new MySqlParameter("repeatCounter", MySqlDbType.Int16) { Value = repeatCounter},

           };

            query = @"SELECT e.msgId,e.msgBody,e.msgOtp,
                        TIMESTAMPDIFF(MINUTE, e.sendingDatetime, CURRENT_TIMESTAMP()) AS SMSSentTime,
                                   TIMESTAMPDIFF(SECOND, e.sendingDatetime, CURRENT_TIMESTAMP()) AS SMSSentTimeInSecond,
                                (e.repeatCounter + 1 ) AS repeatCounter,e.isOtpVerified
                             FROM emailsentdetail e
                             WHERE e.msgId = @msgId AND  e.emailId = @emailId  AND e.repeatCounter < @repeatCounter";
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            if (dt.table.Rows.Count > 0)
            {
                if (Convert.ToInt16(dt.table.Rows[0]["isOtpVerified"].ToString()) == (Int16)OTPStatus.Pending)
                {

                    if (Convert.ToInt32(dt.table.Rows[0]["SMSSentTimeInSecond"].ToString()) > SMSResendDurationInSecond)
                    {

                        query = @"UPDATE emailsentdetail SET
                                   sendingDatetime= CURRENT_TIMESTAMP(), repeatCounter= repeatCounter + 1                           
                             WHERE msgId = @msgId";
                        rb = await db.ExecuteQueryAsync(query, pm.ToArray(), "ResendOTP");
                    }
                    else
                    {
                        dt.status = false;
                        dt.message = "Email will be send after " + SMSResendDurationInSecond.ToString() + " Second.";
                        dt.value = dt.table.Rows[0]["isOtpVerified"].ToString();
                        dt.table.Rows.Clear();
                    }
                }
                else if (Convert.ToInt16(dt.table.Rows[0]["isOtpVerified"].ToString()) == (Int16)OTPStatus.Verified)
                {
                    dt.status = false;
                    dt.message = "Invalid OTP details provided.";
                    dt.value = dt.table.Rows[0]["isOtpVerified"].ToString();
                    dt.table.Rows.Clear();

                }
                else if (Convert.ToInt16(dt.table.Rows[0]["isOtpVerified"].ToString()) == (Int16)OTPStatus.Expired)
                {
                    dt.status = false;
                    dt.message = "OTP Expired.";
                    dt.value = dt.table.Rows[0]["isOtpVerified"].ToString();
                    dt.table.Rows.Clear();
                }
            }
            else
            {
                dt.status = false;
                dt.message = "Invalid OTP details provided.";
            }
            return dt;
        }

        public async Task<ReturnClass.ReturnBool> InsertSMSResponse(SMSResponse bl)
        {
            string query = @" INSERT INTO smsresponse (reqId,status,mobileNo,notice,code,message,deliveryDatetime,clientIp) 
                                    VALUES (@reqId,@status,@mobileNo,@notice,@code,@message,NOW(),@clientIp) ";
            MySqlParameter[] pm = new MySqlParameter[]
            {
                new MySqlParameter("reqId", MySqlDbType.VarChar) { Value = bl.reqId},
                new MySqlParameter("status", MySqlDbType.VarChar) { Value = bl.status},
                new MySqlParameter("mobileNo", MySqlDbType.Int64) { Value = bl.mobileNo},
                new MySqlParameter("notice", MySqlDbType.VarChar) { Value = bl.notice},
                new MySqlParameter("code", MySqlDbType.VarChar) { Value = bl.code},
                new MySqlParameter("message", MySqlDbType.VarChar) { Value = bl.message},
                new MySqlParameter("clientIp", MySqlDbType.VarChar) { Value = bl.clientIp},
            };
            return await db.ExecuteQueryAsync(query, pm, "InsertSMSResponse(INSERT) ");
        }

        /// <summary>
        /// 
        /// Verify Email OTP
        /// </summary>
        /// <returns>Verify OTP</returns>
        public async Task<ReturnClass.ReturnBool> VerifyPublicEmailOTP(string msgId, Int32 OTP, string emailId)
        {
            ReturnClass.ReturnBool rb = new();
            string query = "";
            Int32 repeatCounter = Convert.ToInt32(Utilities.GetAppSettings("SmsConfiguration", "ResendLimit").message);
            MySqlParameter[] pm = new MySqlParameter[]
           {
                new MySqlParameter("msgId", MySqlDbType.String) { Value = msgId},
                new MySqlParameter("emailId", MySqlDbType.String) { Value = emailId},
                new MySqlParameter("msgOtp", MySqlDbType.Int32) { Value = OTP},
                new MySqlParameter("isOtpVerified", MySqlDbType.Int16) { Value = (Int16)OTPStatus.Verified},
                new MySqlParameter("notVerified", MySqlDbType.Int16) { Value = (Int16)OTPStatus.Pending},
           };
            Match match = Regex.Match(emailId.ToString(),
                             @"^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+$", RegexOptions.IgnoreCase);
            if (match.Success == false)
            {
                rb.status = false;
                rb.message = "Given email id is not valid.";
                return rb;
            }
            rb = await VerifyOTP(msgId, (Int16)ContactVerifiedType.Email, OTP, emailId);
            if (rb.status)
            {
                query = @"UPDATE emailsentdetail
                        SET isOtpVerified=@isOtpVerified,otpVerificationDate=NOW()
                             WHERE msgId = @msgId AND  emailId = @emailId  AND msgOtp=@msgOtp AND isOtpVerified= @notVerified;";
                rb = await db.ExecuteQueryAsync(query, pm.ToArray(), "VerifyPublicEmailOTP");
            }
            return rb;
        }

        public async Task<ReturnClass.ReturnBool> InsertEmailResponse(EmailResponse bl)
        {
            ReturnBool returnBool = new();
            try
            {
                string query = @" INSERT INTO emailresponse (reqId,status,emailId,notice,code,message,deliveryDatetime,clientIp) 
                                    VALUES (@reqId,@status,@emailId,@notice,@code,@message,NOW(),@clientIp) ";
                MySqlParameter[] pm = new MySqlParameter[]
                {
                new MySqlParameter("reqId", MySqlDbType.VarChar) { Value = bl.reqId},
                new MySqlParameter("status", MySqlDbType.VarChar) { Value = bl.status},
                new MySqlParameter("emailId", MySqlDbType.VarChar) { Value = bl.emailId},
                new MySqlParameter("notice", MySqlDbType.VarChar) { Value = bl.notice},
                new MySqlParameter("code", MySqlDbType.VarChar) { Value = bl.code},
                new MySqlParameter("message", MySqlDbType.VarChar) { Value = bl.message},
                new MySqlParameter("clientIp", MySqlDbType.VarChar) { Value = bl.clientIp},
                };
                returnBool = await db.ExecuteQueryAsync(query, pm, "InsertSMSResponse(INSERT) ");
            }
            catch (Exception ex)
            { WriteLog.Error("EmailResponse(error)", ex); returnBool.message = "Failed to send Email"; }
            return returnBool;
        }


        /// <summary>
        /// Send OTP to Admin only
        /// </summary>
        /// <param name="userid"></param>
        /// <param name="clientIp"></param>
        /// <returns></returns>
        public async Task<ReturnString> SendAdminOTP(Int64 userid, string clientIp)
        {
            ReturnString rs = new();
            MySqlParameter[] pm = new MySqlParameter[]
           {
                new MySqlParameter("userid", MySqlDbType.Int64) { Value = userid},
                 new MySqlParameter("userRole", MySqlDbType.Int16) { Value = (Int16)UserRole.Administrator}
           };

            string query = @"SELECT e.mobileNo FROM employeemaster e
                                JOIN userlogin u ON u.userId=e.userId AND u.userRole=@userRole
                                 WHERE e.userId=@userid";
            ReturnDataTable dt1 = await db.ExecuteSelectQueryAsync(query, pm);
            SandeshSms sms1 = new();
            if (dt1.table.Rows.Count > 0)
            {
                string msgId = "", msg = "";
                for (int i = 0; i < dt1.table.Rows.Count; i++)
                {
                    if (i == 0)
                    {
                        SendOtp sendOTP = new();
                        sendOTP.mobileNo = Convert.ToInt64(dt1.table.Rows[i]["mobileNo"].ToString());
                        rs = await SendOTPtoAdmin(sendOTP);
                        if (rs.status)
                        {
                            msgId = rs.msgId;
                            msg = rs.secondryId;
                        }
                    }
                    else
                    {
                        if (msgId != String.Empty)
                        {
                            sandeshMessageBody sandeshMessageBody = new();
                            sandeshMessageBody.contact = dt1.table.Rows[i]["mobileNo"].ToString();
                            sandeshMessageBody.msgCategory = (Int16)SandeshmsgCategory.Info;
                            sandeshMessageBody.msgPriority = (Int16)SandeshmsgPriority.HighVolatile;
                            sandeshMessageBody.message = msg;
                            sandeshMessageBody.clientIp = clientIp;
                            sandeshMessageBody.isOTP = true;

                            #region Send sansesh SMS
                            string smsServiceActive = Utilities.GetAppSettings("sandeshSmsConfig", "isActive").message;
                            if (smsServiceActive.ToUpper() == "TRUE")
                                await sms1.callSandeshAPI(sandeshMessageBody);
                            #endregion

                            #region Send Normal SMS
                            string normalSMSServiceActive = Utilities.GetAppSettings("SmsConfiguration", "isActive").message;
                            if (normalSMSServiceActive.ToUpper() == "TRUE")
                                await sms1.CallSMSAPI(sandeshMessageBody);
                            #endregion
                        }
                    }

                }
                rs.secondryId = "0";
            }
            else
            {
                rs.status = false;
                rs.message = "Invalid OTP details provided.";
            }
            return rs;
        }
        /// <summary>
        /// Send OTP to Admin only
        /// </summary>
        /// <param name="bl"></param>
        /// <returns></returns>
        private async Task<ReturnClass.ReturnString> SendOTPtoAdmin(SendOtp bl)
        {
            ReturnClass.ReturnString rs = new();
            ReturnClass.ReturnBool rb = new ReturnClass.ReturnBool();

            bl.mobileNo = Convert.ToInt64(bl.mobileNo.ToString().Substring(bl.mobileNo.ToString().Length - 10));
            string mobileno = bl.mobileNo.ToString();

            Match match = Regex.Match(mobileno,
                              @"^[6-9]\d{9}$", RegexOptions.IgnoreCase);
            if (match.Success == false)
            {
                rs.status = false;
                rs.message = "Invalid Mobile Number";
                return rs;
            }
            dt = await CheckSMSSendDuration(mobileno, (Int16)SMSSendType.Send);
            if (dt.status)
            {
                rs.status = false;
                rs.value = dt.value;
                rs.message = dt.message;
                if (rs.value.ToString().Trim() != ((Int16)OTPStatus.Expired).ToString().Trim())
                {
                    rs.msgId = dt.type;
                    rs.secondryId = mobileno.ToString();
                }
                return rs;
            }
            string smsServiceActive = Utilities.GetAppSettings("SmsConfiguration", "isActive").message;
            Int32 SMSVerificationLimit = Convert.ToInt32(Utilities.GetAppSettings("SmsConfiguration", "SMSVerificationLimit").message) / 60;
            DlCommon dlCommon = new();
            Utilities util = new Utilities();

            Int64 smsotp = util.GenRandomNumber(4);

            AlertMessageBody smsbody = new();
            SandeshResponse rbs = new();
            ReturnDataTable dtsmstemplate = await dlCommon.GetSMSEmailTemplate((Int32)SmsEmailTemplate.OTPSWS);
            sandeshMessageBody sandeshMessageBody = new();




            string smsTemplate = dtsmstemplate.table.Rows[0]["msgBody"].ToString()!;
            sandeshMessageBody.templateId = Convert.ToInt64(dtsmstemplate.table.Rows[0]["templateId"].ToString()!);
            if (sandeshMessageBody.templateId > 0)
            {
                #region create Parameter To send SMS
                object[] values = new object[] { smsotp.ToString() };
                sandeshMessageBody.message = DlCommon.GetFormattedMsg(smsTemplate, values);

                sandeshMessageBody.contact = mobileno;
                sandeshMessageBody.msgCategory = (Int16)SandeshmsgCategory.Info;
                sandeshMessageBody.msgPriority = (Int16)SandeshmsgPriority.HighVolatile;
                smsbody.smsBody = sandeshMessageBody.message;
                sandeshMessageBody.clientIp = bl.clientIp;
                sandeshMessageBody.isOTP = true;
                SandeshSms sms = new SandeshSms();
                #endregion

                #region Send sansesh SMS
                if (smsServiceActive.ToUpper() == "TRUE")
                    rbs = await sms.callSandeshAPI(sandeshMessageBody);
                #endregion

                #region Send Normal SMS
                string normalSMSServiceActive = Utilities.GetAppSettings("SmsConfiguration", "isActive").message;
                if (normalSMSServiceActive.ToUpper() == "TRUE")
                    rbs = await sms.CallSMSAPI(sandeshMessageBody);
                #endregion
            }

            #region SAVE SMS Details
            smsbody.OTP = smsotp;
            smsbody.smsTemplateId = 0;
            smsbody.isOtpMsg = true;
            smsbody.applicationId = bl.id == null ? 0 : bl.id;
            smsbody.mobileNo = bl.mobileNo;
            smsbody.msgCategory = (Int16)MessageCategory.OTP;
            smsbody.clientIp = bl.clientIp;
            smsbody.smsLanguage = LanguageSupported.English;
            smsbody.emailToReceiver = bl.emailId;
            smsbody.emailSubject = "OTP Verification";
            smsbody.messageServerResponse = rbs.status;
            smsbody.actionId = 1;
            rb = await dlCommon.SendSmsSaveAsync(smsbody);
            if (rb.status)
            {
                rs.status = true;
                rs.msgId = rb.message;
                rs.secondryId = smsbody.smsBody;
            }
            #endregion


            return rs;
        }

        /// <summary>
        ///Re-Send OTP to Admin only
        /// </summary>
        /// <param name="userid"></param>
        /// <param name="clientIp"></param>
        /// <param name="msgId"></param>
        /// <returns></returns>
        public async Task<ReturnString> ReSendAdminOTP(Int64 userid, string clientIp, string msgId)
        {
            ReturnString rs = new();
            MySqlParameter[] pm = new MySqlParameter[]
           {
                new MySqlParameter("userid", MySqlDbType.Int64) { Value = userid},
                 new MySqlParameter("userRole", MySqlDbType.Int16) { Value = (Int16)UserRole.Administrator}
           };

            string query = @"SELECT e.mobileNo FROM employeemaster e
                                JOIN userlogin u ON u.userId=e.userId AND u.userRole=@userRole
                                 WHERE e.userId=@userid";
            ReturnDataTable dt1 = await db.ExecuteSelectQueryAsync(query, pm);
            if (dt1.table.Rows.Count > 0)
            {
                string msg = "";
                for (int i = 0; i < dt1.table.Rows.Count; i++)
                {
                    if (i == 0)
                    {
                        SendOtp sendOTP = new();
                        sendOTP.mobileNo = Convert.ToInt64(dt1.table.Rows[i]["mobileNo"].ToString());
                        sendOTP.msgId = msgId;
                        rs = await ReSendOTPtoAdmin(sendOTP);
                        if (rs.status)
                        {
                            msgId = rs.msgId;
                            msg = rs.secondryId;
                        }
                    }
                    else
                    {
                        if (msgId != String.Empty)
                        {
                            #region create Parameter To send SMS
                            sandeshMessageBody sandeshMessageBody = new();
                            sandeshMessageBody.contact = dt1.table.Rows[i]["mobileNo"].ToString();
                            sandeshMessageBody.msgCategory = (Int16)SandeshmsgCategory.Info;
                            sandeshMessageBody.msgPriority = (Int16)SandeshmsgPriority.HighVolatile;
                            sandeshMessageBody.message = msg;
                            sandeshMessageBody.clientIp = clientIp;
                            sandeshMessageBody.isOTP = true;
                            SandeshSms sms = new();
                            #endregion

                            #region Send sansesh SMS
                            string smsServiceActive = Utilities.GetAppSettings("sandeshSmsConfig", "isActive").message;
                            if (smsServiceActive.ToUpper() == "TRUE")
                                await sms.callSandeshAPI(sandeshMessageBody);
                            #endregion

                            #region Send Normal SMS
                            string normalSMSServiceActive = Utilities.GetAppSettings("SmsConfiguration", "isActive").message;
                            if (normalSMSServiceActive.ToUpper() == "TRUE")
                                await sms.CallSMSAPI(sandeshMessageBody);
                            #endregion
                        }
                    }
                    rs.secondryId = "0";
                }
            }
            else
            {
                rs.status = false;
                rs.message = "Invalid OTP details provided.";
            }
            return rs;
        }
        /// <summary>
        /// Re-Send OTP  to admin only
        /// </summary>
        /// <param name="bl"></param>
        /// <returns></returns>
        private async Task<ReturnClass.ReturnString> ReSendOTPtoAdmin(SendOtp bl)
        {
            ReturnClass.ReturnString rs = new();
            ReturnClass.ReturnBool rb = new ReturnClass.ReturnBool();
            bl.mobileNo = Convert.ToInt64(bl.mobileNo.ToString().Substring(bl.mobileNo.ToString().Length - 10));
            string mobileno = bl.mobileNo.ToString();

            Match match = Regex.Match(mobileno,
                              @"^[6-9]\d{9}$", RegexOptions.IgnoreCase);
            if (match.Success == false)
            {
                rs.status = false;
                rs.message = "Invalid Mobile Number";
                return rs;
            }
            DlCommon dlCommon = new();

            dt = await GetLastOTP(bl.msgId, mobileno.ToString());
            if (dt != null)
            {
                if (dt.status == false)
                {
                    rs.status = false;
                    rs.message = dt.message;
                    rs.value = dt.value;
                    return rs;
                }
                if (dt.table.Rows.Count > 0)
                {
                    string smsServiceActive = Utilities.GetAppSettings("sandeshSmsConfig", "isActive").message;
                    SandeshResponse rbs = new();

                    #region create Parameter To send SMS
                    sandeshMessageBody sandeshMessageBody = new();
                    sandeshMessageBody.contact = mobileno;
                    sandeshMessageBody.msgCategory = (Int16)SandeshmsgCategory.Info;
                    sandeshMessageBody.msgPriority = (Int16)SandeshmsgPriority.HighVolatile;
                    sandeshMessageBody.message = dt.table.Rows[0]["msgBody"].ToString();
                    sandeshMessageBody.isOTP = true;
                    sandeshMessageBody.clientIp = bl.clientIp;
                    ReturnDataTable dtsmstemplate = await dlCommon.GetSMSEmailTemplate((Int32)SmsEmailTemplate.OTPSWS);
                    sandeshMessageBody.templateId = Convert.ToInt64(dtsmstemplate.table.Rows[0]["templateId"].ToString()!);
                    rs.value = dt.table.Rows[0]["repeatCounter"].ToString();
                    SandeshSms sms = new SandeshSms();
                    #endregion

                    #region Send sansesh SMS
                    if (smsServiceActive.ToUpper() == "TRUE")
                    {
                        rbs = await sms.callSandeshAPI(sandeshMessageBody);
                    }
                    rs.secondryId = dt.table.Rows[0]["msgBody"].ToString();
                    #endregion

                    #region Send Normal SMS
                    string normalSMSServiceActive = Utilities.GetAppSettings("SmsConfiguration", "isActive").message;
                    if (normalSMSServiceActive.ToUpper() == "TRUE")
                        rbs = await sms.CallSMSAPI(sandeshMessageBody);
                    #endregion                  
                    if ((normalSMSServiceActive.ToUpper() == "FALSE" && smsServiceActive.ToUpper() == "FALSE") || rbs.status.ToString() == "success")
                        rs.status = true;
                }
            }
            return rs;
        }


        /// <summary>
        ///Re-Send OTP to Admin only
        /// </summary>
        /// <param name="userid"></param>
        /// <param name="clientIp"></param>
        /// <param name="sendOTP"></param>
        /// <returns></returns>
        public async Task<ReturnBool> VerifyAdminOTP(SendOtp sendOTP, Int64 userid)
        {
            ReturnBool rb = new();
            MySqlParameter[] pm = new MySqlParameter[]
           {
             new MySqlParameter("userid", MySqlDbType.Int64) { Value = userid},
             new MySqlParameter("userRole", MySqlDbType.Int16) { Value = (Int16)UserRole.Administrator}
           };
            string query = @"SELECT e.mobileNo FROM employeemaster e
                                JOIN userlogin u ON u.userId=e.userId AND u.userRole=@userRole
                                 WHERE e.userId=@userid";
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            if (dt.table.Rows.Count > 0)
                rb = await VerificationAdminOTP(sendOTP.msgId!, (int)sendOTP.OTP!, dt.table.Rows[0]["mobileNo"].ToString()!);
            else
            {
                rb.status = false;
                rb.message = "Invalid OTP details provided.";
            }
            return rb;
        }
        /// <summary>
        /// 
        /// Verify Admin Mobile OTP
        /// </summary>
        /// <returns>Verify OTP</returns>
        private async Task<ReturnClass.ReturnBool> VerificationAdminOTP(string msgId, Int32 OTP, string Mobile)
        {
            ReturnClass.ReturnBool rb = new();
            string query = "";
            Int32 repeatCounter = Convert.ToInt32(Utilities.GetAppSettings("SmsConfiguration", "ResendLimit").message);
            MySqlParameter[] pm = new MySqlParameter[]
           {
                new MySqlParameter("msgId", MySqlDbType.String) { Value = msgId},
                new MySqlParameter("mobileNo", MySqlDbType.String) { Value = Mobile},
                new MySqlParameter("msgOtp", MySqlDbType.Int32) { Value = OTP},
                new MySqlParameter("isOtpVerified", MySqlDbType.Int16) { Value = (Int16)OTPStatus.Verified},
                new MySqlParameter("notVerified", MySqlDbType.Int16) { Value = (Int16)OTPStatus.Pending},
           };
            Mobile = Mobile.ToString().Substring(Mobile.ToString().Length - 10);
            string mobileno = Mobile.ToString();
            Match match = Regex.Match(mobileno.ToString(),
                         @"^[6-9]\d{9}$", RegexOptions.IgnoreCase);
            if (match.Success == false)
            {
                rb.status = false;
                rb.message = "Invalid Mobile Number";
                return rb;
            }
            rb = await VerifyOTP(msgId, (Int16)ContactVerifiedType.Mobile, OTP, Mobile);
            if (rb.status)
            {
                query = @"UPDATE smssentdetail
                        SET isOtpVerified=@isOtpVerified,otpVerificationDate=NOW()
                             WHERE msgId = @msgId AND mobileNo = @mobileNo AND msgOtp=@msgOtp AND isOtpVerified= @notVerified;";
                rb = await db.ExecuteQueryAsync(query, pm.ToArray(), "VerifyOTP");
            }
            return rb;
        }


        public async Task<ReturnClass.ReturnBool> ResetMD5PasswordtoSha256(UserResetPassword bl)
        {
            string query = "", query2 = "";
            if (bl.password.Length > 7)
            {
                MySqlParameter[] pm = new MySqlParameter[]
                {
                new MySqlParameter("loginId", MySqlDbType.String) { Value = bl.loginId},
                new MySqlParameter("password", MySqlDbType.String) { Value = bl.password},
                new MySqlParameter("yes", MySqlDbType.Int16) { Value =(Int16)YesNo.Yes},
                new MySqlParameter("no", MySqlDbType.Int16) { Value =(Int16)YesNo.No},
               new MySqlParameter("active", MySqlDbType.VarChar) { Value = "Y"},
                  new MySqlParameter("clientIp", MySqlDbType.VarChar) { Value = bl.clientIp},                };

                query = @"SELECT  DISTINCT  l.Password,l.isUserMigrate ,'04' as roleId
                            FROM  industry_user_registration.user_login l                            
                            INNER jOIN industry_user_registration.userregistration ur ON ur.login_id=l.Login_Id
                            WHERE  l.login_id=@loginId  AND  l.Active =@active AND  ur.verified=@active
                            UNION ALL                            
                            SELECT  l.Password,l.isUserMigrate,l.Role_Id as roleId
                            FROM user_login l                            
                            WHERE  (l.User_Name=@loginId OR  l.Login_Id =@loginId) AND  l.Active =@active ; ";



                dt = await db1.ExecuteSelectQueryAsync(query, pm.ToArray());
                if (dt.table.Rows.Count > 0)
                {
                    if (dt.table.Rows[0]["isUserMigrate"].ToString() == "1")
                    {
                        rb.status = false;
                        rb.message = "Password has already been changed";
                        return rb;
                    }
                    string passwordTbl = Utilities.CreateHash(bl.requestToken + dt.table.Rows[0]["password"].ToString(), HashingAlgorithmSupported.Md5);
                    if (bl.oldPassword == passwordTbl)
                    {
                        if (dt.table.Rows[0]["roleId"].ToString() == "04")
                        {
                            query2 = @"INSERT INTO industry_user_registration.user_login_log
                                      SELECT * FROM industry_user_registration.user_login l
                                        WHERE  l.login_id=@loginId  AND  l.Active =@active 
                                    AND l.isUserMigrate= @no";

                            query = @"UPDATE  industry_user_registration.user_login 
                                SET password = @password ,isUserMigrate= @yes                         
                            WHERE  login_id=@loginId  AND  Active =@active AND isUserMigrate= @no";
                        }
                        else
                        {
                            query2 = @"INSERT INTO user_login_log
                                      SELECT * FROM user_login l
                                        WHERE  (l.User_Name=@loginId OR  l.Login_Id =@loginId) 
                                        AND  l.Active =@active AND l.isUserMigrate= @no";

                            query = @"UPDATE user_login  
                                SET password = @password ,isUserMigrate= @yes   
                            WHERE  (User_Name=@loginId OR  Login_Id =@loginId) AND  Active =@active AND isUserMigrate= @no ; ";
                        }
                        using (TransactionScope ts = new(TransactionScopeAsyncFlowOption.Enabled))
                        {
                            rb = await db1.ExecuteQueryAsync(query2, pm, "ResetMD5PasswordtoSha256(insertuserloginlog) ");
                            if (rb.status)
                            {
                                rb = await db1.ExecuteQueryAsync(query, pm, "ResetMD5PasswordtoSha256(Updateuserloginlog) ");
                                if (rb.status)
                                {
                                    ts.Complete();
                                    rb.message = "Your Password has been changed!!";
                                }
                                else
                                    rb.message = "Failed to change password. Please try later";
                            }
                        }
                    }
                    else
                    {
                        rb.message = "Invalid old Password.";
                    }
                }
                else
                {
                    rb.message = "Invalid Login-Id.";
                }

            }
            return rb;
        }

        public async Task<string> GetAuthenticationUniqueId(string? authToken)
        {
            string uniqueId = "";
            string query = @" SELECT lt.uniqueId
                              FROM logintrail lt
                              WHERE lt.authToken = @authToken AND lt.isSessionRevoked=@isSessionRevoked ; ";
            MySqlParameter[] pm = new MySqlParameter[]
            {
                new MySqlParameter("authToken", MySqlDbType.VarString) { Value = authToken},
                new MySqlParameter("isSessionRevoked", MySqlDbType.VarString) { Value = (int)YesNo.No},
            };
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            if (dt.table.Rows.Count > 0)
                uniqueId = dt.table.Rows[0]["uniqueId"].ToString();

            return uniqueId;
        }


        private static ReturnClass.ReturnBool DecryptAuthToken(string token)
        {
            ReturnClass.ReturnBool rbKey = Utilities.GetAppSettings("IndustryKey", "RootKey");
            string decryptionKey = rbKey.status ? rbKey.message : "";

            rbKey = rbKey.status ? Utilities.GetAppSettings("IndustryKey", "RootVector") : new();
            string decryptionVector = rbKey.status ? rbKey.message : "";

            ReturnClass.ReturnBool rbReturn = new() { message = "Invalid token" };
            if (rbKey.status)
            {
                rbReturn.message = Utilities.Aes256Decrypt(token, decryptionKey, decryptionVector);
                rbReturn.status = true;
            }
            return rbReturn;
        }
        public async Task<ReturnBool> DecryptSWSDepartmentlogin(string swsAuthToken)
        {
            ReturnBool returnBool = new();
            ReturnBool rbKey = Utilities.GetAppSettings("IndustryKey", "RootKey");
            string aesKeyInd = rbKey.status ? rbKey.message : "Not defined";
            rbKey = Utilities.GetAppSettings("IndustryKey", "RootVector");
            string aesVectorInd = rbKey.status ? rbKey.message : "Not defined";
            if (rbKey.status)
            {
                swsAuthToken = HttpUtility.UrlDecode(swsAuthToken);
                try
                {
                    string authToken, plainToken;
                    plainToken = Utilities.Aes256Decrypt(swsAuthToken, aesKeyInd, aesVectorInd);
                    string[] arrVal = plainToken.Split('#');
                    if (arrVal.Length > 0)
                    {
                        returnBool.status = true;
                        returnBool.message = arrVal[0].ToString();
                        returnBool.message1 = Convert.ToInt64(arrVal[1].ToString()).ToString();
                        returnBool.value = plainToken;
                    }
                    else
                        returnBool.message = "Invalid login Request.";

                }
                catch (Exception ex)
                {
                    returnBool.message = "Failed to Decryp token";
                    WriteLog.Error("DecryptSWSDepartmentlogin - ", ex);
                }
            }
            return returnBool;
        }


        #region  Forgot / Change Password Method For OLD Industry DB
        public async Task<ReturnClass.ReturnBool> ChangeOldIndustriesUsersPassword(BlUser bl)
        {
            string query = "", query2 = "";
            if (bl.password.Length > 7)
            {
                MySqlParameter[] pm = new MySqlParameter[]
                {
                new MySqlParameter("loginId", MySqlDbType.String) { Value = bl.emailId },
                new MySqlParameter("password", MySqlDbType.String) { Value = bl.password},
                new MySqlParameter("yes", MySqlDbType.Int16) { Value =(Int16)YesNo.Yes},
                new MySqlParameter("no", MySqlDbType.Int16) { Value =(Int16)YesNo.No},
               new MySqlParameter("active", MySqlDbType.VarChar) { Value = "Y"},
                  new MySqlParameter("clientIp", MySqlDbType.VarChar) { Value = bl.clientIp},                };

                query = @"SELECT  DISTINCT  l.Password,l.isUserMigrate
                            FROM  industry_user_registration.user_login l                            
                            INNER jOIN industry_user_registration.userregistration ur ON ur.login_id=l.Login_Id
                            WHERE  l.login_id=@loginId  AND  l.Active =@active AND  ur.verified=@active
                            UNION ALL
                            SELECT  l.Password,l.isUserMigrate
                            FROM user_login l                            
                            WHERE  (l.User_Name=@loginId OR  l.Login_Id =@loginId) AND  l.Active =@active ; ";



                dt = await db1.ExecuteSelectQueryAsync(query, pm.ToArray());
                if (dt.table.Rows.Count > 0)
                {

                    //if (dt.table.Rows[0]["isUserMigrate"].ToString() == "1")
                    //{
                    //    rb.status = false;
                    //    rb.message = "Password has already been changed";
                    //    return rb;
                    //}
                    string passwordTbl = dt.table.Rows[0]["password"].ToString();
                    if (bl.oldPassword == passwordTbl)
                    {
                        if (bl.roleId == (Int16)UserRole.OnlineUser)
                        {
                            query2 = @"INSERT INTO industry_user_registration.user_login_log
                                      SELECT * FROM industry_user_registration.user_login l
                                        WHERE  l.login_id=@loginId  AND  l.Active =@active 
                                    ";

                            query = @"UPDATE  industry_user_registration.user_login 
                                SET password = @password ,isUserMigrate= @yes                         
                            WHERE  login_id=@loginId  AND  Active =@active ";
                        }
                        else
                        {
                            query2 = @"INSERT INTO user_login_log
                                      SELECT * FROM user_login l
                                        WHERE  (l.User_Name=@loginId OR  l.Login_Id =@loginId) 
                                        AND  l.Active =@active ";

                            query = @"UPDATE user_login  
                                SET password = @password ,isUserMigrate= @yes   
                            WHERE  (User_Name=@loginId OR  Login_Id =@loginId) AND  Active =@active  ; ";
                        }
                        using (TransactionScope ts = new(TransactionScopeAsyncFlowOption.Enabled))
                        {
                            rb = await db1.ExecuteQueryAsync(query2, pm, "ChangeOldIndustriesUsersPassword(insertuserloginlog) ");
                            if (rb.status)
                            {
                                rb = await db1.ExecuteQueryAsync(query, pm, "ChangeOldIndustriesUsersPassword(Updateuserloginlog) ");
                                if (rb.status)
                                {
                                    ts.Complete();
                                    rb.message = "Your Password has been changed!!";
                                }
                                else
                                    rb.message = "Failed to change password. Please try later";
                            }
                        }
                    }
                    else
                    {
                        rb.message = "Invalid Request token.";
                    }
                }
                else
                {
                    rb.message = "Password must be at least 8 characters";
                }

            }
            return rb;
        }

        public async Task<ReturnClass.ReturnBool> ForgotOldIndustriesUsersPassword(BlUser bl)
        {
            string query = "", query2 = "";
            if (bl.password.Length > 7)
            {
                MySqlParameter[] pm = new MySqlParameter[]
                {
                new MySqlParameter("loginId", MySqlDbType.String) { Value = bl.emailId},
                new MySqlParameter("password", MySqlDbType.String) { Value = bl.password},
                new MySqlParameter("yes", MySqlDbType.Int16) { Value =(Int16)YesNo.Yes},
                new MySqlParameter("no", MySqlDbType.Int16) { Value =(Int16)YesNo.No},
               new MySqlParameter("active", MySqlDbType.VarChar) { Value = "Y"},
                  new MySqlParameter("clientIp", MySqlDbType.VarChar) { Value = bl.clientIp},
                };

                query = @"SELECT  DISTINCT  l.isUserMigrate ," + (Int16)UserRole.OnlineUser + @" AS userRole
                            FROM  industry_user_registration.user_login l                            
                            INNER jOIN industry_user_registration.userregistration ur ON ur.login_id=l.Login_Id
                            WHERE  l.login_id=@loginId  AND  l.Active =@active AND  ur.verified=@active 
                            UNION ALL
                            SELECT  l.isUserMigrate ," + (Int16)UserRole.IndustryNodalUser + @" AS userRole
                            FROM user_login l                            
                            WHERE  (l.User_Name=@loginId OR  l.Login_Id =@loginId) AND  l.Active =@active ; ";



                dt = await db1.ExecuteSelectQueryAsync(query, pm.ToArray());
                if (dt.table.Rows.Count > 0)
                {
                    if (Convert.ToInt16(dt.table.Rows[0]["userRole"].ToString()) == (Int16)UserRole.OnlineUser)
                    {
                        query2 = @"INSERT INTO industry_user_registration.user_login_log
                                      SELECT * FROM industry_user_registration.user_login l
                                        WHERE  l.login_id=@loginId  AND  l.Active =@active ";

                        query = @"UPDATE  industry_user_registration.user_login 
                                SET password = @password ,isUserMigrate= @yes                         
                            WHERE  login_id=@loginId  AND  Active =@active ";
                    }
                    else
                    {
                        query2 = @"INSERT INTO user_login_log
                                      SELECT * FROM user_login l
                                        WHERE  (l.User_Name=@loginId OR  l.Login_Id =@loginId) 
                                        AND  l.Active =@active ";

                        query = @"UPDATE user_login  
                                SET password = @password ,isUserMigrate= @yes   
                            WHERE  (User_Name=@loginId OR  Login_Id =@loginId) AND  Active =@active  ; ";
                    }
                    using (TransactionScope ts = new(TransactionScopeAsyncFlowOption.Enabled))
                    {
                        rb = await db1.ExecuteQueryAsync(query2, pm, "ChangeOldIndustriesUsersPassword(insertuserloginlog) ");
                        if (rb.status)
                        {
                            rb = await db1.ExecuteQueryAsync(query, pm, "ChangeOldIndustriesUsersPassword(Updateuserloginlog) ");
                            if (rb.status)
                            {
                                ts.Complete();
                                rb.message = "Your Password has been changed!!";
                            }
                            else
                                rb.message = "Failed to change password. Please try later";
                        }
                    }
                }
                else
                {
                    rb.message = "Password must be at least 8 characters";
                }

            }
            return rb;
        }
        #endregion

        /// <summary>
        /// </summary>
        /// <returns>Returns True when Account exists</returns>
        public async Task<ReturnClass.ReturnString> CheckUserAccountExistByMobile(SendOtp sendOtp)
        {
            ReturnString rs = new();
            string query = "";
            //query = @"SELECT u.emailId AS userId,sp.swsProjectId  AS id,u.userRole ,sp.deptNameEnglish AS Name
            //                 FROM userlogin u
            //                 JOIN swsregisteredprojects sp ON sp.officeEmail=u.emailId
            //                 WHERE sp.nodalOfficerMobile=@mobileNo ; ";
            MySqlParameter[] pm = new MySqlParameter[]
            {
                //new MySqlParameter("emailId", MySqlDbType.VarChar) { Value = sendOtp.emailId},
                new MySqlParameter("mobileNo", MySqlDbType.VarChar) { Value = sendOtp.mobileNo.ToString()},
            };
            //dt = await db.ExecuteSelectQueryAsync(query, pm);
            //if (dt.table.Rows.Count > 0)
            //{
            //    rs.status = true;
            //    rs.message = "Department Name :" + dt.table.Rows[0]["Name"].ToString();
            //    rs.secondryId = dt.table.Rows[0]["userId"].ToString();
            //    rs.value = "projects";
            //}
            //else
            //{
            //if (sendOtp.loginFor == 1) // New Industrialist
            //{
            //    query = @"SELECT u.emailId AS userId, sp.registrationId AS id,u.userRole ,
            //                    TRIM(CONCAT(sp.applicantFirstName ,' ', IFNULL(sp.applicantMiddleName,'') ,' ', IFNULL(sp.applicantLastName,''))) AS applicantName ,
            //                    sp.applicantFirstName,sp.applicantMiddleName,sp.applicantLastName
            //                 FROM userlogin u
            //                 JOIN userregistration sp ON sp.emailId=u.emailId AND sp.registrationId=u.userId
            //                  WHERE sp.mobileNo=@mobileNo;";
            //    dt = await db.ExecuteSelectQueryAsync(query, pm);
            //    if (dt.table.Rows.Count > 0)
            //    {
            //        rs.status = true;
            //        rs.message = "Applicant Name :" + dt.table.Rows[0]["applicantName"].ToString();
            //        rs.secondryId = dt.table.Rows[0]["userId"].ToString();
            //        rs.value = "user";
            //    }
            //}
            //else // Login For InternalDepartmentUser
            //{
            if (sendOtp.loginFor == 1) // New Industrialist
                query = @"SELECT  DISTINCT user_name AS userName, ur.login_id AS userId,ur.email_id as emailId,
                                 " + (Int16)UserRole.OnlineUser + @"  AS userRole
                              FROM  industry_user_registration.user_login l 
                    INNER JOIN role rl ON rl.Role_Id= l.Role_Id    
                    INNER jOIN industry_user_registration.userregistration ur ON ur.login_id=l.Login_Id 
                    WHERE l.Active =@active AND  ur.verified=@active AND ur.applicant_mobile_no=@mobileNo";

            else if (sendOtp.loginFor == 2) //InternalDepartmentUser
                query = @" SELECT DISTINCT emp.Emp_Name AS userName, l.Login_Id AS userId, emp.Emp_Email_Id as emailId, 
                  " + (Int16)UserRole.IndustryNodalUser + @"  AS userRole
                  FROM user_login l 
                  INNER JOIN employees emp ON emp.emp_id = l.Login_Id 
                  inner JOIN  emp_office_mapping e ON  e.Emp_Id=emp.emp_id AND  e.active=@approved 
                  inner JOIN  office f ON  f.office_code =e.Office_Code 
                  INNER JOIN role r ON  r.role_id=l.role_id 
                  WHERE l.Active =@active AND emp.Emp_Mobile=@mobileNo ";

            pm = new MySqlParameter[]
           {
                        //new MySqlParameter("emailId", MySqlDbType.VarChar) { Value = sendOtp.emailId},
                        new MySqlParameter("mobileNo", MySqlDbType.VarChar) { Value = sendOtp.mobileNo.ToString()},
                        new MySqlParameter("active", MySqlDbType.VarChar) { Value = "Y"},
                        new MySqlParameter("approved", MySqlDbType.VarChar) { Value = "A"},
           };
            dt = await db1.ExecuteSelectQueryAsync(query, pm);
            if (dt.table.Rows.Count > 0)
            {
                rs.status = true;
                rs.secondryId = dt.table.Rows[0]["userId"].ToString();
                rs.value = dt.table.Rows[0]["emailId"].ToString();
                if (Convert.ToInt16(dt.table.Rows[0]["userRole"].ToString()) == (Int16)UserRole.IndustryNodalUser)
                {
                    rs.message = "Department Name :" + dt.table.Rows[0]["userName"].ToString();
                }
                else
                {
                    rs.message = "Applicant Name :" + dt.table.Rows[0]["userName"].ToString();
                }
            }
            else
            {

                rs.status = false;
                rs.message = "Invalid User Details.";
                rs.value = "";
            }
            //}
            //}
            if (rs.status)
            {
                sendOtp.msgType = " forgot userId in ";
                ReturnString rs1 = await SendOTP(sendOtp);
                if (rs1.status)
                    rs.msgId = rs1.msgId;
                else
                {
                    rs.value = rs1.value;
                    rs.msgId = rs1.msgId;
                    rs.secondryId = rs1.secondryId;
                }

            }
            return rs;
        }

        /// <summary>
        /// 
        /// Verify Public Mobile OTP
        /// </summary>
        /// <returns>Verify OTP</returns>
        public async Task<ReturnClass.ReturnBool> VerifyForgetOTPUserId(string msgId, Int32 OTP, string Mobile, string userId, string emailId)
        {
            ReturnClass.ReturnBool rb = new();
            string query = "";
            Int32 repeatCounter = Convert.ToInt32(Utilities.GetAppSettings("SmsConfiguration", "ResendLimit").message);
            MySqlParameter[] pm = new MySqlParameter[]
           {
                new MySqlParameter("msgId", MySqlDbType.String) { Value = msgId},
                new MySqlParameter("mobileNo", MySqlDbType.String) { Value = Mobile},
                new MySqlParameter("msgOtp", MySqlDbType.Int32) { Value = OTP},
                new MySqlParameter("isOtpVerified", MySqlDbType.Int16) { Value = (Int16)OTPStatus.Verified},
                new MySqlParameter("notVerified", MySqlDbType.Int16) { Value = (Int16)OTPStatus.Pending},
           };
            Mobile = Mobile.ToString().Substring(Mobile.ToString().Length - 10);
            string mobileno = Mobile.ToString();

            Match match = Regex.Match(mobileno.ToString(),
                         @"^[6-9]\d{9}$", RegexOptions.IgnoreCase);
            if (match.Success == false)
            {
                rb.status = false;
                rb.message = "Invalid Mobile Number";
                return rb;
            }
            rb = await VerifyOTP(msgId, (Int16)ContactVerifiedType.Mobile, OTP, Mobile);
            if (rb.status)
            {
                query = @"UPDATE smssentdetail
                        SET isOtpVerified=@isOtpVerified,otpVerificationDate=NOW()
                             WHERE msgId = @msgId AND  mobileNo = @mobileNo  AND msgOtp=@msgOtp AND isOtpVerified= @notVerified;";
                rb = await db.ExecuteQueryAsync(query, pm.ToArray(), "VerifyOTP");

                // send userid
                SendOtp bl = new();
                bl.mobileNo = Convert.ToInt64(mobileno);
                string userType = "";
                if (bl.loginFor == 1)
                    userType = "Industrialist";
                else
                    userType = "Department";

                bl.userId = userId;
                bl.emailId = emailId;
                await SendUserId(bl, userType);
            }
            return rb;
        }

        /// <summary>
        /// Send OTP 
        /// </summary>
        /// <param name="bl"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnString> SendUserId(SendOtp bl, string userType)
        {
            ReturnClass.ReturnString rs = new();
            ReturnClass.ReturnBool rb = new ReturnClass.ReturnBool();

            bl.mobileNo = Convert.ToInt64(bl.mobileNo.ToString().Substring(bl.mobileNo.ToString().Length - 10));
            string mobileno = bl.mobileNo.ToString();

            Match match = Regex.Match(mobileno,
                              @"^[6-9]\d{9}$", RegexOptions.IgnoreCase);
            if (match.Success == false)
            {
                rs.status = false;
                rs.message = "Invalid Mobile Number";
                return rs;
            }
            dt = await CheckSMSSendDuration(mobileno, (Int16)SMSSendType.Send);
            if (dt.status)
            {
                rs.status = false;
                rs.value = dt.value;
                rs.message = dt.message;
                if (rs.value.ToString().Trim() != ((Int16)OTPStatus.Expired).ToString().Trim())
                {
                    rs.msgId = dt.type;
                    rs.secondryId = mobileno.ToString();
                }
                return rs;
            }
            DlCommon dlCommon = new();

            Utilities util = new Utilities();
            //Int64 smsotp = util.GenRendomNumber(4);
            rs.secondryId = "Your UserId is " + bl.emailId;
            string smsServiceActive = Utilities.GetAppSettings("sandeshSmsConfig", "isActive").message;
            string normalSMSServiceActive = Utilities.GetAppSettings("SmsConfiguration", "isActive").message;
            string EmailServiceActive = Utilities.GetAppSettings("EmailConfiguration", "isActive").message;
            // Int32 SMSVerificationLimit = Convert.ToInt32(Utilities.GetAppSettings("SmsConfiguration", "SMSVerificationLimit").message) / 60;
            AlertMessageBody smsbody = new();
            SandeshResponse rbs = new();
            ReturnDataTable dtsmstemplate = await dlCommon.GetSMSEmailTemplate((Int32)SmsEmailTemplate.INDSWS_UserIdRetrieval);
            sandeshMessageBody sandeshMessageBody = new();
            string smsTemplate = dtsmstemplate.table.Rows[0]["msgBody"].ToString()!;
            sandeshMessageBody.templateId = Convert.ToInt64(dtsmstemplate.table.Rows[0]["templateId"].ToString()!);
            if (sandeshMessageBody.templateId > 0)
            {
                #region create Parameter To send SMS
                object[] values = new object[] { userType, bl.userId };
                sandeshMessageBody.message = DlCommon.GetFormattedMsg(smsTemplate, values);

                sandeshMessageBody.contact = mobileno;
                sandeshMessageBody.msgCategory = (Int16)SandeshmsgCategory.Info;
                sandeshMessageBody.msgPriority = (Int16)SandeshmsgPriority.HighVolatile;
                smsbody.smsBody = sandeshMessageBody.message;
                sandeshMessageBody.clientIp = bl.clientIp;
                sandeshMessageBody.isOTP = true;
                rs.secondryId = "0";
                SandeshSms sms = new SandeshSms();
                #endregion
                try
                {
                    #region Send sansesh SMS
                    if (smsServiceActive.ToUpper() == "TRUE")
                        rbs = await sms.callSandeshAPI(sandeshMessageBody);
                    #endregion

                    #region Send Normal SMS
                    if (normalSMSServiceActive.ToUpper() == "TRUE")
                        rbs = await sms.CallSMSAPI(sandeshMessageBody);
                    #endregion

                    #region Email OTP 
                    //New code To Send Email From 31.103
                    if (bl.emailId != string.Empty && EmailServiceActive.ToUpper() == "TRUE")
                    {
                        Email em = new();
                        emailSenderClass emailSenderClass = new();
                        emailSenderClass.emailSubject = "UserId Retrieval for SWS Chhattisgarh"!;
                        emailSenderClass.emailBody = sandeshMessageBody.message!;
                        emailSenderClass.emailToId = bl.emailId!;
                        emailSenderClass.emailToName = "";
                        await em.SendEmailViaURLAsync(emailSenderClass);
                    }
                    #endregion


                }
                catch (Exception ex)
                { }
            }

            #region Save User Id Retrieval Details in DB
            smsbody.smsBody = sandeshMessageBody.message;
            smsbody.smsTemplateId = (Int32)SmsEmailTemplate.INDSWS_UserIdRetrieval;
            smsbody.isOtpMsg = false;
            smsbody.applicationId = bl.id == null ? 0 : bl.id;
            smsbody.mobileNo = bl.mobileNo;
            smsbody.msgCategory = (Int16)MessageCategory.OTHER;
            smsbody.clientIp = bl.clientIp;
            smsbody.smsLanguage = LanguageSupported.English;
            smsbody.emailToReceiver = bl.emailId;
            smsbody.emailSubject = "UserId Retrieval";
            smsbody.messageServerResponse = rbs.status;
            smsbody.actionId = 1;
            rb = await dlCommon.SendSmsSaveAsync(smsbody);
            if (rb.status)
            {
                rs.status = true;
                rs.msgId = rb.message;
            }
            #endregion


            return rs;
        }

        #region Save employee
        /// <summary>
        /// Save Employee Details
        /// </summary>
        /// <param name="bl"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnString> SaveEmployee(Employee bl)
        {
            ReturnClass.ReturnString rs = await GenerateEmployeeCode();
            if (rs.status)
            {
                bl.empCode = rs.id;
                //        ReturnClass.ReturnBool rb = new ReturnClass.ReturnBool();
                //bl.contactNumber = Convert.ToInt64(bl.contactNumber.ToString().Substring(bl.contactNumber.ToString().Length - 10));
                //string mobileno = bl.contactNumber.ToString();
                //Match match = Regex.Match(mobileno,
                //                  @"^[6-9]\d{9}$", RegexOptions.IgnoreCase);
                //if (match.Success == false)
                //{
                //    rs.status = false;
                //    rs.message = "Invalid Mobile Number";
                //    return rs;
                //}
                if (bl.email != string.Empty)
                {
                    Match match = Regex.Match(bl.email.ToString(),
                                     @"^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+$", RegexOptions.IgnoreCase);
                    if (match.Success == false)
                    {
                        rs.status = false;
                        rs.message = "Given email id is not valid.";
                        return rs;
                    }
                }
                DlCommon dlCommon = new();
                if (rs.status)
                {

                    string query = @"INSERT INTO employeemaster (empCode,firstName,lastName,contactNumber,
                                            email,dob,gender,nationality,joiningDate,shift,department,
                                            bloodGroup,emergencyContact1,emergencyContact2,address,
                                            country,state,city,zipcode,workingStatus,recruitmentType,
                                            active,userId,clientIp,creationTimeStamp,lastUpdate,
                                            registrationYear) 
										  VALUES
										  (@empCode,@firstName,@lastName,@contactNumber,@email,@dob,@gender,
                                            @nationality,@joiningDate,@shift,@department,@bloodGroup,
                                            @emergencyContact1,@emergencyContact2,@address,@country,
                                            @state,@city,@zipcode,@workingStatus,@recruitmentType,
                                            @active,@userId,@clientIp,@creationTimeStamp,@lastUpdate,
                                            @registrationYear)";
                    if (bl.dob.ToString() != string.Empty)
                        bl.dob = Convert.ToDateTime(bl.dob.ToString()).ToString("yyyy/MM/dd");
                    if (bl.joiningDate.ToString() != string.Empty)
                        bl.joiningDate = Convert.ToDateTime(bl.joiningDate.ToString()).ToString("yyyy/MM/dd");
                    MySqlParameter[] pm = new MySqlParameter[] {
                     new MySqlParameter("@empCode", MySqlDbType.Int64) { Value = bl.empCode},
                    new MySqlParameter("@firstName", MySqlDbType.VarChar) { Value = bl.firstName},
                    new MySqlParameter("@lastName", MySqlDbType.String) { Value = bl.lastName},
                    new MySqlParameter("@contactNumber", MySqlDbType.Int64) { Value = bl.contactNumber},
                    new MySqlParameter("@email", MySqlDbType.VarChar) { Value = bl.email},
                    new MySqlParameter("@dob", MySqlDbType.VarString) { Value = bl.dob},
                    new MySqlParameter("@gender", MySqlDbType.VarString) { Value = bl.gender},
                    new MySqlParameter("@nationality", MySqlDbType.VarString) { Value = bl.nationality},
                    new MySqlParameter("@joiningDate", MySqlDbType.VarString) { Value = bl.joiningDate},
                    new MySqlParameter("@shift", MySqlDbType.VarChar) { Value = bl.shift},
                    new MySqlParameter("@department", MySqlDbType.String) { Value = bl.department},
                    new MySqlParameter("@bloodGroup", MySqlDbType.String) { Value = bl.bloodGroup},
                    new MySqlParameter("@emergencyContact1", MySqlDbType.String) { Value = bl.emergencyContact1},
                    new MySqlParameter("@emergencyContact2", MySqlDbType.String) { Value = bl.emergencyContact2},
                    new MySqlParameter("@address", MySqlDbType.String) { Value = bl.address},
                    new MySqlParameter("@country", MySqlDbType.String) { Value = bl.country},
                    new MySqlParameter("@state", MySqlDbType.String) { Value = bl.state},
                    new MySqlParameter("@city", MySqlDbType.String) { Value = bl.city},
                    new MySqlParameter("@zipcode", MySqlDbType.String) { Value = bl.zipcode},
                    new MySqlParameter("@workingStatus", MySqlDbType.Int16) { Value = bl.workingStatus},
                    new MySqlParameter("@recruitmentType", MySqlDbType.Int16) { Value = bl.recruitmentType},
                    new MySqlParameter("@active", MySqlDbType.Int16) { Value = bl.active},
                     new MySqlParameter("@userId", MySqlDbType.Int64) { Value = bl.userId},
                      new MySqlParameter("@clientIp", MySqlDbType.String) { Value = bl.clientIp},
                       new MySqlParameter("@registrationYear", MySqlDbType.String) { Value = DateTime.Now.Year},

                };

                    rb = await db.ExecuteQueryAsync(query, pm, "SaveEmployee");
                    if (rb.status)
                    {
                        rs.status = true;
                        rs.message = "Employee Details Saved";
                    }
                    else
                    {
                        rs = new();
                        rs.message = "Failed to Save Employee";
                    }
                }
            }

            return rs;
        }

        /// <summary>
        /// Update Employee Details
        /// </summary>
        /// <param name="bl"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnString> UpdateEmployee(Employee bl)
        {
            ReturnClass.ReturnString rs = new();
            ReturnClass.ReturnBool rb = new ReturnClass.ReturnBool();
            //bl.contactNumber = Convert.ToInt64(bl.contactNumber.ToString().Substring(bl.contactNumber.ToString().Length - 10));
            //string mobileno = bl.contactNumber.ToString();
            //Match match = Regex.Match(mobileno,
            //                  @"^[6-9]\d{9}$", RegexOptions.IgnoreCase);
            //if (match.Success == false)
            //{
            //    rs.status = false;
            //    rs.message = "Invalid Mobile Number";
            //    return rs;
            //}
            if (bl.email != string.Empty)
            {
                Match match = Regex.Match(bl.email.ToString(),
                                 @"^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+$", RegexOptions.IgnoreCase);
                if (match.Success == false)
                {
                    rs.status = false;
                    rs.message = "Given email id is not valid.";
                    return rs;
                }
                else rs.status = true;
            }
            else
                rs.status = true;
            DlCommon dlCommon = new();
            if (rs.status)
            {
                string query = @"";
                if (bl.dob.ToString() != string.Empty)
                    bl.dob = Convert.ToDateTime(bl.dob.ToString()).ToString("yyyy/MM/dd");
                if (bl.joiningDate.ToString() != string.Empty)
                    bl.joiningDate = Convert.ToDateTime(bl.joiningDate.ToString()).ToString("yyyy/MM/dd");

                MySqlParameter[] pm = new MySqlParameter[] {
                    new MySqlParameter("@empCode", MySqlDbType.Int64) { Value = bl.empCode},
                     new MySqlParameter("@firstName", MySqlDbType.VarChar) { Value = bl.firstName},
                    new MySqlParameter("@lastName", MySqlDbType.String) { Value = bl.lastName},
                    new MySqlParameter("@contactNumber", MySqlDbType.Int64) { Value = bl.contactNumber},
                    new MySqlParameter("@email", MySqlDbType.VarChar) { Value = bl.email},
                    new MySqlParameter("@dob", MySqlDbType.VarString) { Value = bl.dob},
                    new MySqlParameter("@gender", MySqlDbType.VarString) { Value = bl.gender},
                    new MySqlParameter("@nationality", MySqlDbType.VarString) { Value = bl.nationality},
                    new MySqlParameter("@joiningDate", MySqlDbType.VarString) { Value = bl.joiningDate},
                    new MySqlParameter("@shift", MySqlDbType.VarChar) { Value = bl.shift},
                    new MySqlParameter("@department", MySqlDbType.String) { Value = bl.department},
                    new MySqlParameter("@bloodGroup", MySqlDbType.String) { Value = bl.bloodGroup},
                    new MySqlParameter("@emergencyContact1", MySqlDbType.String) { Value = bl.emergencyContact1},
                    new MySqlParameter("@emergencyContact2", MySqlDbType.String) { Value = bl.emergencyContact2},
                    new MySqlParameter("@address", MySqlDbType.String) { Value = bl.address},
                    new MySqlParameter("@country", MySqlDbType.String) { Value = bl.country},
                    new MySqlParameter("@state", MySqlDbType.String) { Value = bl.state},
                    new MySqlParameter("@city", MySqlDbType.String) { Value = bl.city},
                    new MySqlParameter("@zipcode", MySqlDbType.String) { Value = bl.zipcode},
                    new MySqlParameter("@workingStatus", MySqlDbType.Int16) { Value = bl.workingStatus},
                    new MySqlParameter("@recruitmentType", MySqlDbType.Int16) { Value = bl.recruitmentType},
                    new MySqlParameter("@active", MySqlDbType.Int16) { Value = bl.active},
                     new MySqlParameter("@userId", MySqlDbType.Int64) { Value = bl.userId},
                      new MySqlParameter("@clientIp", MySqlDbType.String) { Value = bl.clientIp},
                       new MySqlParameter("@registrationYear", MySqlDbType.String) { Value = DateTime.Now.Year},

                };
                query = @" INSERT INTO employeemasterlog
                                  SELECT * FROM employeemaster 
                                  WHERE empCode=@empCode ";

                using (TransactionScope ts = new(TransactionScopeAsyncFlowOption.Enabled))
                {
                    rb = await db.ExecuteQueryAsync(query, pm, "SaveEmployeelog");
                    if (rb.status)
                    {
                        query = @"UPDATE employeemaster SET 
                                      firstName=@firstName,lastName=@lastName,contactNumber=@contactNumber,
                                      email=@email,dob=@dob,gender=@gender,nationality=@nationality,
                                      joiningDate=@joiningDate,shift=@shift,department=@department,
                                      bloodGroup=@bloodGroup,emergencyContact1=@emergencyContact1,
                                      emergencyContact2=@emergencyContact2,address=@address,
                                      country=@country,state=@state,city=@city,zipcode=@zipcode,
                                      workingStatus=@workingStatus,recruitmentType=@recruitmentType,
                                      active=@active,userId=@userId,clientIp=@clientIp,
                                      registrationYear=@registrationYear 
                                      WHERE empCode=@empCode;";
                        rb = await db.ExecuteQueryAsync(query, pm, "UpdateEmployee");
                        if (rb.status)
                            ts.Complete();
                    }

                }
                if (rb.status)
                {
                    rs.status = true;
                    rs.message = "Employee Details Updated";
                }
                else
                    rs.message = "Failed to Update Employee";
            }

            return rs;
        }
        /// <summary>
        /// Returns Emp Code in the format P(2) YY NNN NNN N
        /// </summary>
        /// <returns>Emp code</returns>
        private async Task<ReturnClass.ReturnString> GenerateEmployeeCode()
        {
            ReturnClass.ReturnString rs = new();
            string query = @"SELECT IFNULL(MAX(SUBSTRING(e.empCode,4,10)),0) + 1 AS  empCode
                             FROM employeemaster e 
                             WHERE e.registrationYear = YEAR(CURDATE());";

            dt = await db.ExecuteSelectQueryAsync(query);
            if (dt.table.Rows.Count > 0)
            {
                // ID Format = P(2) YY NNN NNN N
                string id = ((int)PrefixId.IndustryEmployee).ToString() + DateTime.Now.ToString("yy") + dt.table.Rows[0]["empCode"].ToString().PadLeft(7, '0');
                rs.id = Convert.ToInt64(id);
                rs.value = dt.table.Rows[0]["empCode"].ToString();
                rs.status = true;
            }
            return rs;
        }
        /// <summary>
        /// 
        /// Get Employee List
        /// </summary>
        /// <returns>Verify OTP</returns>
        public async Task<ReturnDataTable> GetEmployee(Int64 empCode, Int16 active)
        {
            string query = "";
            MySqlParameter[] pm = new MySqlParameter[]
           {
                new MySqlParameter("empCode", MySqlDbType.Int64) { Value = empCode},
                new MySqlParameter("active", MySqlDbType.Int16) { Value = active},
           };
            query = @"SELECT e.empCode,e.firstName,e.lastName,e.contactNumber,e.email,DATE_FORMAT(e.dob,'%d/%m/%Y') AS dob,
                            e.gender,e.nationality,DATE_FORMAT( e.joiningDate,'%d/%m/%Y') AS joiningDate,e.shift,e.department,
                            e.bloodGroup,e.emergencyContact1,e.emergencyContact2,e.address,
                            e.country,e.state,e.city,e.zipcode 
                             FROM employeemaster e 
                           WHERE e.active=@active ";
            if (empCode != 0)
                query += @" AND e.empCode=@empCode ";
            dt = await db.ExecuteSelectQueryAsync(query, pm);

            return dt;
        }

        #endregion

        #region Save Unit Master
        /// <summary>
        /// Save Employee Details
        /// </summary>
        /// <param name="bl"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnBool> SaveUnitMaster(UnitMaster bl)
        {

            DlCommon dlCommon = new();
            string query = @"INSERT INTO unitmaster (unitName,shortName,active,userId,
                                                clientIp) 
										  VALUES
										  (@unitName,@shortName,@active,@userId,
                                                @clientIp)";

            MySqlParameter[] pm = new MySqlParameter[] {
                    // new MySqlParameter("@empCode", MySqlDbType.Int64) { Value = bl.empCode},
                    new MySqlParameter("@unitName", MySqlDbType.VarChar) { Value = bl.unitName},
                    new MySqlParameter("@shortName", MySqlDbType.String) { Value = bl.shortName},
                    new MySqlParameter("@active", MySqlDbType.Int16) { Value = bl.active},
                     new MySqlParameter("@userId", MySqlDbType.Int64) { Value = bl.userId},
                      new MySqlParameter("@clientIp", MySqlDbType.String) { Value = bl.clientIp},

                };

            rb = await db.ExecuteQueryAsync(query, pm, "Saveunit");
            if (rb.status)
                rb.message = "Unit Details Saved";
            else
            {

                rb.message = "Failed to Save Unit";
            }
            return rb;
        }

        /// <summary>
        /// Update Employee Details
        /// </summary>
        /// <param name="bl"></param>
        /// <returns></returns>
        /// 
        public async Task<ReturnClass.ReturnBool> UpdateUnitMaster(UnitMaster bl)
        {

            DlCommon dlCommon = new();
            string query = @"";

            MySqlParameter[] pm = new MySqlParameter[] {
                    new MySqlParameter("@unitId", MySqlDbType.Int32) { Value = bl.unitId},
                    new MySqlParameter("@unitName", MySqlDbType.VarChar) { Value = bl.unitName},
                    new MySqlParameter("@shortName", MySqlDbType.String) { Value = bl.shortName},
                    new MySqlParameter("@active", MySqlDbType.Int16) { Value = bl.active},
                     new MySqlParameter("@userId", MySqlDbType.Int64) { Value = bl.userId},
                      new MySqlParameter("@clientIp", MySqlDbType.String) { Value = bl.clientIp},


                };

            query = @" INSERT INTO unitmasterlog
                                  SELECT * FROM unitmaster 
                                  WHERE unitId=@unitId ";

            using (TransactionScope ts = new(TransactionScopeAsyncFlowOption.Enabled))
            {
                rb = await db.ExecuteQueryAsync(query, pm, "Saveunitlog");
                if (rb.status)
                {
                    query = @"UPDATE unitmaster SET 
                                      unitName=@unitName,shortName=@shortName,
                                      active=@active,userId=@userId,clientIp=@clientIp
                                      WHERE unitId=@unitId;";
                    rb = await db.ExecuteQueryAsync(query, pm, "Updateunit");
                    if (rb.status)
                        ts.Complete();
                }

            }
            if (rb.status)
                rb.message = "Unit Details Updated";
            else
            {

                rb.message = "Failed to Update Unit";
            }
            return rb;
        }


        /// <summary>
        /// 
        /// Get Unit List
        /// </summary>
        /// <returns></returns>
        public async Task<ReturnDataTable> GetUnit(Int64 unitId, Int16 active)
        {
            string query = "";
            MySqlParameter[] pm = new MySqlParameter[]
           {
                new MySqlParameter("unitId", MySqlDbType.Int64) { Value = unitId},
                new MySqlParameter("active", MySqlDbType.Int16) { Value = active},
           };
            query = @"SELECT u.unitId,u.unitName,u.shortName FROM unitmaster  u
                                  WHERE  u.active=@active";
            if (unitId != 0)
                query += @" AND u.unitId=@unitId  ";
            dt = await db.ExecuteSelectQueryAsync(query, pm);

            return dt;
        }

        #endregion

        #region Save Item Master
        /// <summary>
        /// Save Employee Details
        /// </summary>
        /// <param name="bl"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnBool> SaveItemMaster(ItemMaster bl)
        {

            DlCommon dlCommon = new();
            string query = @"INSERT INTO itemmaster (itemName,shortName,unitId,unitName,active,userId,
                                                clientIp,itemTypeId,itemTypeName) 
										  VALUES
										  (@itemName,@shortName,@unitId,@unitName,@active,@userId,
                                                @clientIp,@itemTypeId,@itemTypeName)";

            MySqlParameter[] pm = new MySqlParameter[] {
                    // new MySqlParameter("@itemId", MySqlDbType.Int64) { Value = bl.itemId},
                      new MySqlParameter("@itemName", MySqlDbType.String) { Value = bl.itemName},
                        new MySqlParameter("@shortName", MySqlDbType.String) { Value = bl.shortName},
                          new MySqlParameter("@unitId", MySqlDbType.Int32) { Value = bl.unitId},
                    new MySqlParameter("@unitName", MySqlDbType.VarChar) { Value = bl.unitName},
                    new MySqlParameter("@active", MySqlDbType.Int16) { Value = bl.active},
                     new MySqlParameter("@userId", MySqlDbType.Int64) { Value = bl.userId},
                      new MySqlParameter("@clientIp", MySqlDbType.String) { Value = bl.clientIp},
                        new MySqlParameter("@itemTypeId", MySqlDbType.Int16) { Value = bl.itemTypeId},
                    new MySqlParameter("@itemTypeName", MySqlDbType.VarChar) { Value = bl.itemTypeName},


                };

            rb = await db.ExecuteQueryAsync(query, pm, "SaveItem");
            if (rb.status)
                rb.message = "Item Details Saved";
            else
            {

                rb.message = "Failed to Save Item";
            }
            return rb;
        }

        /// <summary>
        /// Update Employee Details
        /// </summary>
        /// <param name="bl"></param>
        /// <returns></returns>
        /// 
        public async Task<ReturnClass.ReturnBool> UpdateItemMaster(ItemMaster bl)
        {

            DlCommon dlCommon = new();
            string query = @"";

            MySqlParameter[] pm = new MySqlParameter[] {
                   new MySqlParameter("@itemId", MySqlDbType.Int64) { Value = bl.itemId},
                      new MySqlParameter("@itemName", MySqlDbType.String) { Value = bl.itemName},
                        new MySqlParameter("@shortName", MySqlDbType.String) { Value = bl.shortName},
                          new MySqlParameter("@unitId", MySqlDbType.Int32) { Value = bl.unitId},
                    new MySqlParameter("@unitName", MySqlDbType.VarChar) { Value = bl.unitName},
                    new MySqlParameter("@active", MySqlDbType.Int16) { Value = bl.active},
                     new MySqlParameter("@userId", MySqlDbType.Int64) { Value = bl.userId},
                      new MySqlParameter("@clientIp", MySqlDbType.String) { Value = bl.clientIp},
                      new MySqlParameter("@itemTypeId", MySqlDbType.Int16) { Value = bl.itemTypeId},
                    new MySqlParameter("@itemTypeName", MySqlDbType.VarChar) { Value = bl.itemTypeName},


                };

            query = @" INSERT INTO itemmasterlog
                                  SELECT * FROM itemmaster 
                                  WHERE itemId=@itemId ";

            using (TransactionScope ts = new(TransactionScopeAsyncFlowOption.Enabled))
            {
                rb = await db.ExecuteQueryAsync(query, pm, "SaveItemlog");
                if (rb.status)
                {
                    query = @"UPDATE itemmaster SET 
                                      itemName=@itemName,shortName=@shortName,unitId=@unitId,unitName=@unitName,
                                      active=@active,userId=@userId,clientIp=@clientIp,itemTypeId=@itemTypeId,itemTypeName=@itemTypeName
                                      WHERE itemId=@itemId;";
                    rb = await db.ExecuteQueryAsync(query, pm, "UpdateItem");
                    if (rb.status)
                        ts.Complete();
                }

            }
            if (rb.status)
            {
                rb.message = "Item Details Updated";
            }
            else
            {

                rb.message = "Failed to Update Item";
            }
            return rb;
        }


        /// <summary>
        /// 
        /// Get Item List
        /// </summary>
        /// <returns></returns>
        public async Task<ReturnDataTable> GetItem(Int64 itemId, Int16 active, Int16 itemtype)
        {
            string query = "";
            MySqlParameter[] pm = new MySqlParameter[]
           {
                new MySqlParameter("itemId", MySqlDbType.Int64) { Value = itemId},
                new MySqlParameter("active", MySqlDbType.Int16) { Value = active},
                new MySqlParameter("itemTypeId", MySqlDbType.Int16) { Value = itemtype},
           };
            query = @"SELECT  i.itemId,i.itemName,i.shortName,i.unitId,
                            i.itemTypeId,i.itemTypeName,i.categoryType,i.quantity
                       , i.unitName 
                        FROM itemmaster i
                                  WHERE  i.active=@active";
            if (itemId != 0)
                query += @" AND i.itemId=@itemId  ";
            if (itemtype != 0)
                query += @" AND i.itemTypeId=@itemTypeId  ";
            dt = await db.ExecuteSelectQueryAsync(query, pm);

            return dt;
        }
        /// <summary>
        /// 
        /// Get  Vendor wise Item List 
        /// </summary>
        /// <returns></returns>
        public async Task<ReturnDataTable> GetVendorWiseItems(Int64 vendorId)
        {
            vendorId = vendorId == null ? 0 : vendorId;
            if (vendorId != 0)
            {
                string query = "";
                MySqlParameter[] pm = new MySqlParameter[]
               {
                new MySqlParameter("vendorId", MySqlDbType.Int64) { Value = vendorId},
                new MySqlParameter("active", MySqlDbType.Int16) { Value = (Int16)IsActive.Yes},

               };
                query = @"SELECT  i.itemId,i.itemName,i.shortName,i.unitId,i.itemTypeId,i.itemTypeName,i.categoryType,
                        i.unitName 
                        FROM itemmaster i
                        JOIN vendoritemdetail v ON v.itemId=i.itemId 
                        WHERE  i.active=@active AND v.active=@active AND v.vendorId=@vendorId 
                            ORDER BY i.itemName";

                dt = await db.ExecuteSelectQueryAsync(query, pm);
            }
            else
                dt.message = "Invalid Vendor Id";

            return dt;
        }

        #endregion

        #region Save Vendor
        /// <summary>
        /// Save Employee Details
        /// </summary>
        /// <param name="bl"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnString> SaveVendor(Vendor bl)
        {
            ReturnClass.ReturnString rs = await GenerateVendorId();
            if (rs.status)
                bl.vendorId = rs.id;


            if (bl.email != string.Empty)
            {
                Match match = Regex.Match(bl.email.ToString(),
                                 @"^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+$", RegexOptions.IgnoreCase);
                if (match.Success == false)
                {
                    rs.status = false;
                    rs.message = "Given email id is not valid.";
                    return rs;
                }

            }
            DlCommon dlCommon = new();
            if (rs.status)
            {

                string query = @"INSERT INTO vendormaster (vendorId,vendorName,typeId,typeName,phone1,
                                            phone2,email,address,city,country,gst,pan,
                                            tan,tin,active,userId,clientIp) 
										  VALUES
										  (@vendorId,@vendorName,@typeId,@typeName,@phone1,
                                            @phone2,@email,@address,@city,@country,@gst,@pan,
                                            @tan,@tin,@active,@userId,@clientIp)";

                MySqlParameter[] pm = new MySqlParameter[] {
                     new MySqlParameter("@vendorId", MySqlDbType.Int64) { Value = bl.vendorId},
                    new MySqlParameter("@vendorName", MySqlDbType.VarChar) { Value = bl.vendorName},
                    new MySqlParameter("@typeId", MySqlDbType.String) { Value = bl.typeId},
                    new MySqlParameter("@typeName", MySqlDbType.String) { Value = bl.typeName},
                    new MySqlParameter("@phone1", MySqlDbType.Int64) { Value = bl.phone1},
                    new MySqlParameter("@phone2", MySqlDbType.VarChar) { Value = bl.phone2},
                    new MySqlParameter("@email", MySqlDbType.VarString) { Value = bl.email},
                    new MySqlParameter("@address", MySqlDbType.VarString) { Value = bl.address},
                    new MySqlParameter("@city", MySqlDbType.VarString) { Value = bl.city},
                    new MySqlParameter("@country", MySqlDbType.VarString) { Value = bl.country},
                    new MySqlParameter("@gst", MySqlDbType.VarChar) { Value = bl.gst},
                    new MySqlParameter("@pan", MySqlDbType.String) { Value = bl.pan},
                    new MySqlParameter("@tan", MySqlDbType.String) { Value = bl.tan},
                    new MySqlParameter("@tin", MySqlDbType.String) { Value = bl.tin},
                    new MySqlParameter("@active", MySqlDbType.Int16) { Value = bl.active},
                     new MySqlParameter("@userId", MySqlDbType.Int64) { Value = bl.userId},
                      new MySqlParameter("@clientIp", MySqlDbType.String) { Value = bl.clientIp},


                };
                using (TransactionScope ts = new(TransactionScopeAsyncFlowOption.Enabled))
                {
                    rb = await db.ExecuteQueryAsync(query, pm, "SaveVendor");
                    if (rb.status)
                    {
                        rb = await AddVendorItemsAsync(bl, 1);
                        if (rb.status)
                        {
                            ts.Complete();
                        }
                    }
                }
                if (rb.status)
                {
                    rs.status = true;
                    rs.message = "Vendor Details Saved";
                }
                else
                {
                    rs = new();
                    rs.message = "Failed to Save Vendor";
                }
            }


            return rs;
        }
        private async Task<ReturnClass.ReturnBool> AddVendorItemsAsync(Vendor vendor, int counter = 1)
        {
            string query = @"insert into vendoritemdetail(itemId, vendorId, itemName, active,clientIp,
                                         userId)
                                  values ";
            List<MySqlParameter> pm = new();

            foreach (VendorItem vendorItem in vendor.vendorItems)
            {
                query += @"(@itemId" + counter.ToString() + ", @vendorId" + counter.ToString() + ", @itemName" + counter.ToString() +
                            ", @active" + counter.ToString() + ", @clientIp" + counter.ToString() + ", @userId" + counter.ToString() + "),";

                pm.Add(new MySqlParameter("vendorId" + counter.ToString(), MySqlDbType.Int64) { Value = vendor.vendorId });
                pm.Add(new MySqlParameter("itemId" + counter.ToString(), MySqlDbType.Int64) { Value = vendorItem.itemId });
                pm.Add(new MySqlParameter("itemName" + counter.ToString(), MySqlDbType.VarString) { Value = vendorItem.itemName });
                pm.Add(new MySqlParameter("active" + counter.ToString(), MySqlDbType.Int16) { Value = 1 });
                pm.Add(new MySqlParameter("clientIp" + counter.ToString(), MySqlDbType.String) { Value = vendor.clientIp });
                pm.Add(new MySqlParameter("userId" + counter.ToString(), MySqlDbType.Int64) { Value = vendor.userId });

                counter++;
            }
            query = query.TrimEnd(',');
            return await db.ExecuteQueryAsync(query, pm.ToArray(), "SAVEAddVendorItemDetails");
        }

        /// <summary>
        /// Update Employee Details
        /// </summary>
        /// <param name="bl"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnString> UpdateVendor(Vendor bl)
        {
            ReturnClass.ReturnString rs = new();
            ReturnClass.ReturnBool rb = new ReturnClass.ReturnBool();

            if (bl.email != string.Empty)
            {
                Match match = Regex.Match(bl.email.ToString(),
                                 @"^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+$", RegexOptions.IgnoreCase);
                if (match.Success == false)
                {
                    rs.status = false;
                    rs.message = "Given email id is not valid.";
                    return rs;
                }
                else rs.status = true;
            }
            else
                rs.status = true;
            DlCommon dlCommon = new();
            if (rs.status)
            {

                string query = @"INSERT INTO vendormasterlog
                                  SELECT * FROM  vendormaster
										   WHERE vendorId=@vendorId";

                MySqlParameter[] pm = new MySqlParameter[] {
                     new MySqlParameter("@vendorId", MySqlDbType.Int64) { Value = bl.vendorId},
                    new MySqlParameter("@vendorName", MySqlDbType.VarChar) { Value = bl.vendorName},
                    new MySqlParameter("@typeId", MySqlDbType.String) { Value = bl.typeId},
                    new MySqlParameter("@typeName", MySqlDbType.String) { Value = bl.typeName},
                    new MySqlParameter("@phone1", MySqlDbType.Int64) { Value = bl.phone1},
                    new MySqlParameter("@phone2", MySqlDbType.VarChar) { Value = bl.phone2},
                    new MySqlParameter("@email", MySqlDbType.VarString) { Value = bl.email},
                    new MySqlParameter("@address", MySqlDbType.VarString) { Value = bl.address},
                    new MySqlParameter("@city", MySqlDbType.VarString) { Value = bl.city},
                    new MySqlParameter("@country", MySqlDbType.VarString) { Value = bl.country},
                    new MySqlParameter("@gst", MySqlDbType.VarChar) { Value = bl.gst},
                    new MySqlParameter("@pan", MySqlDbType.String) { Value = bl.pan},
                    new MySqlParameter("@tan", MySqlDbType.String) { Value = bl.tan},
                    new MySqlParameter("@tin", MySqlDbType.String) { Value = bl.tin},
                    new MySqlParameter("@active", MySqlDbType.Int16) { Value = bl.active},
                     new MySqlParameter("@userId", MySqlDbType.Int64) { Value = bl.userId},
                      new MySqlParameter("@clientIp", MySqlDbType.String) { Value = bl.clientIp},


                };
                using (TransactionScope ts = new(TransactionScopeAsyncFlowOption.Enabled))
                {
                    rb = await db.ExecuteQueryAsync(query, pm, "SaveVendorlog");
                    if (rb.status)
                    {
                        query = @"UPDATE vendormaster
                                   SET   vendorName=@vendorName,typeId=@typeId,typeName=@typeName,phone1=@phone1,
                                            phone2=@phone2,email=@email,address=@address,city=@city,country=@country,gst=@gst,pan=@pan,
                                            tan=@tan,tin=@tin,active=@active,userId=@userId,clientIp=@clientIp 
										   WHERE vendorId=@vendorId";
                        rb = await db.ExecuteQueryAsync(query, pm, "UpdateVendor");
                        if (rb.status)
                        {
                            query = @"INSERT INTO vendoritemdetaillog
                                  SELECT * FROM  vendoritemdetail
										   WHERE vendorId=@vendorId";
                            rb = await db.ExecuteQueryAsync(query, pm, "UpdateVendor");
                            if (rb.status)
                            {
                                query = @"DELETE FROM  vendoritemdetail
										   WHERE vendorId=@vendorId";
                                rb = await db.ExecuteQueryAsync(query, pm, "UpdateVendor");
                                if (rb.status)
                                {
                                    rb = await AddVendorItemsAsync(bl, 1);
                                    if (rb.status)
                                    {
                                        ts.Complete();//
                                    }
                                }
                            }
                        }
                    }
                }
                if (rb.status)
                {
                    rs.status = true;
                    rs.message = "Vendor Details UPDATED";
                }
                else
                {
                    rs = new();
                    rs.message = "Failed to Update Vendor";
                }
            }

            return rs;
        }

        /// <summary>
        /// 
        /// Get Employee List
        /// </summary>
        /// <returns>Verify OTP</returns>
        public async Task<ReturnDataSet> GetVendor(Int64 vendorId, Int16 active)
        {
            string query = "";
            ReturnDataSet ds = new();
            MySqlParameter[] pm = new MySqlParameter[]
           {
                new MySqlParameter("empCode", MySqlDbType.Int64) { Value = vendorId},
                new MySqlParameter("active", MySqlDbType.Int16) { Value = active},
           };
            query = @"SELECT e.vendorId,e.vendorName,e.typeId,e.typeName,e.phone1,
                                            e.phone2,e.email,e.address,e.city,e.country,e.gst,e.pan,
                                            e.tan,e.tin
                             FROM vendormaster e 
                           WHERE e.active=@active ";
            if (vendorId != 0)
                query += @" AND e.vendorId=@vendorId ";
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            ds.status = true;
            if (dt.table.Rows.Count > 0)
            {

                dt.table.TableName = "Vendor";
                ds.dataset.Tables.Add(dt.table);
                query = @"SELECT e.itemId,e.vendorId,e.itemName
                             FROM vendoritemdetail e 
                           WHERE e.active=@active ";
                dt = await db.ExecuteSelectQueryAsync(query, pm);
                if (dt.table.Rows.Count > 0)
                {
                    ds.status = true;
                    dt.table.TableName = "Vendor_Items";
                    ds.dataset.Tables.Add(dt.table);
                }
            }
            else
            {
                dt.table.TableName = "Vendor";
                ds.dataset.Tables.Add(dt.table);
            }
            return ds;
        }
        /// <summary>
        /// Returns Vendor id in the format P(4) NNNN
        /// </summary>
        /// <returns>Emp code</returns>
        private async Task<ReturnClass.ReturnString> GenerateVendorId()
        {
            ReturnClass.ReturnString rs = new();
            string query = @"SELECT IFNULL(MAX(SUBSTRING(e.vendorId,2,5)),0) + 1 AS  vendorId
                             FROM vendormaster e ;";

            dt = await db.ExecuteSelectQueryAsync(query);
            if (dt.table.Rows.Count > 0)
            {
                // ID Format = P(2) YY NNN NNN N
                string id = ((int)PrefixId.BusinessEntityID).ToString() + dt.table.Rows[0]["vendorId"].ToString().PadLeft(4, '0');
                rs.id = Convert.ToInt64(id);
                rs.status = true;
            }
            return rs;
        }

        #endregion

        #region  Brand Master
        /// <summary>
        /// Save Brand Details
        /// </summary>
        /// <param name="bl"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnBool> SavebrandMaster(BrandMaster bl)
        {

            DlCommon dlCommon = new();
            string query = @"INSERT INTO brandmaster (brandName,brandNameHindi,brandCategory,active,userId,
                                                clientIp) 
										  VALUES
										  (@brandName,@brandNameHindi,@brandCategory,@active,@userId,
                                                @clientIp)";

            MySqlParameter[] pm = new MySqlParameter[] {
                  //  new MySqlParameter("@brandId", MySqlDbType.Int32) { Value = bl.brandId},
                    new MySqlParameter("@brandName", MySqlDbType.VarChar) { Value = bl.brandName},
                    new MySqlParameter("@brandNameHindi", MySqlDbType.String) { Value = bl.brandNameHindi},
                    new MySqlParameter("@brandCategory", MySqlDbType.Int16) { Value = bl.brandCategory},
                    new MySqlParameter("@active", MySqlDbType.Int16) { Value = bl.active},
                     new MySqlParameter("@userId", MySqlDbType.Int64) { Value = bl.userId},
                      new MySqlParameter("@clientIp", MySqlDbType.String) { Value = bl.clientIp},


                };

            rb = await db.ExecuteQueryAsync(query, pm, "SaveBrand");
            if (rb.status)
                rb.message = "Brand Details Saved";
            else
            {

                rb.message = "Failed to Save Brand";
            }
            return rb;
        }

        /// <summary>
        /// Update Brand Details
        /// </summary>
        /// <param name="bl"></param>
        /// <returns></returns>
        /// 
        public async Task<ReturnClass.ReturnBool> UpdateBrandMaster(BrandMaster bl)
        {

            DlCommon dlCommon = new();
            string query = @"";

            MySqlParameter[] pm = new MySqlParameter[] {
                    new MySqlParameter("@brandId", MySqlDbType.Int32) { Value = bl.brandId},
                    new MySqlParameter("@brandName", MySqlDbType.VarChar) { Value = bl.brandName},
                    new MySqlParameter("@brandNameHindi", MySqlDbType.String) { Value = bl.brandNameHindi},
                     new MySqlParameter("@brandCategory", MySqlDbType.Int16) { Value = bl.brandCategory},
                    new MySqlParameter("@active", MySqlDbType.Int16) { Value = bl.active},
                     new MySqlParameter("@userId", MySqlDbType.Int64) { Value = bl.userId},
                      new MySqlParameter("@clientIp", MySqlDbType.String) { Value = bl.clientIp},


                };

            query = @" INSERT INTO brandmasterlog
                                  SELECT * FROM brandmaster 
                                  WHERE brandId=@brandId ";

            using (TransactionScope ts = new(TransactionScopeAsyncFlowOption.Enabled))
            {
                rb = await db.ExecuteQueryAsync(query, pm, "SaveBrandlog");
                if (rb.status)
                {
                    query = @"UPDATE brandmaster SET  
                                      brandName=@brandName,brandNameHindi=@brandNameHindi,
                                      brandCategory=@brandCategory,
                                      active=@active,userId=@userId,clientIp=@clientIp
                                      WHERE brandId=@brandId;";
                    rb = await db.ExecuteQueryAsync(query, pm, "Updatebrand");
                    if (rb.status)
                        ts.Complete();
                }

            }
            if (rb.status)
                rb.message = "Brand Details Updated";
            else
            {

                rb.message = "Failed to Update Brand";
            }
            return rb;
        }


        /// <summary>
        /// 
        /// Get Brand List
        /// </summary>
        /// <returns></returns>
        public async Task<ReturnDataTable> GetBrand(Int64 brandId, Int16 active)
        {
            string query = "";
            MySqlParameter[] pm = new MySqlParameter[]
           {
                new MySqlParameter("brandId", MySqlDbType.Int64) { Value = brandId},
                new MySqlParameter("active", MySqlDbType.Int16) { Value = active},
           };
            query = @"SELECT u.brandId,u.brandName,u.brandNameHindi,u.brandCategory FROM brandmaster  u
                                  WHERE  u.active=@active";
            if (brandId != 0)
                query += @" AND u.brandId=@brandId  ";
            dt = await db.ExecuteSelectQueryAsync(query, pm);

            return dt;
        }

        #endregion

        #region Unloading GatePass
        /// <summary>
        /// Save Gate Pass Unloading Entry
        /// </summary>
        /// <param name="bl"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnString> SaveUnloadingEntry(UnloadingEntry bl)
        {
            ReturnClass.ReturnString rs = await GenerateUnloadingId();
            if (rs.status)
                bl.unloadingId = rs.id;
            DlCommon dlCommon = new();
            if (rs.status)
            {

                string query = @"INSERT INTO unloadingentry (unloadingId,personName,vehicleNo,personMobileNo,
                                            vendorId,vendorName,billTNo,remark,entryTime,exitTime,active,
                                            userId,clientIp) 
										  VALUES
										  (@unloadingId,@personName,@vehicleNo,@personMobileNo,
                                            @vendorId,@vendorName,@billTNo,@remark,@entryTime,@outTime,@active,
                                            @userId,@clientIp)";

                MySqlParameter[] pm = new MySqlParameter[] {

                    new MySqlParameter("@unloadingId", MySqlDbType.Int64) { Value = bl.unloadingId},
                    new MySqlParameter("@personName", MySqlDbType.VarChar) { Value = bl.personName},
                    new MySqlParameter("@vehicleNo", MySqlDbType.VarChar) { Value = bl.vehicleNo},
                    new MySqlParameter("@personMobileNo", MySqlDbType.VarChar) { Value = bl.personMobileNo},
                    new MySqlParameter("@vendorId", MySqlDbType.Int64) { Value = bl.vendorId},
                    new MySqlParameter("@vendorName", MySqlDbType.VarChar) { Value = bl.vendorName},
                    new MySqlParameter("@billTNo", MySqlDbType.VarChar) { Value = bl.billTNo},
                    new MySqlParameter("@remark", MySqlDbType.VarChar) { Value = bl.remark},
                    new MySqlParameter("@entryTime", MySqlDbType.VarString) { Value = DateTime.Now.ToString("hh:mm tt")},
                    new MySqlParameter("@active", MySqlDbType.Int16) { Value = bl.active},
                     new MySqlParameter("@userId", MySqlDbType.Int64) { Value = bl.userId},
                      new MySqlParameter("@clientIp", MySqlDbType.String) { Value = bl.clientIp},


                };
                using (TransactionScope ts = new(TransactionScopeAsyncFlowOption.Enabled))
                {
                    rb = await db.ExecuteQueryAsync(query, pm, "SaveUnloadingEntry");
                    if (rb.status)
                    {
                        rb = await AddUnloadingItemsAsync(bl, 1);
                        if (rb.status)
                        {
                            ts.Complete();
                        }
                    }
                }
                if (rb.status)
                {
                    rs.status = true;
                    rs.message = "Unloading GatePass has been Generated.";
                }
                else
                {
                    rs = new();
                    rs.message = "Failed to Generate Unloading GatePass";
                }
            }


            return rs;
        }
        private async Task<ReturnClass.ReturnBool> AddUnloadingItemsAsync(UnloadingEntry unloadingEntry, int counter = 1)
        {
            string query = @"insert into unloadingitems(itemId, unloadingId, itemName, active,clientIp,
                                         userId)
                                  values ";
            List<MySqlParameter> pm = new();

            foreach (GatePassItem GatePassItem in unloadingEntry.GatePassItems)
            {
                query += @"(@itemId" + counter.ToString() + ", @unloadingId" + counter.ToString() + ", @itemName" + counter.ToString() +
                            ", @active" + counter.ToString() + ", @clientIp" + counter.ToString() + ", @userId" + counter.ToString() + "),";

                pm.Add(new MySqlParameter("unloadingId" + counter.ToString(), MySqlDbType.Int64) { Value = unloadingEntry.unloadingId });
                pm.Add(new MySqlParameter("itemId" + counter.ToString(), MySqlDbType.Int64) { Value = GatePassItem.itemId });
                pm.Add(new MySqlParameter("itemName" + counter.ToString(), MySqlDbType.VarString) { Value = GatePassItem.itemName });
                pm.Add(new MySqlParameter("active" + counter.ToString(), MySqlDbType.Int16) { Value = (Int16)IsActive.Yes });
                pm.Add(new MySqlParameter("clientIp" + counter.ToString(), MySqlDbType.String) { Value = unloadingEntry.clientIp });
                pm.Add(new MySqlParameter("userId" + counter.ToString(), MySqlDbType.Int64) { Value = unloadingEntry.userId });

                counter++;
            }
            query = query.TrimEnd(',');
            return await db.ExecuteQueryAsync(query, pm.ToArray(), "SaveUnloadingItemDetails");
        }

        /// <summary>
        /// Update Gatepass Uploading Entries
        /// </summary>
        /// <param name="bl"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnString> UpdateUnloadingEntry(UnloadingEntry bl)
        {
            ReturnClass.ReturnString rs = new();
            ReturnClass.ReturnBool rb = new ReturnClass.ReturnBool();

            string query = @"INSERT INTO unloadingentrylog
                                  SELECT * FROM  unloadingentry
										   WHERE unloadingId=@unloadingId";

            MySqlParameter[] pm = new MySqlParameter[] {
                    new MySqlParameter("@unloadingId", MySqlDbType.Int64) { Value = bl.unloadingId},
                    new MySqlParameter("@personName", MySqlDbType.VarChar) { Value = bl.personName},
                    new MySqlParameter("@vehicleNo", MySqlDbType.VarChar) { Value = bl.vehicleNo},
                    new MySqlParameter("@personMobileNo", MySqlDbType.VarChar) { Value = bl.personMobileNo},
                    new MySqlParameter("@vendorId", MySqlDbType.Int64) { Value = bl.vendorId},
                    new MySqlParameter("@vendorName", MySqlDbType.VarChar) { Value = bl.vendorName},
                    new MySqlParameter("@billTNo", MySqlDbType.VarChar) { Value = bl.billTNo},
                    new MySqlParameter("@remark", MySqlDbType.VarChar) { Value = bl.remark},
                    new MySqlParameter("@entryTime", MySqlDbType.VarString) { Value = DateTime.Now.ToString("hh:mm tt")},
                    new MySqlParameter("@active", MySqlDbType.Int16) { Value = bl.active},
                     new MySqlParameter("@userId", MySqlDbType.Int64) { Value = bl.userId},
                      new MySqlParameter("@clientIp", MySqlDbType.String) { Value = bl.clientIp},
                };
            using (TransactionScope ts = new(TransactionScopeAsyncFlowOption.Enabled))
            {
                rb = await db.ExecuteQueryAsync(query, pm, "Saveunloadingentrylog");
                if (rb.status)
                {
                    query = @"UPDATE unloadingentry
                                   SET   personName=@personName,vehicleNo=@vehicleNo,personMobileNo=@personMobileNo,
                                        vendorId=@vendorId,vendorName=@vendorName,billTNo=@billTNo,remark=@remark,
                                       active=@active,userId=@userId,clientIp=@clientIp 
										   WHERE unloadingId=@unloadingId";
                    // entryTime=@entryTime,
                    rb = await db.ExecuteQueryAsync(query, pm, "Updateunloadingentry");
                    if (rb.status)
                    {
                        query = @"INSERT INTO unloadingitemslog
                                  SELECT * FROM  unloadingitems
										   WHERE unloadingId=@unloadingId";
                        rb = await db.ExecuteQueryAsync(query, pm, "Updateunloadingitemslog");
                        if (rb.status)
                        {
                            query = @"DELETE FROM  unloadingitems
										   WHERE unloadingId=@unloadingId";
                            rb = await db.ExecuteQueryAsync(query, pm, "Updateunloadingitems");
                            if (rb.status)
                            {
                                rb = await AddUnloadingItemsAsync(bl, 1);
                                if (rb.status)
                                    ts.Complete();

                            }
                        }
                    }
                }
            }
            if (rb.status)
            {
                rs.status = true;
                rs.message = "Unloading GatePass has been Updated";
            }
            else
            {
                rs = new();
                rs.message = "Failed to Update Unloading GatePass";
            }
            return rs;
        }
        /// <summary>
        /// Update Gatepass Uploading Exit Time
        /// </summary>
        /// <param name="bl"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnString> UpdateUnloadingExitTime(UnloadingEntry bl)
        {
            ReturnClass.ReturnString rs = new();
            ReturnClass.ReturnBool rb = new ReturnClass.ReturnBool();

            string query = @"INSERT INTO unloadingentrylog
                                  SELECT * FROM  unloadingentry
										   WHERE unloadingId=@unloadingId";

            MySqlParameter[] pm = new MySqlParameter[] {
                    new MySqlParameter("@unloadingId", MySqlDbType.Int64) { Value = bl.unloadingId},
                    new MySqlParameter("@remark", MySqlDbType.VarChar) { Value = bl.remark},
                    new MySqlParameter("@exitTime", MySqlDbType.VarString) { Value = DateTime.Now.ToString("hh:mm tt")},
                     new MySqlParameter("@userId", MySqlDbType.Int64) { Value = bl.userId},
                      new MySqlParameter("@clientIp", MySqlDbType.String) { Value = bl.clientIp},
                };
            using (TransactionScope ts = new(TransactionScopeAsyncFlowOption.Enabled))
            {
                rb = await db.ExecuteQueryAsync(query, pm, "SaveunloadingExitTimelog");
                if (rb.status)
                {
                    query = @"UPDATE unloadingentry
                                   SET 
                                        exitTime=@exitTime,
                                        userId=@userId,clientIp=@clientIp 
										   WHERE unloadingId=@unloadingId";
                    rb = await db.ExecuteQueryAsync(query, pm, "UpdateunloadinExitTime");
                    if (rb.status)
                        ts.Complete();
                }
            }
            if (rb.status)
            {
                rs.status = true;
                rs.message = "Unloading GatePass Exit Time has been Updated";
            }
            else
            {
                rs = new();
                rs.message = "Failed to Update Unloading GatePass Exit Time";
            }
            return rs;
        }

        /// <summary>
        /// 
        /// Get GatePass Unloading List
        /// </summary>
        /// <returns>Verify OTP</returns>
        public async Task<ReturnDataSet> GetUnloadingGatePassList(GatePassSearch gatePassSearch)
        {
            string query = "";
            ReturnDataSet ds = new();
            gatePassSearch.id = gatePassSearch.id == null ? 0 : gatePassSearch.id;
            gatePassSearch.vendorId = gatePassSearch.vendorId == null ? 0 : gatePassSearch.vendorId;
            //gatePassSearch.fromDate = gatePassSearch.fromDate == null ? "" : gatePassSearch.fromDate;
            //gatePassSearch.toDate = gatePassSearch.toDate == null ? "" : gatePassSearch.toDate;
            if (gatePassSearch.fromDate != string.Empty)
                gatePassSearch.fromDate = Convert.ToDateTime(gatePassSearch.fromDate.ToString()).ToString("yyyy/MM/dd");
            if (gatePassSearch.toDate != string.Empty)
                gatePassSearch.toDate = Convert.ToDateTime(gatePassSearch.toDate.ToString()).ToString("yyyy/MM/dd");

            MySqlParameter[] pm = new MySqlParameter[]
           {
                new MySqlParameter("unloadingId", MySqlDbType.Int64) { Value = gatePassSearch.id},
                new MySqlParameter("active", MySqlDbType.Int16) { Value = (Int16)IsActive.Yes},
                new MySqlParameter("vehicleNo", MySqlDbType.String) { Value = gatePassSearch.vehicleNo},
                new MySqlParameter("personMobileNo", MySqlDbType.String) { Value = gatePassSearch.personMobileNo},
                new MySqlParameter("vendorId", MySqlDbType.Int32) { Value = gatePassSearch.vendorId},
                new MySqlParameter("billTNo", MySqlDbType.String) { Value = gatePassSearch.billTNo},
                new MySqlParameter("fromDate", MySqlDbType.DateTime) { Value = gatePassSearch.fromDate},
                new MySqlParameter("toDate", MySqlDbType.DateTime) { Value = gatePassSearch.toDate},
           };
            String WHERE = "";

            if (gatePassSearch.id > 0)
                WHERE += @" AND u.unloadingId=@unloadingId ";

            if (gatePassSearch.vehicleNo != string.Empty)
                WHERE += @" AND u.vehicleNo=@vehicleNo ";

            if (gatePassSearch.personMobileNo != string.Empty)
                WHERE += @" AND u.personMobileNo=@personMobileNo ";

            if (gatePassSearch.vendorId > 0)
                WHERE += @" AND u.vendorId=@vendorId ";

            if (gatePassSearch.billTNo != string.Empty)
                WHERE += @" AND u.billTNo=@billTNo ";
            //gatePassSearch.fromDate = gatePassSearch.fromDate == null ? string.Empty : gatePassSearch.fromDate;
            //gatePassSearch.toDate = gatePassSearch.toDate == null ? string.Empty : gatePassSearch.toDate;
            if (gatePassSearch.fromDate != string.Empty && gatePassSearch.toDate != string.Empty)
            {
                if (gatePassSearch.fromDate == gatePassSearch.toDate)
                    WHERE += @" AND DATE_FORMAT(u.creationTimeStamp,'%d/%m/%Y') BETWEEN  DATE_FORMAT(fromDate,'%d/%m/%Y') AND DATE_FORMAT(toDate,'%d/%m/%Y') ";
                else
                    WHERE += @" AND DATE_FORMAT(u.creationTimeStamp,'%d/%m/%Y') = DATE_FORMAT(fromDate,'%d/%m/%Y')  ";
            }


            query = @"SELECT u.unloadingId,u.personName,u.vehicleNo,u.personMobileNo,u.vendorId,
                            u.vendorName,u.billTNo,u.remark,
                            u.entryTime,u.exitTime
                             FROM unloadingentry u 
                             WHERE u.active=@active " + WHERE + @"
                            ORDER BY u.creationTimeStamp DESC ";
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            ds.status = true;

            if (dt.table.Rows.Count > 0)
            {

                dt.table.TableName = "Unloading_List";
                ds.dataset.Tables.Add(dt.table);
                query = @"SELECT e.itemId,e.unloadingId,e.itemName
                             FROM unloadingitems e 
                           WHERE e.active=@active ";
                dt = await db.ExecuteSelectQueryAsync(query, pm);
                if (dt.table.Rows.Count > 0)
                {
                    ds.status = true;
                    dt.table.TableName = "Unloading_Items";
                    ds.dataset.Tables.Add(dt.table);
                }
            }
            else
            {
                dt.table.TableName = "Unloading_List";
                ds.dataset.Tables.Add(dt.table);
            }
            return ds;
        }
        /// <summary>
        /// Returns Unloading Id in the format 2+YYMMDD+ NNN
        /// </summary>
        /// <returns></returns>
        private async Task<ReturnClass.ReturnString> GenerateUnloadingId()
        {
            ReturnClass.ReturnString rs = new();
            string query = @"SELECT IFNULL(MAX(SUBSTRING(e.unloadingId,8,11)),0) + 1 AS  unloadingId
                             FROM unloadingentry e 
                                WHERE  
                                DATE_FORMAT(e.creationTimeStamp,'%d/%m/%Y') = DATE_FORMAT(NOW(),'%d/%m/%Y');";
            dt = await db.ExecuteSelectQueryAsync(query);
            if (dt.table.Rows.Count > 0)
            {
                // ID Format = P(2) YY NNN NNN N
                string id = ((int)PrefixId.Unloading).ToString() + DateTime.Now.ToString("yyMMdd") + dt.table.Rows[0]["unloadingId"].ToString().PadLeft(3, '0');
                rs.id = Convert.ToInt64(id);
                rs.status = true;
            }
            return rs;
        }

        #endregion

        #region  Loading GatePass
        /// <summary>
        /// Save Gate Pass Loading Entry
        /// </summary>
        /// <param name="bl"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnString> SaveLoadingEntry(LoadingEntry bl)
        {
            ReturnClass.ReturnString rs = await GenerateLoadingId();
            if (rs.status)
                bl.loadingId = rs.id;
            DlCommon dlCommon = new();
            if (rs.status)
            {

                string query = @"INSERT INTO loadingentry (loadingId,personName,vehicleNo,personMobileNo,
                                            vendorId,vendorName,billTNo,remark,entryTime,active,
                                            userId,clientIp) 
										  VALUES
										  (@loadingId,@personName,@vehicleNo,@personMobileNo,
                                            @vendorId,@vendorName,@billTNo,@remark,@entryTime,@active,
                                            @userId,@clientIp)";

                MySqlParameter[] pm = new MySqlParameter[] {

                    new MySqlParameter("@loadingId", MySqlDbType.Int64) { Value = bl.loadingId},
                    new MySqlParameter("@personName", MySqlDbType.VarChar) { Value = bl.personName},
                    new MySqlParameter("@vehicleNo", MySqlDbType.VarChar) { Value = bl.vehicleNo},
                    new MySqlParameter("@personMobileNo", MySqlDbType.VarChar) { Value = bl.personMobileNo},
                    new MySqlParameter("@vendorId", MySqlDbType.Int64) { Value = bl.vendorId},
                    new MySqlParameter("@vendorName", MySqlDbType.VarChar) { Value = bl.vendorName},
                    new MySqlParameter("@billTNo", MySqlDbType.VarChar) { Value = bl.billTNo},
                    new MySqlParameter("@remark", MySqlDbType.VarChar) { Value = bl.remark},
                    new MySqlParameter("@entryTime", MySqlDbType.VarString) { Value = DateTime.Now.ToString("hh:mm tt")},
                    new MySqlParameter("@active", MySqlDbType.Int16) { Value = bl.active},
                     new MySqlParameter("@userId", MySqlDbType.Int64) { Value = bl.userId},
                      new MySqlParameter("@clientIp", MySqlDbType.String) { Value = bl.clientIp},


                };
                using (TransactionScope ts = new(TransactionScopeAsyncFlowOption.Enabled))
                {
                    rb = await db.ExecuteQueryAsync(query, pm, "SaveLoadingEntry");
                    if (rb.status)
                    {
                        //rb = await AddLoadingItemsAsync(bl, 1);
                        //if (rb.status)
                        //{
                        ts.Complete();
                        //}
                    }
                }
                if (rb.status)
                {
                    rs.status = true;
                    rs.message = "Loading GatePass has been Generated.";
                }
                else
                {
                    rs = new();
                    rs.message = "Failed to Generate Loading GatePass";
                }
            }


            return rs;
        }
        private async Task<ReturnClass.ReturnBool> AddLoadingItemsAsync(LoadingEntry LoadingEntry, int counter = 1)
        {
            string query = @"insert into loadingitems(itemId, loadingId, itemName, active,clientIp,
                                         userId)
                                  values ";
            List<MySqlParameter> pm = new();

            foreach (GatePassItem GatePassItem in LoadingEntry.GatePassItems)
            {
                query += @"(@itemId" + counter.ToString() + ", @loadingId" + counter.ToString() + ", @itemName" + counter.ToString() +
                            ", @active" + counter.ToString() + ", @clientIp" + counter.ToString() + ", @userId" + counter.ToString() + "),";

                pm.Add(new MySqlParameter("loadingId" + counter.ToString(), MySqlDbType.Int64) { Value = LoadingEntry.loadingId });
                pm.Add(new MySqlParameter("itemId" + counter.ToString(), MySqlDbType.Int64) { Value = GatePassItem.itemId });
                pm.Add(new MySqlParameter("itemName" + counter.ToString(), MySqlDbType.VarString) { Value = GatePassItem.itemName });
                pm.Add(new MySqlParameter("active" + counter.ToString(), MySqlDbType.Int16) { Value = (Int16)IsActive.Yes });
                pm.Add(new MySqlParameter("clientIp" + counter.ToString(), MySqlDbType.String) { Value = LoadingEntry.clientIp });
                pm.Add(new MySqlParameter("userId" + counter.ToString(), MySqlDbType.Int64) { Value = LoadingEntry.userId });

                counter++;
            }
            query = query.TrimEnd(',');
            return await db.ExecuteQueryAsync(query, pm.ToArray(), "SaveLoadingItemDetails");
        }

        /// <summary>
        /// Update Gatepass Loading Entries
        /// </summary>
        /// <param name="bl"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnString> UpdateLoadingEntry(LoadingEntry bl)
        {
            ReturnClass.ReturnString rs = new();
            ReturnClass.ReturnBool rb = new ReturnClass.ReturnBool();

            string query = @"INSERT INTO loadingentrylog
                                  SELECT * FROM  loadingentry
										   WHERE loadingId=@loadingId";
            MySqlParameter[] pm = new MySqlParameter[] {
                    new MySqlParameter("@loadingId", MySqlDbType.Int64) { Value = bl.loadingId},
                    new MySqlParameter("@personName", MySqlDbType.VarChar) { Value = bl.personName},
                    new MySqlParameter("@vehicleNo", MySqlDbType.VarChar) { Value = bl.vehicleNo},
                    new MySqlParameter("@personMobileNo", MySqlDbType.VarChar) { Value = bl.personMobileNo},
                    new MySqlParameter("@vendorId", MySqlDbType.Int64) { Value = bl.vendorId},
                    new MySqlParameter("@vendorName", MySqlDbType.VarChar) { Value = bl.vendorName},
                    new MySqlParameter("@billTNo", MySqlDbType.VarChar) { Value = bl.billTNo},
                    new MySqlParameter("@remark", MySqlDbType.VarChar) { Value = bl.remark},
                    new MySqlParameter("@entryTime", MySqlDbType.VarString) { Value = DateTime.Now.ToString("hh:mm tt")},
                    new MySqlParameter("@active", MySqlDbType.Int16) { Value = bl.active},
                     new MySqlParameter("@userId", MySqlDbType.Int64) { Value = bl.userId},
                      new MySqlParameter("@clientIp", MySqlDbType.String) { Value = bl.clientIp},
                };
            using (TransactionScope ts = new(TransactionScopeAsyncFlowOption.Enabled))
            {
                rb = await db.ExecuteQueryAsync(query, pm, "SaveLoadingentrylog");
                if (rb.status)
                {
                    query = @"UPDATE loadingentry
                                   SET   personName=@personName,vehicleNo=@vehicleNo,personMobileNo=@personMobileNo,
                                        vendorId=@vendorId,vendorName=@vendorName,billTNo=@billTNo,remark=@remark,
                                        active=@active,userId=@userId,clientIp=@clientIp 
										   WHERE loadingId=@loadingId";
                    //entryTime=@entryTime,
                    rb = await db.ExecuteQueryAsync(query, pm, "Updateloadingentry");
                    if (rb.status)
                    {
                        //           query = @"INSERT INTO loadingitemslog
                        //                     SELECT * FROM  loadingitems
                        //WHERE loadingId=@loadingId";
                        //           rb = await db.ExecuteQueryAsync(query, pm, "Updateloadingitemslog");
                        //           if (rb.status)
                        //           {
                        //               query = @"DELETE FROM  loadingitems
                        //WHERE loadingId=@loadingId";
                        //               rb = await db.ExecuteQueryAsync(query, pm, "Updateloadingitems");
                        //               if (rb.status)
                        //               {
                        //                   rb = await AddLoadingItemsAsync(bl, 1);
                        //                   if (rb.status)
                        ts.Complete();
                        //               }
                        //           }
                    }
                }
            }
            if (rb.status)
            {
                rs.status = true;
                rs.message = "Loading GatePass has been Updated";
            }
            else
            {
                rs = new();
                rs.message = "Failed to Update Loading GatePass";
            }
            return rs;
        }
        /// <summary>
        /// Update Gatepass Loading Exit Time
        /// </summary>
        /// <param name="bl"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnString> UpdateLoadingExitTime(LoadingEntry bl)
        {
            ReturnClass.ReturnString rs = new();
            ReturnClass.ReturnBool rb = new ReturnClass.ReturnBool();

            string query = @"INSERT INTO loadingentrylog
                                  SELECT * FROM  loadingentry
										   WHERE loadingId=@loadingId";

            MySqlParameter[] pm = new MySqlParameter[] {
                    new MySqlParameter("@loadingId", MySqlDbType.Int64) { Value = bl.loadingId},
                    new MySqlParameter("@remark", MySqlDbType.VarChar) { Value = bl.remark},
                   new MySqlParameter("@billTNo", MySqlDbType.VarChar) { Value = bl.billTNo},
                    new MySqlParameter("@exitTime", MySqlDbType.VarString) { Value = DateTime.Now.ToString("hh:mm tt")},
                     new MySqlParameter("@userId", MySqlDbType.Int64) { Value = bl.userId},
                      new MySqlParameter("@clientIp", MySqlDbType.String) { Value = bl.clientIp},
                };
            using (TransactionScope ts = new(TransactionScopeAsyncFlowOption.Enabled))
            {
                rb = await db.ExecuteQueryAsync(query, pm, "SaveloadingExitTimelog");
                if (rb.status)
                {
                    query = @"UPDATE loadingentry
                                   SET 
                                        exitTime=@exitTime,billTNo=@billTNo,
                                        userId=@userId,clientIp=@clientIp 
										   WHERE loadingId=@loadingId";
                    rb = await db.ExecuteQueryAsync(query, pm, "UpdateloadinExitTime");
                    if (rb.status)
                    {
                        query = @"INSERT INTO loadingitemslog
                                  SELECT * FROM  loadingitems
										   WHERE loadingId=@loadingId";
                        rb = await db.ExecuteQueryAsync(query, pm, "Updateloadingitemslog");
                        if (rb.status)
                        {
                            query = @"DELETE FROM  loadingitems
										   WHERE loadingId=@loadingId";
                            rb = await db.ExecuteQueryAsync(query, pm, "Updateloadingitems");
                            if (rb.status)
                            {
                                rb = await AddLoadingItemsAsync(bl, 1);
                                if (rb.status)
                                    ts.Complete();

                            }
                        }
                    }
                }
            }
            if (rb.status)
            {
                rs.status = true;
                rs.message = "Loading GatePass Exit Time has been Updated";
            }
            else
            {
                rs = new();
                rs.message = "Failed to Update Loading GatePass Exit Time";
            }
            return rs;
        }

        /// <summary>
        /// 
        /// Get GatePass loading List
        /// </summary>
        /// <returns>Verify OTP</returns>
        public async Task<ReturnDataSet> GetLoadingGatePassList(GatePassSearch gatePassSearch)
        {
            string query = "";
            ReturnDataSet ds = new();
            gatePassSearch.id = gatePassSearch.id == null ? 0 : gatePassSearch.id;
            gatePassSearch.vendorId = gatePassSearch.vendorId == null ? 0 : gatePassSearch.vendorId;
            gatePassSearch.fromDate = gatePassSearch.fromDate == null ? "" : gatePassSearch.fromDate;
            gatePassSearch.toDate = gatePassSearch.toDate == null ? "" : gatePassSearch.toDate;
            if (gatePassSearch.fromDate != string.Empty)
                gatePassSearch.fromDate = Convert.ToDateTime(gatePassSearch.fromDate.ToString()).ToString("yyyy/MM/dd");
            if (gatePassSearch.toDate != string.Empty)
                gatePassSearch.toDate = Convert.ToDateTime(gatePassSearch.toDate.ToString()).ToString("yyyy/MM/dd");

            MySqlParameter[] pm = new MySqlParameter[]
           {
                new MySqlParameter("loadingId", MySqlDbType.Int64) { Value = gatePassSearch.id},
                new MySqlParameter("active", MySqlDbType.Int16) { Value = (Int16)IsActive.Yes},
                new MySqlParameter("vehicleNo", MySqlDbType.String) { Value = gatePassSearch.vehicleNo},
                new MySqlParameter("personMobileNo", MySqlDbType.String) { Value = gatePassSearch.personMobileNo},
                new MySqlParameter("vendorId", MySqlDbType.Int32) { Value = gatePassSearch.vendorId},
                new MySqlParameter("billTNo", MySqlDbType.String) { Value = gatePassSearch.billTNo},
                new MySqlParameter("fromDate", MySqlDbType.DateTime) { Value = gatePassSearch.fromDate},
                new MySqlParameter("toDate", MySqlDbType.DateTime) { Value = gatePassSearch.toDate},
           };
            String WHERE = "";

            if (gatePassSearch.id > 0)
                WHERE += @" AND u.loadingId=@loadingId ";
            if (gatePassSearch.vehicleNo != string.Empty)
                WHERE += @" AND u.vehicleNo=@vehicleNo ";
            if (gatePassSearch.personMobileNo != string.Empty)
                WHERE += @" AND u.personMobileNo=@personMobileNo ";

            if (gatePassSearch.vendorId > 0)
                WHERE += @" AND u.vendorId=@vendorId ";
            if (gatePassSearch.billTNo != string.Empty)
                WHERE += @" AND u.billTNo=@billTNo ";
            if (gatePassSearch.fromDate != string.Empty && gatePassSearch.toDate != string.Empty)
            {
                if (gatePassSearch.fromDate == gatePassSearch.toDate)
                    WHERE += @" AND DATE_FORMAT(u.creationTimeStamp,'%d/%m/%Y') BETWEEN  DATE_FORMAT(fromDate,'%d/%m/%Y') AND DATE_FORMAT(toDate,'%d/%m/%Y') ";
                else
                    WHERE += @" AND DATE_FORMAT(u.creationTimeStamp,'%d/%m/%Y') = DATE_FORMAT(fromDate,'%d/%m/%Y')  ";
            }
            query = @"SELECT u.loadingId,u.personName,u.vehicleNo,u.personMobileNo,u.vendorId,
                            u.vendorName,u.billTNo,u.remark,
                            u.entryTime,u.exitTime
                             FROM loadingentry u 
                             WHERE u.active=@active " + WHERE + @"
                            ORDER BY u.creationTimeStamp DESC ";
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            ds.status = true;

            if (dt.table.Rows.Count > 0)
            {

                dt.table.TableName = "Loading_List";
                ds.dataset.Tables.Add(dt.table);
                query = @"SELECT e.itemId,e.loadingId,e.itemName
                             FROM loadingitems e 
                           WHERE e.active=@active ";
                dt = await db.ExecuteSelectQueryAsync(query, pm);
                if (dt.table.Rows.Count > 0)
                {
                    ds.status = true;
                    dt.table.TableName = "Loading_Items";
                    ds.dataset.Tables.Add(dt.table);
                }
            }
            else
            {
                dt.table.TableName = "Loading_List";
                ds.dataset.Tables.Add(dt.table);
            }
            return ds;
        }
        /// <summary>
        /// Returns Unloading Id in the format 3+YYMMDD+ NNN
        /// </summary>
        /// <returns></returns>
        private async Task<ReturnClass.ReturnString> GenerateLoadingId()
        {
            ReturnClass.ReturnString rs = new();
            string query = @"SELECT IFNULL(MAX(SUBSTRING(e.loadingId,8,11)),0) + 1 AS  loadingId
                             FROM loadingentry e 
                                WHERE  
                                DATE_FORMAT(e.creationTimeStamp,'%d/%m/%Y') = DATE_FORMAT(NOW(),'%d/%m/%Y');";
            dt = await db.ExecuteSelectQueryAsync(query);
            if (dt.table.Rows.Count > 0)
            {
                // ID Format = P(2) YY NNN NNN N
                string id = ((int)PrefixId.Loading).ToString() + DateTime.Now.ToString("yyMMdd") + dt.table.Rows[0]["loadingId"].ToString().PadLeft(3, '0');
                rs.id = Convert.ToInt64(id);
                rs.status = true;
            }
            return rs;
        }

        #endregion

        #region Visitor GatePass
        /// <summary>
        /// Save Gate Pass Loading Entry
        /// </summary>
        /// <param name="bl"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnString> SaveVisitorEntry(VisitorEntry bl)
        {
            ReturnClass.ReturnString rs = await GenerateVisitorId();
            if (rs.status)
                bl.visitorId = rs.id;
            DlCommon dlCommon = new();
            if (rs.status)
            {

                string query = @"INSERT INTO visitorentry (visitorId,personName,vehicleNo,personMobileNo,
                                      purpose,remark,entryTime,active,
                                      userId,clientIp) 
							  VALUES
							  (@visitorId,@personName,@vehicleNo,@personMobileNo,
                                      @purpose,@remark,@entryTime,@active,
                                      @userId,@clientIp)";

                MySqlParameter[] pm = new MySqlParameter[] {

              new MySqlParameter("@visitorId", MySqlDbType.Int64) { Value = bl.visitorId},
              new MySqlParameter("@personName", MySqlDbType.VarChar) { Value = bl.personName},
              new MySqlParameter("@vehicleNo", MySqlDbType.VarChar) { Value = bl.vehicleNo},
              new MySqlParameter("@personMobileNo", MySqlDbType.VarChar) { Value = bl.personMobileNo},
              new MySqlParameter("@remark", MySqlDbType.VarChar) { Value = bl.remark},
               new MySqlParameter("@purpose", MySqlDbType.VarChar) { Value = bl.purpose},
              new MySqlParameter("@entryTime", MySqlDbType.VarString) { Value = DateTime.Now.ToString("hh:mm tt")},
              new MySqlParameter("@active", MySqlDbType.Int16) { Value = bl.active},
               new MySqlParameter("@userId", MySqlDbType.Int64) { Value = bl.userId},
                new MySqlParameter("@clientIp", MySqlDbType.String) { Value = bl.clientIp},


          };
                rb = await db.ExecuteQueryAsync(query, pm, "SaveLoadingEntry");


                if (rb.status)
                {
                    rs.status = true;
                    rs.message = "Visitor GatePass has been Generated.";
                }
                else
                {
                    rs = new();
                    rs.message = "Failed to Generate Visitor GatePass";
                }
            }


            return rs;
        }

        /// <summary>
        /// Update Gatepass Loading Entries
        /// </summary>
        /// <param name="bl"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnString> UpdateVisitorEntry(VisitorEntry bl)
        {
            ReturnClass.ReturnString rs = new();
            ReturnClass.ReturnBool rb = new ReturnClass.ReturnBool();

            string query = @"INSERT INTO visitorentrylog
                            SELECT * FROM  visitorentry
							   WHERE visitorId=@visitorId";

            MySqlParameter[] pm = new MySqlParameter[] {
              new MySqlParameter("@visitorId", MySqlDbType.Int64) { Value = bl.visitorId},
              new MySqlParameter("@personName", MySqlDbType.VarChar) { Value = bl.personName},
              new MySqlParameter("@vehicleNo", MySqlDbType.VarChar) { Value = bl.vehicleNo},
              new MySqlParameter("@personMobileNo", MySqlDbType.VarChar) { Value = bl.personMobileNo},
              new MySqlParameter("@remark", MySqlDbType.VarChar) { Value = bl.remark},
              new MySqlParameter("@purpose", MySqlDbType.VarChar) { Value = bl.purpose},
              new MySqlParameter("@entryTime", MySqlDbType.VarString) { Value = DateTime.Now.ToString("hh:mm tt")},
              new MySqlParameter("@active", MySqlDbType.Int16) { Value = bl.active},
               new MySqlParameter("@userId", MySqlDbType.Int64) { Value = bl.userId},
                new MySqlParameter("@clientIp", MySqlDbType.String) { Value = bl.clientIp},
          };
            using (TransactionScope ts = new(TransactionScopeAsyncFlowOption.Enabled))
            {
                rb = await db.ExecuteQueryAsync(query, pm, "SaveLoadingentrylog");
                if (rb.status)
                {
                    query = @"UPDATE visitorentry
                             SET   personName=@personName,vehicleNo=@vehicleNo,personMobileNo=@personMobileNo,
                                  remark=@remark,purpose=@purpose,
                                  active=@active,userId=@userId,clientIp=@clientIp 
							   WHERE visitorId=@visitorId";
                    // entryTime = @entryTime,
                    rb = await db.ExecuteQueryAsync(query, pm, "Updatevisitorentry");
                    if (rb.status)
                        ts.Complete();


                }
            }
            if (rb.status)
            {
                rs.status = true;
                rs.message = "Visitor GatePass has been Updated";
            }
            else
            {
                rs = new();
                rs.message = "Failed to Update Visitor GatePass";
            }
            return rs;
        }
        /// <summary>
        /// Update Gatepass Loading Exit Time
        /// </summary>
        /// <param name="bl"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnString> UpdateVisitorExitTime(VisitorEntry bl)
        {
            ReturnClass.ReturnString rs = new();
            ReturnClass.ReturnBool rb = new ReturnClass.ReturnBool();

            string query = @"INSERT INTO visitorentrylog
                            SELECT * FROM  visitorentry
							   WHERE visitorId=@visitorId";

            MySqlParameter[] pm = new MySqlParameter[] {
              new MySqlParameter("@visitorId", MySqlDbType.Int64) { Value = bl.visitorId},
              new MySqlParameter("@remark", MySqlDbType.VarChar) { Value = bl.remark},
              new MySqlParameter("@exitTime", MySqlDbType.VarString) { Value = DateTime.Now.ToString("hh:mm tt")},
               new MySqlParameter("@userId", MySqlDbType.Int64) { Value = bl.userId},
                new MySqlParameter("@clientIp", MySqlDbType.String) { Value = bl.clientIp},
          };
            using (TransactionScope ts = new(TransactionScopeAsyncFlowOption.Enabled))
            {
                rb = await db.ExecuteQueryAsync(query, pm, "SaveloadingExitTimelog");
                if (rb.status)
                {
                    query = @"UPDATE visitorentry
                             SET 
                                  exitTime=@exitTime,
                                  userId=@userId,clientIp=@clientIp 
							   WHERE visitorId=@visitorId";
                    rb = await db.ExecuteQueryAsync(query, pm, "UpdateloadinExitTime");
                    if (rb.status)
                        ts.Complete();
                }
            }
            if (rb.status)
            {
                rs.status = true;
                rs.message = "Visitor GatePass Exit Time has been Updated";
            }
            else
            {
                rs = new();
                rs.message = "Failed to Update Visitor GatePass Exit Time";
            }
            return rs;
        }

        /// <summary>
        /// 
        /// Get GatePass Visitor List
        /// </summary>
        /// <returns>Verify OTP</returns>
        public async Task<ReturnDataSet> GetVisitorGatePassList(GatePassSearch gatePassSearch)
        {
            string query = "";
            ReturnDataSet ds = new();
            gatePassSearch.id = gatePassSearch.id == null ? 0 : gatePassSearch.id;
            gatePassSearch.vendorId = gatePassSearch.vendorId == null ? 0 : gatePassSearch.vendorId;
            gatePassSearch.fromDate = gatePassSearch.fromDate == null ? "" : gatePassSearch.fromDate;
            gatePassSearch.toDate = gatePassSearch.toDate == null ? "" : gatePassSearch.toDate;
            if (gatePassSearch.fromDate != string.Empty)
                gatePassSearch.fromDate = Convert.ToDateTime(gatePassSearch.fromDate.ToString()).ToString("yyyy/MM/dd");
            if (gatePassSearch.toDate != string.Empty)
                gatePassSearch.toDate = Convert.ToDateTime(gatePassSearch.toDate.ToString()).ToString("yyyy/MM/dd");

            MySqlParameter[] pm = new MySqlParameter[]
           {
          new MySqlParameter("visitorId", MySqlDbType.Int64) { Value = gatePassSearch.id},
          new MySqlParameter("active", MySqlDbType.Int16) { Value = (Int16)IsActive.Yes},
          new MySqlParameter("vehicleNo", MySqlDbType.String) { Value = gatePassSearch.vehicleNo},
          new MySqlParameter("personMobileNo", MySqlDbType.String) { Value = gatePassSearch.personMobileNo},
          new MySqlParameter("vendorId", MySqlDbType.Int32) { Value = gatePassSearch.vendorId},
          new MySqlParameter("fromDate", MySqlDbType.DateTime) { Value = gatePassSearch.fromDate},
          new MySqlParameter("toDate", MySqlDbType.DateTime) { Value = gatePassSearch.toDate},
           };
            String WHERE = "";

            if (gatePassSearch.id > 0)
                WHERE += @" AND u.visitorId=@visitorId ";

            if (gatePassSearch.vehicleNo != string.Empty)
                WHERE += @" AND u.vehicleNo=@vehicleNo ";
            if (gatePassSearch.personMobileNo != string.Empty)
                WHERE += @" AND u.personMobileNo=@personMobileNo ";
            if (gatePassSearch.fromDate != string.Empty && gatePassSearch.toDate != string.Empty)
            {
                if (gatePassSearch.fromDate == gatePassSearch.toDate)
                    WHERE += @" AND DATE_FORMAT(u.creationTimeStamp,'%d/%m/%Y') BETWEEN  DATE_FORMAT(fromDate,'%d/%m/%Y') AND DATE_FORMAT(toDate,'%d/%m/%Y') ";
                else
                    WHERE += @" AND DATE_FORMAT(u.creationTimeStamp,'%d/%m/%Y') = DATE_FORMAT(fromDate,'%d/%m/%Y')  ";
            }
            query = @"SELECT u.visitorId,u.personName,u.vehicleNo,u.personMobileNo,u.purpose,u.remark,
                      u.entryTime,u.exitTime
                       FROM visitorentry u 
                       WHERE u.active=@active " + WHERE + @"
                      ORDER BY u.creationTimeStamp DESC ";
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            ds.status = true;
            dt.table.TableName = "visitor_List";
            ds.dataset.Tables.Add(dt.table);

            return ds;
        }
        /// <summary>
        /// Returns Unloading Id in the format 1+YYMMDD+ NNN
        /// </summary>
        /// <returns></returns>
        private async Task<ReturnClass.ReturnString> GenerateVisitorId()
        {
            ReturnClass.ReturnString rs = new();
            string query = @"SELECT IFNULL(MAX(SUBSTRING(e.visitorId,8,11)),0) + 1 AS  visitorId
                       FROM visitorentry e 
                          WHERE  
                          DATE_FORMAT(e.creationTimeStamp,'%d/%m/%Y') = DATE_FORMAT(NOW(),'%d/%m/%Y');";
            dt = await db.ExecuteSelectQueryAsync(query);
            if (dt.table.Rows.Count > 0)
            {
                // ID Format = P(2) YY NNN NNN N
                string id = ((int)PrefixId.Visitor).ToString() + DateTime.Now.ToString("yyMMdd") + dt.table.Rows[0]["visitorId"].ToString().PadLeft(3, '0');
                rs.id = Convert.ToInt64(id);
                rs.status = true;
            }
            return rs;
        }

        #endregion

        #region Manage Row Materials Stock
        /// <summary>
        /// 
        /// Get RowMaterial List to Stock
        /// </summary>
        /// <returns>RowMaterial List</returns>
        public async Task<ReturnDataSet> GetRowMaterialListToStock(GatePassSearch gatePassSearch)
        {
            string query = "";
            ReturnDataSet ds = new();
            gatePassSearch.id = gatePassSearch.id == null ? 0 : gatePassSearch.id;
            gatePassSearch.vendorId = gatePassSearch.vendorId == null ? 0 : gatePassSearch.vendorId;
            gatePassSearch.fromDate = gatePassSearch.fromDate == null ? "" : gatePassSearch.fromDate;
            gatePassSearch.toDate = gatePassSearch.toDate == null ? "" : gatePassSearch.toDate;
            if (gatePassSearch.fromDate != string.Empty)
                gatePassSearch.fromDate = Convert.ToDateTime(gatePassSearch.fromDate.ToString()).ToString("yyyy/MM/dd");
            if (gatePassSearch.toDate != string.Empty)
                gatePassSearch.toDate = Convert.ToDateTime(gatePassSearch.toDate.ToString()).ToString("yyyy/MM/dd");

            MySqlParameter[] pm = new MySqlParameter[]
           {
          new MySqlParameter("visitorId", MySqlDbType.Int64) { Value = gatePassSearch.id},
          new MySqlParameter("active", MySqlDbType.Int16) { Value = (Int16)IsActive.Yes},
          new MySqlParameter("vehicleNo", MySqlDbType.String) { Value = gatePassSearch.vehicleNo},
          new MySqlParameter("personMobileNo", MySqlDbType.String) { Value = gatePassSearch.personMobileNo},
          new MySqlParameter("vendorId", MySqlDbType.Int32) { Value = gatePassSearch.vendorId},
          new MySqlParameter("fromDate", MySqlDbType.DateTime) { Value = gatePassSearch.fromDate},
          new MySqlParameter("toDate", MySqlDbType.DateTime) { Value = gatePassSearch.toDate},
           };
            String WHERE = "";

            if (gatePassSearch.id > 0)
                WHERE += @" AND u.visitorId=@visitorId ";

            if (gatePassSearch.vehicleNo != string.Empty)
                WHERE += @" AND u.vehicleNo=@vehicleNo ";
            if (gatePassSearch.personMobileNo != string.Empty)
                WHERE += @" AND u.personMobileNo=@personMobileNo ";
            if (gatePassSearch.fromDate != string.Empty && gatePassSearch.toDate != string.Empty)
            {
                if (gatePassSearch.fromDate == gatePassSearch.toDate)
                    WHERE += @" AND DATE_FORMAT(u.creationTimeStamp,'%d/%m/%Y') BETWEEN  DATE_FORMAT(fromDate,'%d/%m/%Y') AND DATE_FORMAT(toDate,'%d/%m/%Y') ";
                else
                    WHERE += @" AND DATE_FORMAT(u.creationTimeStamp,'%d/%m/%Y') = DATE_FORMAT(fromDate,'%d/%m/%Y')  ";
            }
            query = @"SELECT u.unloadingId,u.personName,u.vehicleNo,u.billTNo,DATE_FORMAT(u.creationTimeStamp,'%d/%m/%Y') AS gatePassDate ,
                            u.vendorId,u.vendorName,ui.itemId,ui.itemName
                            FROM unloadingentry u 
                            JOIN unloadingitems ui ON ui.unloadingId=u.unloadingId AND ui.active=@active
                            WHERE u.unloadingId NOT IN (SELECT i.unloadingId FROM itemstockdetail i )
                                AND u.active=@active " + WHERE + @"
                      ORDER BY u.creationTimeStamp DESC ";
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            ds.status = true;

            dt.table.TableName = "list";
            ds.dataset.Tables.Add(dt.table);

            return ds;
        }

        /// <summary>
        /// Save RowMaterial In Stock
        /// </summary>
        /// <param name="itemStock"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnString> SaveRowMaterialInStock(List<ItemStock> itemStock)
        {
            bool isItemExistsInStock = false;
            ReturnClass.ReturnString rs = await ItemExistsInStock((long)itemStock[0].unloadingId);
            isItemExistsInStock = rs.status;

            rs = await GenerateItemStockId();
            Int64 ItemStockId = 0;
            if (rs.status)
                ItemStockId = rs.id;

            ReturnDataTable dtExistData = new();
            DlCommon dlCommon = new();
            if (rs.status)
            {
                MySqlParameter[] pm = new MySqlParameter[] {

                    new MySqlParameter("@unloadingId", MySqlDbType.Int64) { Value = itemStock[0].unloadingId}
                };

                if (isItemExistsInStock)
                {
                    //dtExistData = await GetItemStockForUpdate((long)itemStock[0].unloadingId!);
                }
                string query = @"INSERT INTO itemstockdetaillog
                                    SELECT * FROM itemstockdetail i
                                    WHERE i.unloadingId = @unloadingId; ";
                using (TransactionScope ts = new(TransactionScopeAsyncFlowOption.Enabled))
                {
                    if (isItemExistsInStock)
                    {
                        //Update
                        rb = await db.ExecuteQueryAsync(query, pm, "Saveitemstockdetaillog");
                        if (rb.status)
                        {
                            query = @"DELETE FROM itemstockdetail 
                                    WHERE unloadingId = @unloadingId; ";
                            if (rb.status)
                                rb = await db.ExecuteQueryAsync(query, pm, "Deleteitemstockdetail");
                        }
                    }
                    else
                        rb.status = true;
                    if (rb.status)
                    {
                        rb = await AddItemInStockAsync(itemStock, ItemStockId, isItemExistsInStock, 1);
                        if (rb.status)
                            ts.Complete();
                    }
                }
                if (rb.status)
                {
                    rs.status = true;
                    rs.message = "Stock Added.";
                }
                else
                {
                    rs = new();
                    rs.message = "Failed to Save Stock";
                }
            }


            return rs;
        }
        /// <summary>
        /// Returns Item Stock Id in the format YYMM NNN NNN 
        /// </summary>
        /// <returns></returns>
        private async Task<ReturnClass.ReturnString> GenerateItemStockId()
        {
            ReturnClass.ReturnString rs = new();
            string query = @"SELECT IFNULL(MAX(SUBSTRING(e.itemStockId,5,10)),0) + 1 AS itemStockId
                             FROM itemstockdetail e 
                                WHERE  
                                DATE_FORMAT(e.creationTimeStamp,'%m/%Y') = DATE_FORMAT(NOW(),'%m/%Y');";
            dt = await db.ExecuteSelectQueryAsync(query);
            if (dt.table.Rows.Count > 0)
            {
                // ID Format =  YYMM NNN NNN 
                string id = DateTime.Now.ToString("yyMM") + dt.table.Rows[0]["itemStockId"].ToString().PadLeft(6, '0');
                rs.id = Convert.ToInt64(id);
                rs.status = true;
            }
            return rs;
        }
        /// <summary>
        /// Returns Item Stock Id in the format YYMM NNN NNN 
        /// </summary>
        /// <returns></returns>
        private async Task<ReturnClass.ReturnDataTable> GetItemStockForUpdate(Int64 unloadingId)
        {
            ReturnClass.ReturnString rs = new();
            string query = @"SELECT e.itemStockId,e.unloadingId,e.itemId,e.quantity
                             FROM itemstockdetail e 
                                WHERE  
                                e.unloadingId = @unloadingId LIMIT 1;";
            MySqlParameter[] pm = new MySqlParameter[] {

                    new MySqlParameter("@unloadingId", MySqlDbType.Int64) { Value = unloadingId}
                };
            dt = await db.ExecuteSelectQueryAsync(query, pm);

            return dt;
        }
        /// <summary>
        /// Returns Item Stock Id in the format YYMM NNN NNN 
        /// </summary>
        /// <returns></returns>
        private async Task<ReturnClass.ReturnString> ItemExistsInStock(Int64 unloadingId)
        {
            ReturnClass.ReturnString rs = new();
            string query = @"SELECT e.itemStockId
                             FROM itemstockdetail e 
                                WHERE  
                                e.unloadingId = @unloadingId LIMIT 1;";
            MySqlParameter[] pm = new MySqlParameter[] {

                    new MySqlParameter("@unloadingId", MySqlDbType.Int64) { Value = unloadingId}
                };
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            rs.status = false;
            if (dt.table.Rows.Count > 0)
            {
                rs.status = true;
                rs.message = "Item Exists";
            }
            return rs;
        }
        private async Task<ReturnClass.ReturnDataTable> GetItemQuantityInStock(Int64 itemStockId)
        {
            ReturnClass.ReturnString rs = new();
            string query = @"SELECT e.itemStockId,e.quantity,e.itemId
                             FROM itemstockdetail e 
                                WHERE  
                                e.itemStockId = @itemStockId;";
            MySqlParameter[] pm = new MySqlParameter[] {

                    new MySqlParameter("@itemStockId", MySqlDbType.Int64) { Value = itemStockId}
                };
            return await db.ExecuteSelectQueryAsync(query, pm);

        }

        private async Task<ReturnClass.ReturnBool> AddItemInStockAsync(List<ItemStock> itemStocks, Int64 ItemStockId, bool isItemExistsInStock, int counter = 1)
        {
            string query = @"insert into itemstockdetail(itemStockId, unloadingId, itemId,itemName,
                                        quantity,unitId,unitName,ageing,SerialNoFrom,SerialNoTo,
                                        expiryDate,remark,amount,active,clientIp,userId)
                                  values ";
            string Updatequery = "";
            List<MySqlParameter> pm = new();
            string updateQuery = "";
            foreach (ItemStock itemStock in itemStocks)
            {
                #region Remove Auto Adustment
                //if (isItemExistsInStock)
                //{
                //    if (itemStock.oldQuantity == itemStock.quantity)
                //    {
                //        itemStock.updatedQuantity = 0;
                //    }
                //    else if (itemStock.oldQuantity > itemStock.quantity)
                //    {
                //        itemStock.updatedQuantity = itemStock.oldQuantity - itemStock.quantity;
                //        updateQuery += "UPDATE itemmaster SET quantity = quantity- @updatedQuantity " + counter.ToString() + @"
                //                        WHERE itemId=@itemId" + counter.ToString() + @";";

                //    }
                //    else if (itemStock.oldQuantity < itemStock.quantity)
                //    {
                //        itemStock.updatedQuantity = itemStock.quantity - itemStock.oldQuantity;
                //        updateQuery += "UPDATE itemmaster SET quantity=quantity+ @updatedQuantity" + counter.ToString() + @"
                //                        WHERE itemId=@itemId" + counter.ToString() + @";";
                //    }
                //}
                //else
                //{
                //    if (itemStock.quantity > 0)
                //    {
                //        updateQuery += "UPDATE itemmaster SET quantity=quantity+ @quantity " + counter.ToString() + @"
                //                        WHERE itemId=@itemId " + counter.ToString() + @";";
                //    }
                //}
                #endregion

                query += @"(@itemStockId" + counter.ToString() + ", @unloadingId" + counter.ToString() + ", @itemId" + counter.ToString() +
                            ", @itemName" + counter.ToString() + ", @quantity" + counter.ToString() + ", @unitId" + counter.ToString() +
                                ", @unitName" + counter.ToString() + ", @ageing" + counter.ToString() + ", @SerialNoFrom" + counter.ToString() +
                               ", @SerialNoTo" + counter.ToString() + ", @expiryDate" + counter.ToString() + ", @remark" + counter.ToString() +
                               ", @amount" + counter.ToString() +
                            ", @active" + counter.ToString() + ", @clientIp" + counter.ToString() + ", @userId" + counter.ToString() + "),";



                pm.Add(new MySqlParameter("itemStockId" + counter.ToString(), MySqlDbType.Int64) { Value = ItemStockId });
                pm.Add(new MySqlParameter("unloadingId" + counter.ToString(), MySqlDbType.Int64) { Value = itemStock.unloadingId });
                pm.Add(new MySqlParameter("itemId" + counter.ToString(), MySqlDbType.Int32) { Value = itemStock.itemId });
                pm.Add(new MySqlParameter("itemName" + counter.ToString(), MySqlDbType.VarString) { Value = itemStock.itemName });
                pm.Add(new MySqlParameter("quantity" + counter.ToString(), MySqlDbType.Int64) { Value = itemStock.quantity });
                pm.Add(new MySqlParameter("updatedQuantity" + counter.ToString(), MySqlDbType.Int64) { Value = itemStock.updatedQuantity });
                pm.Add(new MySqlParameter("unitId" + counter.ToString(), MySqlDbType.Int16) { Value = itemStock.unitId });
                pm.Add(new MySqlParameter("unitName" + counter.ToString(), MySqlDbType.VarChar) { Value = itemStock.unitName });
                pm.Add(new MySqlParameter("ageing" + counter.ToString(), MySqlDbType.Int64) { Value = itemStock.ageing });
                pm.Add(new MySqlParameter("SerialNoFrom" + counter.ToString(), MySqlDbType.VarChar) { Value = itemStock.SerialNoFrom });
                pm.Add(new MySqlParameter("SerialNoTo" + counter.ToString(), MySqlDbType.VarChar) { Value = itemStock.SerialNoTo });
                pm.Add(new MySqlParameter("expiryDate" + counter.ToString(), MySqlDbType.Int64) { Value = itemStock.expiryDate });
                pm.Add(new MySqlParameter("remark" + counter.ToString(), MySqlDbType.VarChar) { Value = itemStock.remark });
                pm.Add(new MySqlParameter("amount" + counter.ToString(), MySqlDbType.Decimal) { Value = itemStock.amount });
                pm.Add(new MySqlParameter("active" + counter.ToString(), MySqlDbType.Int16) { Value = (Int16)IsActive.Yes });
                pm.Add(new MySqlParameter("clientIp" + counter.ToString(), MySqlDbType.String) { Value = itemStocks[0].clientIp });
                pm.Add(new MySqlParameter("userId" + counter.ToString(), MySqlDbType.Int64) { Value = itemStocks[0].userId });
                ReturnBool rb1 = await IncreaseItems((Int32)itemStock.itemId!, (long)itemStock.quantity!);
                if (!rb1.status)
                {
                    rb1.message = "something Went Wrong, Please Try again";
                    return rb1;
                }
                counter++; ItemStockId++;
            }
            query = query.TrimEnd(',');

            rb = await db.ExecuteQueryAsync(query, pm.ToArray(), "Saveitemstockdetail");
            return rb;
        }
        public async Task<ReturnClass.ReturnBool> RemoveItemfromStockAsync(Int64 ItemStockId)
        {
            ReturnBool rb = new();
            ReturnDataTable dt1 = await GetItemQuantityInStock(ItemStockId);
            if (dt1.table.Rows.Count == 0)
            {
                rb.message = "Invalid Details Provided.";
                return rb;
            }
            Int32 itemId = Convert.ToInt32(dt1.table.Rows[0]["itemId"].ToString());
            Int64 quantity = Convert.ToInt64(dt1.table.Rows[0]["quantity"].ToString());

            MySqlParameter[] pm = new MySqlParameter[] {

                    new MySqlParameter("@itemStockId", MySqlDbType.Int64) { Value = ItemStockId},
                     new MySqlParameter("@itemId", MySqlDbType.Int32) { Value = itemId},
                };


            string query = @"INSERT INTO itemstockdetaillog
                                    SELECT * FROM itemstockdetail i
                                    WHERE i.itemStockId = @itemStockId; ";
            using (TransactionScope ts = new(TransactionScopeAsyncFlowOption.Enabled))
            {

                rb = await db.ExecuteQueryAsync(query, pm, "Saveitemstockdetaillog");
                if (rb.status)
                {
                    query = @"DELETE FROM itemstockdetail 
                                    WHERE itemStockId = @itemStockId; ";
                    if (rb.status)
                        rb = await db.ExecuteQueryAsync(query, pm, "Deleteitemstockdetail");
                    if (rb.status)
                        rb = await DecreaseItems((Int32)itemId!, (long)quantity!);
                    if (rb.status)
                    {
                        rb.message = "Item has been Removed.";
                        ts.Complete();
                    }
                }


            }

            return rb;
        }

        /// <summary>
        /// 
        /// Get Stock List
        /// </summary>
        /// <returns>Verify OTP</returns>
        public async Task<ReturnDataSet> GetStockList(ItemStockSearch itemStockSearch)
        {
            string query = "";
            ReturnDataSet ds = new();
            itemStockSearch.itemStockId = itemStockSearch.itemStockId == null ? 0 : itemStockSearch.itemStockId;
            itemStockSearch.unloadingId = itemStockSearch.unloadingId == null ? 0 : itemStockSearch.unloadingId;
            itemStockSearch.active = itemStockSearch.active == null ? 1 : itemStockSearch.active;

            MySqlParameter[] pm = new MySqlParameter[]
           {
          new MySqlParameter("itemStockId", MySqlDbType.Int64) { Value = itemStockSearch.itemStockId},
          new MySqlParameter("active", MySqlDbType.Int16) { Value = itemStockSearch.active},
          new MySqlParameter("unloadingId", MySqlDbType.String) { Value =itemStockSearch.unloadingId},

           };
            String WHERE = "";

            if (itemStockSearch.itemStockId > 0)
                WHERE += @" AND u.itemStockId=@itemStockId ";
            if (itemStockSearch.itemStockId > 0)
                WHERE += @" AND u.unloadingId=@unloadingId ";


            query = @"SELECT  u.itemStockId, u.unloadingId, u.itemId,u.itemName,
                                        u.quantity,u.unitId,u.unitName,u.ageing,u.SerialNoFrom,u.SerialNoTo,
                                       DATE_FORMAT( u.expiryDate,'%d/%m/%Y') AS expiryDate,u.remark,u.amount
                             FROM itemstockdetail u
                       WHERE u.active=@active " + WHERE + @"
                      ORDER BY u.creationTimeStamp DESC ";
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            ds.status = true;

            dt.table.TableName = "itemstockdetail";
            ds.dataset.Tables.Add(dt.table);

            return ds;
        }
        #endregion

        #region Blending Process 

        /// <summary>
        /// Save Blending Process
        /// </summary>

        /// <returns></returns>
        public async Task<ReturnClass.ReturnString> SaveBlendingProcess(Blending blending)
        {
            bool isBlendingProcessExistsI = false;
            ReturnClass.ReturnString rs = await BlendingProcessExists((Int16)blending.containerId!, (Int32)blending.brandId!);
            isBlendingProcessExistsI = rs.status;
            if (!rs.status)
            {
                rs = await GenerateBatchId();
                if (rs.status)
                    blending.batchId = rs.id;
            }
            if (blending.batchId == 0)
            {
                rs.status = false;
                rs.message = "Invalid Details BatchId.";
            }
            DlCommon dlCommon = new();
            if (rs.status)
            {
                MySqlParameter[] pm = new MySqlParameter[] {

                    new MySqlParameter("@batchId", MySqlDbType.Int64) { Value = blending.batchId}
                };
                string query = @"INSERT INTO blendingmasterlog
                                    SELECT * FROM blendingmaster b
                                    WHERE b.batchId = @batchId; ";
                using (TransactionScope ts = new(TransactionScopeAsyncFlowOption.Enabled))
                {
                    if (isBlendingProcessExistsI)
                    {
                        rb = await db.ExecuteQueryAsync(query, pm, "Saveblendingmasterlog");
                        if (rb.status)
                        {
                            query = @"DELETE FROM blendingmaster 
                                    WHERE batchId = @batchId; ";
                            rb = await db.ExecuteQueryAsync(query, pm, "Deleteblendingmaster");
                            if (rb.status)
                            {
                                query = @"INSERT INTO blendingitemlog
                                    SELECT * FROM blendingitem b
                                    WHERE b.batchId = @batchId; ";
                                rb = await db.ExecuteQueryAsync(query, pm, "Insertblendingitemlog");
                                if (rb.status)
                                {
                                    query = @"DELETE FROM blendingitem 
                                    WHERE batchId = @batchId; ";
                                    rb = await db.ExecuteQueryAsync(query, pm, "Deleteblendingitem");
                                }
                            }
                        }
                    }
                    else
                        rb.status = true;
                    if (rb.status)
                    {
                        rb = await AddItemInBlendingProcessAsync(blending, isBlendingProcessExistsI, 1);
                        if (rb.status)
                            ts.Complete();
                    }
                }
                if (rb.status)
                {
                    rs.status = true;
                    rs.message = "Blending Process starts into " + blending.containerName;
                }
                else
                {
                    rs = new();
                    rs.message = "Failed to start Blending into" + blending.containerName;
                }
            }


            return rs;
        }
        /// <summary>
        /// Returns Item Batch Id in the format YYMMDD NNN
        /// </summary>
        /// <returns></returns>
        private async Task<ReturnClass.ReturnString> GenerateBatchId()
        {
            ReturnClass.ReturnString rs = new();
            string query = @"SELECT IFNULL(MAX(SUBSTRING(b.batchId,7,9)),0) + 1 AS batchId
                             FROM blendingmaster b 
                                WHERE  
                                DATE_FORMAT(b.creationTimeStamp,'%d/%m/%Y') = DATE_FORMAT(NOW(),'%d/%m/%Y');";
            dt = await db.ExecuteSelectQueryAsync(query);
            if (dt.table.Rows.Count > 0)
            {
                // ID Format =  YYMMdd NNN NNN 
                string id = DateTime.Now.ToString("yyMMdd") + dt.table.Rows[0]["batchId"].ToString().PadLeft(3, '0');
                rs.id = Convert.ToInt64(id);
                rs.status = true;
            }
            return rs;
        }
        /// <summary>
        /// Returns Blending Process Exists
        /// </summary>
        /// <returns></returns>
        private async Task<ReturnClass.ReturnString> BlendingProcessExists(Int16 containerId, Int32 brandId)
        {
            ReturnClass.ReturnString rs = new();
            string query = @"SELECT e.batchId
                             FROM blendingmaster e 
                                WHERE  
                                e.containerId = @containerId AND e.brandId=@brandId  
                                        AND  DATE_FORMAT(e.startDate,'%d/%m/%Y') = DATE_FORMAT(NOW(),'%d/%m/%Y') LIMIT 1;";
            MySqlParameter[] pm = new MySqlParameter[] {

                    new MySqlParameter("@containerId", MySqlDbType.Int16) { Value = containerId},
                    new MySqlParameter("@brandId", MySqlDbType.Int32) { Value = brandId}
                };
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            rs.status = false;
            if (dt.table.Rows.Count > 0)
            {
                rs.status = true;
                rs.message = "Blending Process Exists";
            }
            return rs;
        }

        private async Task<ReturnClass.ReturnBool> AddItemInBlendingProcessAsync(Blending blending, bool isBlendingProcessExistsI, int counter = 1)
        {
            string query1 = @"insert into blendingmaster (batchId,containerId,containerName,brandId,brandName,
                                                    totalQuantity,balanceQuantity,unitId,unitName,remark,
                                                startDate,active,clientIp,userId)
                                  values (@batchId,@containerId,@containerName,@brandId,@brandName,
                                            @totalQuantity,@balanceQuantity,@unitId,@unitName,@remark,
                                            NOW(),@active,@clientIp,@userId)";
            string query = "";
            //blending.totalQuantity = blending.blendingItems.Where(x => x.applicationFor == 1).Sum(x => x.equipmentCount);
            blending.totalQuantity = blending.blendingItems.Sum(x => x.quantity);
            blending.balanceQuantity = blending.totalQuantity;

            MySqlParameter[] pm1 = new MySqlParameter[] {

              new MySqlParameter("@batchId", MySqlDbType.Int64) { Value = blending.batchId},
              new MySqlParameter("@containerId", MySqlDbType.VarChar) { Value = blending.containerId},
              new MySqlParameter("@containerName", MySqlDbType.VarChar) { Value = blending.containerName},
              new MySqlParameter("@brandId", MySqlDbType.VarChar) { Value = blending.brandId},
              new MySqlParameter("@brandName", MySqlDbType.VarChar) { Value = blending.brandName},
               new MySqlParameter("@totalQuantity", MySqlDbType.VarChar) { Value = blending.totalQuantity},
               new MySqlParameter("@balanceQuantity", MySqlDbType.VarChar) { Value = blending.balanceQuantity},
               new MySqlParameter("@unitId", MySqlDbType.VarChar) { Value = blending.unitId},
               new MySqlParameter("@unitName", MySqlDbType.VarChar) { Value = blending.unitName},
               new MySqlParameter("@remark", MySqlDbType.VarChar) { Value = blending.remark},
              new MySqlParameter("@active", MySqlDbType.Int16) { Value = blending.active},
               new MySqlParameter("@userId", MySqlDbType.Int64) { Value = blending.userId},
                new MySqlParameter("@clientIp", MySqlDbType.String) { Value = blending.clientIp},
          };
            List<MySqlParameter> pm = new();
            query = @"insert into blendingitem (batchId,itemId,itemName,quantity,
                                               unitId,unitName,active,clientIp,userId)
                                  values ";
            string updateQuery = "";
            foreach (BlendingItems blendingItem in blending.blendingItems)
            {

                query += @"(@batchId" + counter.ToString() + ", @itemId" + counter.ToString() +
                            ", @itemName" + counter.ToString() + ", @quantity" + counter.ToString() +
                            ", @unitId" + counter.ToString() + ", @unitName" + counter.ToString() +
                            ", @active" + counter.ToString() + ", @clientIp" + counter.ToString() +
                            ", @userId" + counter.ToString() + "),";

                pm.Add(new MySqlParameter("batchId" + counter.ToString(), MySqlDbType.Int64) { Value = blending.batchId });

                pm.Add(new MySqlParameter("itemId" + counter.ToString(), MySqlDbType.Int64) { Value = blendingItem.itemId });
                pm.Add(new MySqlParameter("itemName" + counter.ToString(), MySqlDbType.VarString) { Value = blendingItem.itemName });
                pm.Add(new MySqlParameter("quantity" + counter.ToString(), MySqlDbType.Int64) { Value = blendingItem.quantity });
                pm.Add(new MySqlParameter("updatedQuantity" + counter.ToString(), MySqlDbType.Int64) { Value = blendingItem.updatedQuantity });
                pm.Add(new MySqlParameter("unitId" + counter.ToString(), MySqlDbType.VarString) { Value = blendingItem.unitId });
                pm.Add(new MySqlParameter("unitName" + counter.ToString(), MySqlDbType.Int64) { Value = blendingItem.unitName });
                pm.Add(new MySqlParameter("active" + counter.ToString(), MySqlDbType.Int16) { Value = (Int16)IsActive.Yes });
                pm.Add(new MySqlParameter("clientIp" + counter.ToString(), MySqlDbType.String) { Value = blending.clientIp });
                pm.Add(new MySqlParameter("userId" + counter.ToString(), MySqlDbType.Int64) { Value = blending.userId });
                updateQuery = "";

                ReturnBool rb = await DecreaseItems((Int32)blendingItem.itemId!, (long)blendingItem.quantity!);
                if (!rb.status)
                {
                    rb.message = "something Went Wrong, Please Try again";
                    return rb;
                }
                counter++;
            }
            query = query.TrimEnd(',');
            ReturnBool returnBool = await db.ExecuteQueryAsync(query1, pm1.ToArray(), "SaveblendingMaster");
            if (returnBool.status)
                returnBool = await db.ExecuteQueryAsync(query, pm.ToArray(), "Saveblendingitem");
            //if (returnBool.status)
            //    returnBool = await db.ExecuteQueryAsync(updateQuery, pm.ToArray(), "UpdateItemMaster");
            return returnBool;


        }
        private async Task<ReturnClass.ReturnDataTable> GetItemQuantityfromBlendingProcess(Int64 batchId, Int32 itemId)
        {
            ReturnClass.ReturnString rs = new();
            string query = @"SELECT e.batchId,e.quantity,e.itemId
                             FROM blendingitem e 
                                WHERE  
                                e.batchId = @batchId AND e.itemId=@itemId;";
            MySqlParameter[] pm = new MySqlParameter[] {

                    new MySqlParameter("@batchId", MySqlDbType.Int64) { Value = batchId},
                    new MySqlParameter("@itemId", MySqlDbType.Int64) { Value = itemId}
                };
            return await db.ExecuteSelectQueryAsync(query, pm);

        }
        public async Task<ReturnClass.ReturnBool> RemoveItemfromBlendingProcess(Int64 batchId, Int32 itemId)
        {
            ReturnBool rb = new();
            ReturnDataTable dt1 = await GetItemQuantityfromBlendingProcess(batchId, itemId);
            if (dt1.table.Rows.Count == 0)
            {
                rb.message = "Invalid Details Provided.";
                return rb;
            }
            itemId = Convert.ToInt32(dt1.table.Rows[0]["itemId"].ToString());
            Int64 quantity = Convert.ToInt64(dt1.table.Rows[0]["quantity"].ToString());

            MySqlParameter[] pm = new MySqlParameter[] {

                    new MySqlParameter("@batchId", MySqlDbType.Int64) { Value = batchId},
                     new MySqlParameter("@itemId", MySqlDbType.Int32) { Value = itemId},
                };


            string query = @"INSERT INTO blendingitemlog
                                    SELECT * FROM blendingitem i
                                    WHERE i.batchId = @batchId AND i.itemId=@itemId ; ";
            using (TransactionScope ts = new(TransactionScopeAsyncFlowOption.Enabled))
            {

                rb = await db.ExecuteQueryAsync(query, pm, "Saveblendingitemlog");
                if (rb.status)
                {
                    query = @"DELETE FROM blendingitem 
                                    WHERE batchId = @batchId AND itemId=@itemId; ";
                    if (rb.status)
                        rb = await db.ExecuteQueryAsync(query, pm, "Deleteblendingitem");
                    if (rb.status)
                        rb = await IncreaseItems((Int32)itemId!, (long)quantity!);
                    if (rb.status)
                        rb = await DecreaseBlendingMaster((long)batchId!, (long)quantity!);
                    if (rb.status)
                    {
                        ts.Complete();
                        rb.message = "Blending Process has been Removed.";
                    }
                }


            }

            return rb;
        }

        /// <summary>
        /// 
        /// Get Blending Process List
        /// </summary>
        /// <returns>Verify OTP</returns>
        public async Task<ReturnDataSet> GetBlendingProcessList(Blending itemStockSearch)
        {
            string query = "";
            ReturnDataSet ds = new();
            itemStockSearch.batchId = itemStockSearch.batchId == null ? 0 : itemStockSearch.batchId;
            itemStockSearch.containerId = itemStockSearch.containerId == null ? 0 : itemStockSearch.containerId;
            itemStockSearch.brandId = itemStockSearch.brandId == null ? 0 : itemStockSearch.brandId;
            itemStockSearch.active = itemStockSearch.active == null ? 1 : itemStockSearch.active;

            MySqlParameter[] pm = new MySqlParameter[]
           {
          new MySqlParameter("batchId", MySqlDbType.Int64) { Value = itemStockSearch.batchId},
          new MySqlParameter("containerId", MySqlDbType.Int64) { Value = itemStockSearch.containerId},
          new MySqlParameter("brandId", MySqlDbType.Int64) { Value = itemStockSearch.brandId},
          new MySqlParameter("active", MySqlDbType.Int16) { Value = itemStockSearch.active},


           };
            String WHERE = "";

            if (itemStockSearch.batchId > 0)
                WHERE += @" AND bm.batchId=@batchId ";
            if (itemStockSearch.containerId > 0)
                WHERE += @" AND bm.containerId=@containerId ";
            if (itemStockSearch.brandId > 0)
                WHERE += @" AND bm.brandId=@brandId ";


            query = @"SELECT bm.batchId,bm.containerId,bm.containerName,bm.brandId,bm.brandName,
                            bm.totalQuantity,bm.balanceQuantity,bm.unitId,bm.unitName,bm.remark,
                            bm.startDate,
                            bm.endDate,bm.emptyDate
                             FROM blendingmaster bm 
                            WHERE bm.active=@active " + WHERE + "  ORDER BY bm.batchId DESC ";
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            ds.status = true;
            if (dt.table.Rows.Count > 0)
            {

                dt.table.TableName = "blendingMaster";
                ds.dataset.Tables.Add(dt.table);
                query = @"SELECT bm.batchId,bi.itemId,bi.quantity,bi.unitId,bi.unitName
                         FROM blendingmaster bm 
                        JOIN blendingitem bi ON bi.batchId=bm.batchId
                        WHERE bi.active=@active " + WHERE;
                dt = await db.ExecuteSelectQueryAsync(query, pm);

                ds.status = true;
                dt.table.TableName = "blendingItem";
                ds.dataset.Tables.Add(dt.table);

            }
            return ds;
        }

        #endregion

        #region Material Issue for Packaging 

        /// <summary>
        /// Save Issue Packaging Material
        /// </summary>
        /// <param name="issueMaterial"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnString> IssuePackagingMaterial(IssueMaterial issueMaterial)
        {
            bool isItemAlreadyIssued = false;
            ReturnClass.ReturnString rs = new();

            rs = await CheckItemIssued(issueMaterial);
            if (!rs.status)
            {
                rs = await GenerateMaterialIssueId();
                issueMaterial.issueId = rs.id;
            }
            else
                isItemAlreadyIssued = true;
            DlCommon dlCommon = new();
            if (rs.status)
            {
                MySqlParameter[] pm = new MySqlParameter[] {

                    new MySqlParameter("@issueId", MySqlDbType.Int64) { Value = issueMaterial.issueId}
                };
                string query = @"INSERT INTO blendingmaterialissuelog
                                    SELECT * FROM blendingmaterialissue b
                                    WHERE b.issueId = @issueId; ";
                using (TransactionScope ts = new(TransactionScopeAsyncFlowOption.Enabled))
                {
                    if (isItemAlreadyIssued)
                    {

                        rb = await db.ExecuteQueryAsync(query, pm, "Saveblendingmaterialissuelog");
                        if (rb.status)
                        {
                            query = @"DELETE FROM blendingmaterialissue 
                                    WHERE issueId = @issueId; ";
                            rb = await db.ExecuteQueryAsync(query, pm, "Deleteblendingmaster");

                        }
                    }
                    else
                        rb.status = true;
                    if (rb.status)
                    {
                        rb = await AddIssuedItemAsync(issueMaterial, isItemAlreadyIssued, 1);
                        if (rb.status)
                            ts.Complete();
                    }
                }
                if (rb.status)
                {
                    rs.status = true;
                    rs.message = "Item Issued for Packaging ";
                }
                else
                {
                    rs = new();
                    rs.message = "Failed to Item Issued for Packaging";
                }
            }


            return rs;
        }
        /// <summary>
        /// Returns Material Issue Id in the format 5+YYMMDD NNN
        /// </summary>
        /// <returns></returns>
        private async Task<ReturnClass.ReturnString> GenerateMaterialIssueId()
        {
            ReturnClass.ReturnString rs = new();
            string query = @"SELECT IFNULL(MAX(SUBSTRING(b.issueId,8,10)),0) + 1 AS issueId
                             FROM blendingmaterialissue b 
                                WHERE  
                                DATE_FORMAT(b.creationTimeStamp,'%d/%m/%Y') = DATE_FORMAT(NOW(),'%d/%m/%Y');";
            dt = await db.ExecuteSelectQueryAsync(query);
            if (dt.table.Rows.Count > 0)
            {

                string id = ((Int16)PrefixId.MaterialIssue).ToString() +
                    DateTime.Now.ToString("yyMMdd") +
                    dt.table.Rows[0]["issueId"].ToString().PadLeft(3, '0');
                rs.id = Convert.ToInt64(id);
                rs.status = true;
            }
            return rs;
        }
        /// <summary>
        /// Returns Blending Process Exists
        /// </summary>
        /// <returns></returns>
        private async Task<ReturnClass.ReturnString> CheckItemIssued(IssueMaterial issuePackagingMaterial)
        {
            ReturnClass.ReturnString rs = new();
            issuePackagingMaterial.issueId = issuePackagingMaterial.issueId == null ? 0 : issuePackagingMaterial.issueId;
            string where = "";
            if (issuePackagingMaterial.issueId > 0)
                where = " AND e.issueId=@issueId ";

            string query = @"SELECT e.issueId
                             FROM blendingmaterialissue e 
                                WHERE  
                                e.batchId = @batchId 
                                        AND  DATE_FORMAT(e.issueDate,'%d/%m/%Y') = DATE_FORMAT(NOW(),'%d/%m/%Y')
                                    " + where + @"
                                    LIMIT 1;";
            MySqlParameter[] pm = new MySqlParameter[] {

                    new MySqlParameter("@batchId", MySqlDbType.Int64) { Value = issuePackagingMaterial.batchId},
                    new MySqlParameter("@issueId", MySqlDbType.Int64) { Value = issuePackagingMaterial.issueId},

                };
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            rs.status = false;
            if (dt.table.Rows.Count > 0)
            {
                rs.status = true;
                rs.message = "Already Issued";
                rs.id = Convert.ToInt64(dt.table.Rows[0]["issueId"].ToString());
            }

            return rs;
        }

        private async Task<ReturnClass.ReturnBool> AddIssuedItemAsync(IssueMaterial issueMaterial, bool isItemAlreadyIssued, int counter = 1)
        {

            string query = "";

            List<MySqlParameter> pm = new();
            query = @"insert into blendingmaterialissue (issueId,batchId,itemId,itemName,quantity,balanceQuantity,
                                                    unitId,unitName,issueDate,remark,active,clientIp,userId)
                                  values ";
            string updateQuery = "";
            foreach (IssuePackagingMaterial issuePackagingMaterial in issueMaterial.IssuePackagingMaterials)
            {
                #region Remove Master Auto Adustment 
                /*
                if (issuePackagingMaterial.issuedQuantity > 0 && isItemAlreadyIssued)
                {
                    if (issuePackagingMaterial.issuedQuantity == issuePackagingMaterial.quantity)
                    {
                        issuePackagingMaterial.updatedQuantity = 0;
                    }
                    else if (issuePackagingMaterial.issuedQuantity > issuePackagingMaterial.quantity)
                    {
                        issuePackagingMaterial.updatedQuantity = issuePackagingMaterial.issuedQuantity - issuePackagingMaterial.quantity;
                        updateQuery += "UPDATE itemmaster SET quantity = quantity + @updatedQuantity " + counter.ToString() + @"
                                        WHERE itemId=@itemId" + counter.ToString() + @";";

                    }
                    else if (issuePackagingMaterial.issuedQuantity < issuePackagingMaterial.quantity)
                    {
                        issuePackagingMaterial.updatedQuantity = issuePackagingMaterial.quantity - issuePackagingMaterial.issuedQuantity;
                        updateQuery += "UPDATE itemmaster SET quantity= quantity- @updatedQuantity" + counter.ToString() + @"
                                        WHERE itemId=@itemId" + counter.ToString() + @";";
                    }
                }
                else
                {
                    if (issuePackagingMaterial.quantity > 0)
                    {
                        updateQuery += "UPDATE itemmaster SET quantity= quantity- @quantity" + counter.ToString() + @"
                                        WHERE itemId=@itemId" + counter.ToString() + @";";
                    }
                }*/
                #endregion

                query += @"(@issueId" + counter.ToString() + ",@batchId" + counter.ToString() +
                            ",@itemId" + counter.ToString() + ",@itemName" + counter.ToString() +
                            ",@quantity" + counter.ToString() + ",@quantity" + counter.ToString() +
                            ",@unitId" + counter.ToString() + ",@unitName" + counter.ToString() + ",NOW()" +
                            ",@remark" + counter.ToString() + ",@active" + counter.ToString() +
                            ",@clientIp" + counter.ToString() + ",@userId" + counter.ToString() + "),";
                pm.Add(new MySqlParameter("@batchId" + counter.ToString(), MySqlDbType.Int64) { Value = issueMaterial.batchId });
                pm.Add(new MySqlParameter("@issueId" + counter.ToString(), MySqlDbType.Int64) { Value = issueMaterial.issueId });
                pm.Add(new MySqlParameter("@itemId" + counter.ToString(), MySqlDbType.Int32) { Value = issuePackagingMaterial.itemId });
                pm.Add(new MySqlParameter("@itemName" + counter.ToString(), MySqlDbType.VarChar) { Value = issuePackagingMaterial.itemName });
                pm.Add(new MySqlParameter("@quantity" + counter.ToString(), MySqlDbType.Decimal) { Value = issuePackagingMaterial.quantity });
                pm.Add(new MySqlParameter("updatedQuantity" + counter.ToString(), MySqlDbType.Decimal) { Value = issuePackagingMaterial.updatedQuantity });
                pm.Add(new MySqlParameter("@unitId" + counter.ToString(), MySqlDbType.Int16) { Value = issuePackagingMaterial.unitId });
                pm.Add(new MySqlParameter("@unitName" + counter.ToString(), MySqlDbType.VarChar) { Value = issuePackagingMaterial.unitName });
                pm.Add(new MySqlParameter("@remark" + counter.ToString(), MySqlDbType.VarChar) { Value = issuePackagingMaterial.remark });
                pm.Add(new MySqlParameter("@active" + counter.ToString(), MySqlDbType.Int16) { Value = (Int16)IsActive.Yes });
                pm.Add(new MySqlParameter("@clientIp" + counter.ToString(), MySqlDbType.String) { Value = issueMaterial.clientIp });
                pm.Add(new MySqlParameter("@userId" + counter.ToString(), MySqlDbType.Int64) { Value = issueMaterial.userId });
                ReturnBool rb1 = await DecreaseItems((Int32)issuePackagingMaterial.itemId!, (long)issuePackagingMaterial.quantity!);
                if (!rb1.status)
                {
                    rb1.message = "something Went Wrong, Please Try again";
                    return rb1;
                }
                counter++;
                issueMaterial.issueId++;
            }
            query = query.TrimEnd(',');

            ReturnBool returnBool = await db.ExecuteQueryAsync(query, pm.ToArray(), "Saveblendingmaterialissue");
            //if (returnBool.status)
            //    returnBool = await db.ExecuteQueryAsync(updateQuery, pm.ToArray(), "UpdateItemMaster");
            return returnBool;
        }

        public async Task<ReturnClass.ReturnBool> RemoveItemfromIssuedItem(Int64 issueId, Int32 itemId)
        {
            ReturnBool rb = new();
            ReturnDataTable dt1 = await GetItemQuantityfromIssuedItem(issueId, itemId);
            if (dt1.table.Rows.Count == 0)
            {
                rb.message = "Invalid Details Provided.";
                return rb;
            }
            itemId = Convert.ToInt32(dt1.table.Rows[0]["itemId"].ToString());
            Int64 quantity = Convert.ToInt64(dt1.table.Rows[0]["quantity"].ToString());

            MySqlParameter[] pm = new MySqlParameter[] {

                    new MySqlParameter("@issueId", MySqlDbType.Int64) { Value = issueId},
                     new MySqlParameter("@itemId", MySqlDbType.Int32) { Value = itemId},
                };


            string query = @"INSERT INTO blendingmaterialissuelog
                                    SELECT * FROM blendingmaterialissue i
                                    WHERE i.issueId = @issueId AND i.itemId=@itemId; ";
            using (TransactionScope ts = new(TransactionScopeAsyncFlowOption.Enabled))
            {

                rb = await db.ExecuteQueryAsync(query, pm, "Saveblendingmaterialissuelog");
                if (rb.status)
                {
                    query = @"DELETE FROM blendingmaterialissue 
                                    WHERE issueId = @issueId AND itemId=@itemId; ";
                    if (rb.status)
                        rb = await db.ExecuteQueryAsync(query, pm, "Deleteblendingmaterialissue");
                    if (rb.status)
                        rb = await IncreaseItems((Int32)itemId!, (long)quantity!);
                    if (rb.status)
                    {
                        ts.Complete();
                        rb.message = "Issued Item has been Removed.";
                    }
                }


            }

            return rb;
        }

        private async Task<ReturnClass.ReturnDataTable> GetItemQuantityfromIssuedItem(Int64 issueId, Int32 itemId)
        {
            ReturnClass.ReturnString rs = new();
            string query = @"SELECT e.issueId,e.quantity,e.itemId
                             FROM blendingmaterialissue e 
                                WHERE  
                                e.issueId = @issueId AND e.itemId=@itemId;";
            MySqlParameter[] pm = new MySqlParameter[] {

                    new MySqlParameter("@issueId", MySqlDbType.Int64) { Value = issueId},
                    new MySqlParameter("@itemId", MySqlDbType.Int64) { Value = itemId}
                };
            return await db.ExecuteSelectQueryAsync(query, pm);

        }

        /// <summary>
        /// Save Issue Packaging Material
        /// </summary>
        /// <param name="issueMaterial"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnString> ReturnIssuedItem(IssueMaterial issueMaterial)
        {
            ReturnClass.ReturnString rs = new();
            if (issueMaterial.IssuePackagingMaterials[0].issueId > 0)
            {
                rs.status = true;
                rs = await ValidateReturnIssuedItemAsync(issueMaterial);
                if (!rs.status)
                    return rs;
            }
            else
            {
                rs.status = false;
                rs.message = "Invalid Issue Id.";
                return rs;
            }
            DlCommon dlCommon = new();
            if (rs.status)
            {
                using (TransactionScope ts = new(TransactionScopeAsyncFlowOption.Enabled))
                {
                    rb = await ReturnIssuedItemAsync(issueMaterial, 0);
                    if (rb.status)
                        ts.Complete();
                }
                if (rb.status)
                {
                    rs.status = true;
                    rs.message = "Item has been returned";
                }
                else
                {
                    rs = new();
                    rs.message = "Failed to returned, " + rb.message;
                }
            }
            return rs;
        }

        private async Task<ReturnClass.ReturnBool> ReturnIssuedItemAsync(IssueMaterial issueMaterial, int counter = 0)
        {

            string query = "";
            ReturnBool returnBool = new();
            List<MySqlParameter> pm = new();
            query = @"INSERT INTO blendingmaterialissuelog
                                    SELECT * FROM blendingmaterialissue b
                                    WHERE b.issueId = @issueId; ";


            foreach (IssuePackagingMaterial issuePackagingMaterial in issueMaterial.IssuePackagingMaterials)
            {
                issuePackagingMaterial.quantity = issuePackagingMaterial.retunQuantity;
                pm.Add(new MySqlParameter("@batchId", MySqlDbType.Int64) { Value = issueMaterial.batchId });
                pm.Add(new MySqlParameter("@issueId", MySqlDbType.Int64) { Value = issuePackagingMaterial.issueId });
                pm.Add(new MySqlParameter("@itemId", MySqlDbType.Int32) { Value = issuePackagingMaterial.itemId });
                pm.Add(new MySqlParameter("@retunQuantity", MySqlDbType.Decimal) { Value = issuePackagingMaterial.retunQuantity });
                pm.Add(new MySqlParameter("@remark", MySqlDbType.VarChar) { Value = issuePackagingMaterial.remark });
                pm.Add(new MySqlParameter("@clientIp", MySqlDbType.String) { Value = issueMaterial.clientIp });
                pm.Add(new MySqlParameter("@userId", MySqlDbType.Int64) { Value = issueMaterial.userId });
                rb = await db.ExecuteQueryAsync(query, pm.ToArray(), "Saveblendingmaterialissuelog");
                if (rb.status)
                {
                    query = @"UPDATE blendingmaterialissue SET
                            retunQuantity=retunQuantity+@retunQuantity,
                                                    balanceQuantity=balanceQuantity-@retunQuantity,
                                                    returnDate=NOW(),remark=@remark,clientIp=@clientIp,
                                                    userId=@userId
                                WHERE issueId=@issueId AND balanceQuantity >=@retunQuantity ;";
                    returnBool = await db.ExecuteQueryAsync(query, pm.ToArray(), "Returnmaterialissue");
                    if (returnBool.status)
                    {
                        returnBool = await IncreaseItems((Int32)issuePackagingMaterial.itemId!, (long)issuePackagingMaterial.quantity!);
                        if (returnBool.status)
                            counter++;
                        else
                        {
                            returnBool.status = false;
                            returnBool.message = "invalid Item Details";
                            return returnBool;
                        }
                    }
                    else
                    {
                        returnBool.status = false;
                        returnBool.message = "invalid return quantity";
                        return returnBool;
                    }
                }
            }
            if (returnBool.status)
            {
                returnBool.status = true;
                returnBool.message = "Item has been returned Successfully.";
            }
            else
            {
                returnBool.status = false;
                returnBool.message = "Try again, Data not updated.";
            }
            return returnBool;
        }
        private async Task<ReturnClass.ReturnString> ValidateReturnIssuedItemAsync(IssueMaterial issueMaterial, int counter = 0)
        {

            string query = "";
            ReturnString returnBool = new();

            query = @"";
            foreach (IssuePackagingMaterial issuePackagingMaterial in issueMaterial.IssuePackagingMaterials)
            {
                if (issuePackagingMaterial.retunQuantity > 0)
                {
                    List<MySqlParameter> pm = new();
                    pm.Add(new MySqlParameter("@issueId", MySqlDbType.Int64) { Value = issuePackagingMaterial.issueId });
                    pm.Add(new MySqlParameter("@retunQuantity", MySqlDbType.Decimal) { Value = issuePackagingMaterial.retunQuantity });

                    query = @"SELECT b.issueId FROM blendingmaterialissue b                            
                                WHERE b.issueId=@issueId AND b.balanceQuantity >= @retunQuantity;";
                    ReturnDataTable dtvallidate = await db.ExecuteSelectQueryAsync(query, pm.ToArray());
                    if (dtvallidate.table.Rows.Count > 0)
                        counter++;
                    else
                    {
                        returnBool.status = false;
                        returnBool.message = "Invalid Return Quantity.";
                        return returnBool;
                    }
                }
                else
                {
                    returnBool.status = false;
                    returnBool.message = "Invalid Return Quantity.";
                    return returnBool;
                }
            }
            returnBool.status = true;
            return returnBool;
        }
        /// <summary>
        /// 
        /// Get Blending Process List
        /// </summary>
        /// <returns>Verify OTP</returns>
        public async Task<ReturnDataSet> GetItemIssueList(IssueMaterial itemSearch)
        {
            string query = "";
            ReturnDataSet ds = new();
            itemSearch.batchId = itemSearch.batchId == null ? 0 : itemSearch.batchId;
            itemSearch.issueId = itemSearch.issueId == null ? 0 : itemSearch.issueId;
            itemSearch.active = itemSearch.active == null ? 1 : itemSearch.active;

            MySqlParameter[] pm = new MySqlParameter[]
           {
          new MySqlParameter("batchId", MySqlDbType.Int64) { Value = itemSearch.batchId},
          new MySqlParameter("issueId", MySqlDbType.Int64) { Value = itemSearch.issueId},
          new MySqlParameter("issueDate", MySqlDbType.DateTime) { Value = itemSearch.issueDate},
          new MySqlParameter("active", MySqlDbType.Int16) { Value = itemSearch.active},


           };
            String WHERE = "";

            if (itemSearch.batchId > 0)
                WHERE += @" AND bmi.batchId=@batchId ";
            if (itemSearch.issueId > 0)
                WHERE += @" AND bmi.issueId=@issueId ";
            if (itemSearch.issueDate != null)
                WHERE += @" AND DATE_FORMAT(bmi.issueDate,'%d/%m/%Y')=DATE_FORMAT(@issueDate,'%d/%m/%Y')";


            query = @"SELECT b.batchId,b.brandId,b.brandName,b.containerId,b.containerName,
                        bmi.issueId,bmi.itemId,bmi.itemName,bmi.quantity,bmi.balanceQuantity,bmi.retunQuantity,
                        bmi.unitId,bmi.unitName,DATE_FORMAT(bmi.issueDate,'%d/%m/%Y') AS issueDate,bmi.remark
                         FROM blendingmaster b 
                        JOIN blendingmaterialissue bmi ON bmi.batchId=b.batchId
                        WHERE b.active=@active " + WHERE + "  ORDER BY bmi.issueId DESC ";
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            ds.status = true;

            dt.table.TableName = "blendingmaterialissue";
            ds.dataset.Tables.Add(dt.table);


            return ds;
        }

        #endregion

        #region Finished Product

        /// <summary>
        /// Save Issue Packaging Material
        /// </summary>

        /// <returns></returns>
        public async Task<ReturnClass.ReturnString> SavefinishedProduct(FinishedProduct finishedProduct)
        {
            bool isfinishedProductExists = false;
            ReturnClass.ReturnString rs = new();

            if (finishedProduct.batchId == 0)
            {
                rs.status = false;
                rs.message = "batchId should not be empty .";
                return rs;
            }
            if (finishedProduct.brandId == 0)
            {
                rs.status = false;
                rs.message = "brandId should not be empty .";
                return rs;
            }
            bool isFinalMasterProductExist = await GetFinishedProductMasterData(finishedProduct);


            finishedProduct.productId = finishedProduct.productId == null ? 0 : finishedProduct.productId;

            decimal netQuantity = 0, netBalanceQuantity = 0, oldQuantity = 0;
            if (finishedProduct.productId > 0)
            {
                ReturnDataTable dt1 = await GetFinishedProductSumData(finishedProduct);
                if (dt1.table.Rows.Count > 0)
                    oldQuantity = Convert.ToInt64(dt1.table.Rows[0]["totalQuantity"].ToString());
            }

            #region Remove Auto Calculation finished Product
            /*
            dt = await GetFinishedProductMasterData((long)finishedProduct.batchId!, (long)finishedProduct.brandId!);
            if (dt.table.Rows.Count == 0)
            {
                dt.table.Rows[0]["totalQuantity"] = "0";
                dt.table.Rows[0]["balanceQuantity"] = "0";
            }
            ReturnDataTable dt1 = new();
            if (finishedProduct.productId > 0)
            {
                dt1 = await GetFinishedProductSumData(finishedProduct);
                if (dt1.table.Rows.Count == 0)
                    dt1.table.Rows[0]["totalQuantity"] = "0";

                if (dt1.table.Rows.Count > 0)
                {
                    oldQuantity = Convert.ToDecimal(dt1.table.Rows[0]["totalQuantity"].ToString());
                    //oldBalanceQuantity = Convert.ToDecimal(dt1.table.Rows[0]["balanceQuantity"].ToString());

                    if (oldQuantity == (long)finishedProduct.totalQuantity)
                    {
                        netQuantity = (long)finishedProduct.totalQuantity + Convert.ToDecimal(dt.table.Rows[0]["totalQuantity"].ToString());
                        netBalanceQuantity = (long)finishedProduct.totalQuantity + Convert.ToDecimal(dt.table.Rows[0]["balanceQuantity"].ToString());
                    }
                    if (oldQuantity > 0 && oldBalanceQuantity > 0)
                    {
                        if (oldQuantity > (long)finishedProduct.totalQuantity)
                        {
                            DiffQuantity = oldQuantity - (long)finishedProduct.totalQuantity;
                            DiffBalanceQuantity = netBalanceQuantity - (long)finishedProduct.totalQuantity;
                        }
                        if (oldQuantity < (long)finishedProduct.totalQuantity)
                        {
                            netQuantity = oldQuantity + (long)finishedProduct.totalQuantity;
                            netBalanceQuantity = netBalanceQuantity + (long)finishedProduct.totalQuantity;
                        }
                    }
                }
            }
            else
            {
                if (dt.table.Rows.Count > 0)
                {
                    if (oldQuantity > (long)finishedProduct.totalQuantity)
                    {
                        netQuantity = oldQuantity - ((long)finishedProduct.totalQuantity + Convert.ToDecimal(dt.table.Rows[0]["totalQuantity"].ToString()));
                        netBalanceQuantity = oldQuantity - ((long)finishedProduct.totalQuantity + Convert.ToDecimal(dt.table.Rows[0]["balanceQuantity"].ToString()));
                    }
                    else if (oldQuantity < (long)finishedProduct.totalQuantity)
                    {
                        netQuantity = (long)finishedProduct.totalQuantity + (oldQuantity + Convert.ToDecimal(dt.table.Rows[0]["totalQuantity"].ToString()));
                        netBalanceQuantity = (long)finishedProduct.totalQuantity + (oldQuantity + Convert.ToDecimal(dt.table.Rows[0]["balanceQuantity"].ToString()));
                    }
                    else
                    {
                        netQuantity = Convert.ToDecimal(dt.table.Rows[0]["totalQuantity"].ToString());
                        netBalanceQuantity = Convert.ToDecimal(dt.table.Rows[0]["balanceQuantity"]);
                    }
                }
            }
            */
            #endregion
            if (finishedProduct.productId == 0)
                rs = await GenerateFinishedProductId((long)finishedProduct.batchId);
            else
                isfinishedProductExists = true;
            if (rs.status)
                finishedProduct.productId = rs.id;
            else
                rs.status = true;
            DlCommon dlCommon = new();
            if (rs.status)
            {
                MySqlParameter[] pm = new MySqlParameter[] {

              new MySqlParameter("@productId", MySqlDbType.Int64) { Value = finishedProduct.productId},
              new MySqlParameter("@batchId", MySqlDbType.Int64) { Value = finishedProduct.batchId},
              new MySqlParameter("@brandId", MySqlDbType.Int64) { Value = finishedProduct.brandId},
              new MySqlParameter("@brandName", MySqlDbType.VarChar) { Value = finishedProduct.brandName},
              new MySqlParameter("@totalQuantity", MySqlDbType.Decimal) { Value = finishedProduct.totalQuantity},
              new MySqlParameter("@balanceQuantity", MySqlDbType.Decimal) { Value = finishedProduct.totalQuantity},
              new MySqlParameter("@unitId", MySqlDbType.Int16) { Value = finishedProduct.unitId},
              new MySqlParameter("@unitName", MySqlDbType.VarChar) { Value = finishedProduct.unitName},
              new MySqlParameter("@remark", MySqlDbType.VarChar) { Value = finishedProduct.remark},
              new MySqlParameter("@active", MySqlDbType.Int16) { Value =( Int16)IsActive.Yes},
              new MySqlParameter("@userId", MySqlDbType.Int64) { Value = finishedProduct.userId},
              new MySqlParameter("@clientIp", MySqlDbType.String) { Value = finishedProduct.clientIp},
                };
                string query = @"INSERT INTO finishedproductlog
                                    SELECT * FROM finishedproduct b
                                    WHERE b.productId = @productId; ";
                using (TransactionScope ts = new(TransactionScopeAsyncFlowOption.Enabled))
                {
                    if (isfinishedProductExists)
                    {
                        rb = await db.ExecuteQueryAsync(query, pm, "Saveblendingmaterialissuelog");
                        if (rb.status)
                        {
                            query = @"DELETE FROM finishedproduct 
                                    WHERE productId = @productId; ";
                            rb = await db.ExecuteQueryAsync(query, pm, "Deleteblendingmaster");
                            if (rb.status && oldQuantity > 0)
                            {
                                if (oldQuantity > (long)finishedProduct.totalQuantity!)
                                    finishedProduct.totalQuantity = oldQuantity - finishedProduct.totalQuantity;
                                else if (oldQuantity < (long)finishedProduct.totalQuantity!)
                                    finishedProduct.totalQuantity = finishedProduct.totalQuantity - oldQuantity;
                            }


                        }
                    }
                    else
                        rb.status = true;
                    if (rb.status)
                    {
                        query = @"INSERT INTO finishedproduct (productId, batchId, brandId, brandName, 
							totalQuantity,unitId, unitName,
								 remark,active,clientIp,userId) VALUES 
                                    (@productId,@batchId,@brandId,@brandName,@totalQuantity,
			                            @unitId,@unitName,@remark,
			                            	@active,@clientIp,@userId)";
                        rb = await db.ExecuteQueryAsync(query, pm, "insertfinishedproduct");
                        if (rb.status)
                        {
                            if (isFinalMasterProductExist)
                                rb = await IncreaseFinalProduct((long)finishedProduct.batchId!, (long)finishedProduct.brandId, (long)finishedProduct.totalQuantity);
                            else
                            {
                                query = @"INSERT INTO finishedproducmaster (batchId,brandId,brandName,totalQuantity, 
							balanceQuantity,unitId,unitName,remark,active,clientIp,userId) VALUES 
                                    (@batchId,@brandId,@brandName,@totalQuantity, 
							@balanceQuantity,@unitId,@unitName,@remark,@active,@clientIp,@userId)";

                                rb = await db.ExecuteQueryAsync(query, pm, "InsertfinishedproductMaster");
                            }
                        }

                        if (rb.status)
                            ts.Complete();
                    }
                }
                if (rb.status)
                {
                    rs.status = true;
                    rs.message = "Finished Product has been stocked ";
                }
                else
                {
                    rs = new();
                    rs.message = "Failed to stocked Finished Product";
                }
            }


            return rs;
        }
        /// <summary>
        /// Returns Generate Finished Product Id BatchId+ NNN
        /// </summary>
        /// <returns></returns>
        private async Task<ReturnClass.ReturnString> GenerateFinishedProductId(Int64 batchId)
        {
            ReturnClass.ReturnString rs = new();
            string query = @"SELECT IFNULL(MAX(SUBSTRING(b.productId,10,12)),0) + 1 AS productId
                             FROM finishedproduct b 
                                WHERE  
                                b.batchId=@batchId;";
            MySqlParameter[] pm = new MySqlParameter[] {

                    new MySqlParameter("@batchId", MySqlDbType.Int64) { Value = batchId},

                };
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            if (dt.table.Rows.Count > 0)
            {

                string id = batchId.ToString() + dt.table.Rows[0]["productId"].ToString().PadLeft(3, '0');
                rs.id = Convert.ToInt64(id);
                rs.status = true;
            }
            return rs;
        }
        /// <summary>
        /// Returns Get Finished Product Master Data
        /// </summary>
        /// <returns></returns>
        private async Task<ReturnClass.ReturnDataTable> GetFinishedProductMasterData(Int64 batchId, Int64 brandId)
        {
            ReturnClass.ReturnString rs = new();
            string where = "";
            if (batchId > 0)
                where += " AND fm.batchId=@batchId ";
            if (brandId > 0)
                where += " AND fm.brandId=@brandId ";
            //if (finishedProduct.productId > 0)
            //    where += " AND fm.productId=@productId ";


            string query = @"SELECT fm.batchId,fm.brandId,fm.brandName,fm.totalQuantity,fm.balanceQuantity,
                                fm.unitId,fm.unitName,fm.remark,fm.clientIp,fm.userId
                                    FROM finishedproducmaster fm WHERE fm.active=@active " + where;
            MySqlParameter[] pm = new MySqlParameter[] {

                    new MySqlParameter("@active", MySqlDbType.Int64) { Value =( Int16)IsActive.Yes},
                    new MySqlParameter("@batchId", MySqlDbType.Int64) { Value = batchId},
                    new MySqlParameter("@brandId", MySqlDbType.Int64) { Value = brandId},

                };
            return await db.ExecuteSelectQueryAsync(query, pm);
        }
        private async Task<ReturnClass.ReturnDataTable> GetFinishedProductSumData(FinishedProduct finishedProduct)
        {
            ReturnClass.ReturnString rs = new();
            string where = "";
            if (finishedProduct.batchId > 0)
                where += " AND fm.batchId=@batchId ";
            if (finishedProduct.brandId > 0)
                where += " AND fm.brandId=@brandId ";
            if (finishedProduct.productId > 0)
                where += " AND fm.productId=@productId ";


            string query = @"SELECT IFNULL(SUM(fm.totalQuantity),0) as totalQuantity                                                                           
                                    FROM finishedproduct fm WHERE fm.active=@active " + where;
            MySqlParameter[] pm = new MySqlParameter[] {

                    new MySqlParameter("@active", MySqlDbType.Int64) { Value =( Int16)IsActive.Yes},
                    new MySqlParameter("@batchId", MySqlDbType.Int64) { Value = finishedProduct.batchId},
                    new MySqlParameter("@brandId", MySqlDbType.Int64) { Value = finishedProduct.brandId},

                };
            return await db.ExecuteSelectQueryAsync(query, pm);
        }
        private async Task<bool> GetFinishedProductMasterData(FinishedProduct finishedProduct)
        {
            ReturnClass.ReturnString rs = new();
            string where = "";
            if (finishedProduct.batchId > 0)
                where += " AND fm.batchId=@batchId ";
            if (finishedProduct.brandId > 0)
                where += " AND fm.brandId=@brandId ";



            string query = @"SELECT fm.batchId                                                                           
                                    FROM finishedproducmaster fm WHERE fm.active=@active " + where;
            MySqlParameter[] pm = new MySqlParameter[] {

                    new MySqlParameter("@active", MySqlDbType.Int64) { Value =( Int16)IsActive.Yes},
                    new MySqlParameter("@batchId", MySqlDbType.Int64) { Value = finishedProduct.batchId},
                    new MySqlParameter("@brandId", MySqlDbType.Int64) { Value = finishedProduct.brandId},

                };
            bool istrue = false;
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            if (dt.table.Rows.Count > 0)
                istrue = true;
            return istrue;
        }



        /// <summary>
        /// 
        /// Get Blending Process List
        /// </summary>
        /// <returns>Verify OTP</returns>
        public async Task<ReturnDataSet> GetFinishedProductList(FinishedProduct finishedProduct)
        {
            string query = "";
            ReturnDataSet ds = new();
            finishedProduct.batchId = finishedProduct.batchId == null ? 0 : finishedProduct.batchId;
            finishedProduct.productId = finishedProduct.productId == null ? 0 : finishedProduct.productId;
            finishedProduct.brandId = finishedProduct.brandId == null ? 0 : finishedProduct.brandId;
            finishedProduct.active = finishedProduct.active == null ? 1 : finishedProduct.active;

            MySqlParameter[] pm = new MySqlParameter[]
           {
          new MySqlParameter("batchId", MySqlDbType.Int64) { Value = finishedProduct.batchId},
          new MySqlParameter("productId", MySqlDbType.Int64) { Value = finishedProduct.productId},
          new MySqlParameter("brandId", MySqlDbType.Int64) { Value = finishedProduct.brandId},
          new MySqlParameter("stockDate", MySqlDbType.DateTime) { Value = finishedProduct.stockDate},
          new MySqlParameter("lastIssueDate", MySqlDbType.DateTime) { Value = finishedProduct.lastIssueDate},
          new MySqlParameter("active", MySqlDbType.Int16) { Value = finishedProduct.active},


           };
            String WHERE = "";

            if (finishedProduct.batchId > 0)
                WHERE += @" AND fp.batchId=@batchId ";
            if (finishedProduct.brandId > 0)
                WHERE += @" AND fp.brandId=@brandId ";
            if (finishedProduct.productId > 0)
                WHERE += @" AND fp.productId=@productId ";
            if (finishedProduct.stockDate != null)
                WHERE += @" AND DATE_FORMAT(fp.stockDate,'%d/%m/%Y')=DATE_FORMAT(@stockDate,'%d/%m/%Y')";
            if (finishedProduct.lastIssueDate != null)
                WHERE += @" AND DATE_FORMAT(fp.lastIssueDate,'%d/%m/%Y')=DATE_FORMAT(@lastIssueDate,'%d/%m/%Y')";


            query = @"SELECT fp.productId,fp.batchId,fp.brandId,fp.brandName,
			fp.totalQuantity,fp.unitId,
				fp.unitName,fp.remark,fp.stockDate,fp.lastIssueDate 
				FROM finishedproduct fp 
				JOIN blendingmaster b ON b.batchId=fp.batchId				
				WHERE fp.active=@active " + WHERE + "  ORDER BY fp.productId DESC ";
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            ds.status = true;
            if (dt.table.Rows.Count > 0)
            {
                ds.dataset.Tables.Add(dt.table);

            }
            query = @" SELECT fm.brandName,fm.totalQuantity,fm.balanceQuantity ,
                         fm.unitId,fm.unitName,fm.remark 
                    FROM finishedproducmaster fm JOIN
                    finishedproduct fp ON fp.batchId = fm.batchId AND fm.brandId = fp.brandId			
				WHERE fp.active=@active " + WHERE + "  ORDER BY fm.brandName "; ;
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            ds.status = true;
            if (dt.table.Rows.Count > 0)
            {
                ds.dataset.Tables.Add(dt.table);

            }

            return ds;
        }

        #endregion

        #region Dispatch Finished Product

        /// <summary>
        /// Save Issue Packaging Material
        /// </summary>
        /// <param name="issueMaterial"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnString> SaveDispatch(Dispatch dispatch)
        {
            bool isBlendingProcessExistsI = false;
            ReturnClass.ReturnString rs = new();
            dispatch.dispatchId = dispatch.dispatchId == null ? 0 : dispatch.dispatchId;
            dispatch.quantity = dispatch.dispatchDetails.Sum(x => x.quantity);
            //    await DispatchExists((Int16)dispatch.dispatchId!, (Int32)dispatch.brandId!);
            //isBlendingProcessExistsI = rs.status;
            if (dispatch.dispatchId == 0)
            {
                rs = await GenerateDispatchID();
                if (rs.status)
                    dispatch.dispatchId = rs.id;
            }
            else
                isBlendingProcessExistsI = true;
            if (dispatch.dispatchDetails[0].batchId == 0)
            {
                rs.status = false;
                rs.message = "Invalid Details BatchId.";
            }
            DlCommon dlCommon = new();

            MySqlParameter[] pm = new MySqlParameter[] {

                    new MySqlParameter("@dispatchId", MySqlDbType.Int64) { Value = dispatch.dispatchId}
                };
            string query = @"INSERT INTO dispatchmasterlog
                                    SELECT * FROM dispatchmaster b
                                    WHERE b.dispatchId = @dispatchId; ";
            using (TransactionScope ts = new(TransactionScopeAsyncFlowOption.Enabled))
            {
                if (isBlendingProcessExistsI)
                {
                    rb = await db.ExecuteQueryAsync(query, pm, "SavedispatchIdmasterlog");
                    if (rb.status)
                    {
                        query = @"DELETE FROM dispatchIdmaster 
                                    WHERE dispatchId = @dispatchId; ";
                        rb = await db.ExecuteQueryAsync(query, pm, "Deleteblendingmaster");
                        if (rb.status)
                        {
                            query = @"INSERT INTO dispatchdetaillog
                                    SELECT * FROM dispatchdetail b
                                    WHERE b.dispatchId = @dispatchId; ";
                            rb = await db.ExecuteQueryAsync(query, pm, "Insertblendingitemlog");
                            if (rb.status)
                            {
                                query = @"DELETE FROM dispatchdetail 
                                    WHERE dispatchId = @dispatchId; ";
                                rb = await db.ExecuteQueryAsync(query, pm, "Deleteblendingitem");
                            }
                        }
                    }
                }
                else
                    rb.status = true;
                if (rb.status)
                {
                    rb = await AddDispatchItem(dispatch, isBlendingProcessExistsI, 1);
                    if (rb.status)
                        ts.Complete();
                }
            }
            if (rb.status)
            {
                rs.status = true;
                rs.message = "Product has been Dispatched ";
            }
            else
            {
                rs = new();
                rs.message = "Failed to Dispatched Product";
            }



            return rs;
        }
        private async Task<ReturnClass.ReturnString> DispatchExists(Int64 batchId, Int32 brandId, Int64 loadingId)
        {
            ReturnClass.ReturnString rs = new();
            string query = @"SELECT e.batchId,dispatchId,quantity
                             FROM dispatchdetail e 
                                WHERE  
                                e.batchId = @batchId AND e.brandId=@brandId  
                                        AND loadingId=@loadingId;";
            MySqlParameter[] pm = new MySqlParameter[] {

                    new MySqlParameter("@batchId", MySqlDbType.Int64) { Value = batchId},
                    new MySqlParameter("@loadingId", MySqlDbType.Int64) { Value = loadingId},
                    new MySqlParameter("@brandId", MySqlDbType.Int32) { Value = brandId}
                };
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            rs.status = false;
            if (dt.table.Rows.Count > 0)
            {
                rs.status = true;
                rs.message = "Blending Process Exists";
            }
            return rs;
        }

        /// <summary>
        /// Returns Generate Dispatch ID 7+DDMM + NNN NN
        /// </summary>
        /// <returns></returns>
        private async Task<ReturnClass.ReturnString> GenerateDispatchID()
        {
            ReturnClass.ReturnString rs = new();
            string query = @"SELECT IFNULL(MAX(SUBSTRING(e.dispatchId,6,10)),0) + 1 AS  dispatchId
                             FROM dispatchdetail e 
                                WHERE  
                                DATE_FORMAT(e.creationTimeStamp,'%d/%m/%Y') = DATE_FORMAT(NOW(),'%d/%m/%Y');";

            dt = await db.ExecuteSelectQueryAsync(query);
            if (dt.table.Rows.Count > 0)
            {

                string id = ((int)PrefixId.Dispatch).ToString() + DateTime.Now.ToString("yyMM") + dt.table.Rows[0]["dispatchId"].ToString()!.PadLeft(5, '0');
                rs.id = Convert.ToInt64(id);
                rs.status = true;
            }
            return rs;
        }
        private async Task<ReturnClass.ReturnBool> AddDispatchItem(Dispatch dispatch, bool isfinishedProductExists, int counter = 0)
        {

            ReturnString rs1 = new();
            string query = "";
            string query1 = "";
            string billTNo = "SF" + dispatch.dispatchId.ToString();
            List<MySqlParameter> pm1 = new();
            query = @"INSERT INTO dispatchmaster (dispatchId,loadingId,	quantity,remark,
                                                billTNo,active,clientIp,userId) 
                                                VALUES 
                                    (@dispatchId,@loadingId,@quantity,@remark,
                                                @billTNo,@active,@clientIp,@userId)";

            MySqlParameter[] pm = new MySqlParameter[] {
              new MySqlParameter("@dispatchId", MySqlDbType.Int64) { Value = dispatch.dispatchId},
              new MySqlParameter("@loadingId", MySqlDbType.Int64) { Value = dispatch.loadingId},
              new MySqlParameter("@quantity", MySqlDbType.Decimal) { Value = dispatch.quantity},
              //new MySqlParameter("@unitId"+counter.ToString(), MySqlDbType.Int16) { Value = dispatch.unitId},
             // new MySqlParameter("@unitName"+counter.ToString(), MySqlDbType.VarChar) { Value = dispatch.unitName},
              new MySqlParameter("@remark", MySqlDbType.VarChar) { Value = dispatch.remark},
              new MySqlParameter("@billTNo", MySqlDbType.VarChar) { Value =billTNo},
              new MySqlParameter("@active", MySqlDbType.Int16) { Value =( Int16)IsActive.Yes},
               new MySqlParameter("@userId", MySqlDbType.Int64) { Value = dispatch.userId},
                new MySqlParameter("@clientIp", MySqlDbType.String) { Value = dispatch.clientIp},
                };

            query1 = @"INSERT INTO dispatchdetail (dispatchId,batchId,brandId,brandName,
							                        quantity,unitId,unitName,active,clientIp,userId) 
                                                VALUES ";
            foreach (DispatchDetail dispatchDetail in dispatch.dispatchDetails)
            {
                //dt = await GetFinishedProductMasterData((long)dispatchDetail.batchId!, (long)dispatchDetail.brandId!);
                //if (dt.table.Rows.Count == 0)
                //{
                //    rs.status = false;
                //    rs.message = "Stock Not Available.";
                //    return rs;
                //}
                //else
                //{
                //    if ((long)dispatchDetail.quantity! > Convert.ToDecimal(dt.table.Rows[0]["balanceQuantity"].ToString()))
                //    {
                //        rs.status = false;
                //        rs.message = "quantity not Available in Stock.";
                //        return rs;
                //    }
                //}
                pm1.Add(new MySqlParameter("@dispatchId" + counter.ToString(), MySqlDbType.Int64) { Value = dispatch.dispatchId });
                pm1.Add(new MySqlParameter("@batchId" + counter.ToString(), MySqlDbType.Int64) { Value = dispatchDetail.batchId });

                pm1.Add(new MySqlParameter("@brandId" + counter.ToString(), MySqlDbType.Int64) { Value = dispatchDetail.brandId });
                pm1.Add(new MySqlParameter("@brandName" + counter.ToString(), MySqlDbType.VarChar) { Value = dispatchDetail.brandName });
                pm1.Add(new MySqlParameter("@quantity" + counter.ToString(), MySqlDbType.Decimal) { Value = dispatchDetail.quantity });
                pm1.Add(new MySqlParameter("@unitId" + counter.ToString(), MySqlDbType.Int16) { Value = dispatchDetail.unitId });
                pm1.Add(new MySqlParameter("@unitName" + counter.ToString(), MySqlDbType.VarChar) { Value = dispatchDetail.unitName });
                pm1.Add(new MySqlParameter("@active" + counter.ToString(), MySqlDbType.Int16) { Value = (Int16)IsActive.Yes });
                pm1.Add(new MySqlParameter("@userId" + counter.ToString(), MySqlDbType.Int64) { Value = dispatch.userId });
                pm1.Add(new MySqlParameter("@clientIp" + counter.ToString(), MySqlDbType.String) { Value = dispatch.clientIp });

                query1 += @"(@dispatchId" + counter.ToString() + @",@batchId" + counter.ToString() + @",@brandId" + counter.ToString() +
                            @",@brandName" + counter.ToString() + @",@quantity" + counter.ToString()
                            + @",@unitId" + counter.ToString() + @",@unitName" + counter.ToString() +
                            @",@active" + counter.ToString() + @",@clientIp" + counter.ToString() + @",@userId" + counter.ToString() + @"),";

                rb = await DecreaseFinalProduct((long)dispatchDetail.batchId!, (long)dispatchDetail.brandId, (long)dispatchDetail.quantity);
                if (!rb.status)
                {
                    rb.status = false;
                    rb.message = "Something Went Wrong";
                    return rb;
                }
                counter++;
            }
            query1 = query1.TrimEnd(',');
            rb = await db.ExecuteQueryAsync(query, pm, "insertdispatchMaster");
            if (rb.status)
                rb = await db.ExecuteQueryAsync(query1, pm1.ToArray(), "insertdispatchdetail");
            return rb;
        }
        /// <summary>
        /// 
        /// Get Dispatch List
        /// </summary>
        /// <returns></returns>
        public async Task<ReturnDataSet> GetDispatchList(DispatchSearch dispatch)
        {
            string query = "";
            ReturnDataSet ds = new();
            dispatch.batchId = dispatch.batchId == null ? 0 : dispatch.batchId;

            dispatch.brandId = dispatch.brandId == null ? 0 : dispatch.brandId;
            // dispatch.active = dispatch.active == null ? 1 : dispatch.active;

            MySqlParameter[] pm = new MySqlParameter[]
           {
               new MySqlParameter("batchId", MySqlDbType.Int64) { Value = dispatch.batchId},

               new MySqlParameter("brandId", MySqlDbType.Int64) { Value = dispatch.brandId},
               //new MySqlParameter("stockDate", MySqlDbType.DateTime) { Value = dispatch.stockDate},
               //new MySqlParameter("lastIssueDate", MySqlDbType.DateTime) { Value = dispatch.lastIssueDate},
               new MySqlParameter("active", MySqlDbType.Int16) { Value = (Int16)YesNo.Yes},


           };
            String WHERE = "";
            if (dispatch.dispatchId > 0)
                WHERE += @" AND d.dispatchId=@dispatchId ";
            if (dispatch.batchId > 0)
                WHERE += @" AND d.batchId=@batchId ";
            if (dispatch.batchId > 0)
                WHERE += @" AND d.batchId=@batchId ";
            if (dispatch.loadingId > 0)
                WHERE += @" AND dm.loadingId=@loadingId ";

            //if (dispatch. != null)
            //    WHERE += @" AND DATE_FORMAT(fp.stockDate,'%d/%m/%Y')=DATE_FORMAT(@stockDate,'%d/%m/%Y')";
            //if (dispatch.lastIssueDate != null)
            //    WHERE += @" AND DATE_FORMAT(fp.lastIssueDate,'%d/%m/%Y')=DATE_FORMAT(@lastIssueDate,'%d/%m/%Y')";


            query = @"SELECT d.dispatchId,d.batchId,d.brandId,d.brandName,
							d.quantity,d.unitId,d.unitName,b.balanceQuantity,
                        DATE_FORMAT(dm.creationTimeStamp ,'%d/%m/%Y') as dispatchDate,
                        dm.loadingId,dm.billTNo
        	FROM dispatch d 
            JOIN dispatchmaster dm ON d.dispatchId=dm.dispatchId
        	JOIN finishedproducmaster b ON b.batchId=d.batchId AND b.brandId=d.brandId				
        	WHERE d.active=@active " + WHERE + " ORDER BY d.dispatchId DESC";
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            if (dt.table.Rows.Count > 0)
            {
                ds.status = true;
                ds.dataset.Tables.Add(dt.table);

            }
            return ds;
        }
        #endregion


        #region Waste Manegement

        /// <summary>
        /// Save Waste Detail
        /// </summary>
        /// <param name="wasteDetail"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnString> SaveWasteDetail(WasteDetail wasteDetail)
        {
            ReturnClass.ReturnString rs = new();
            DlCommon dlCommon = new();
            using (TransactionScope ts = new(TransactionScopeAsyncFlowOption.Enabled))
            {
                rb = await AddWasteItem(wasteDetail);

                if (rb.status)
                {
                    if (wasteDetail.wasteCategoryId == (Int16)WasteCategory.Items)
                        rb = await wastageItemfromStockAsync((long)wasteDetail.itemStockId!);
                    else if (wasteDetail.wasteCategoryId == (Int16)WasteCategory.Blending)
                        rb = await wastageItemfromBlendingProcess((long)wasteDetail.batchId!, (Int32)wasteDetail.itemId!);
                    else if (wasteDetail.wasteCategoryId == (Int16)WasteCategory.Dispatch)
                        rb = await wastageInFinalProductDuringDispatch((long)wasteDetail.batchId!, (Int32)wasteDetail.brandId!, (Int64)wasteDetail.quantity!);
                    if (rb.status)
                    {
                        ts.Complete();
                        rs.status = true;
                        rs.message = "Waste Details Saved ";
                    }
                }
                else
                {
                    rs = new();
                    rs.message = "Failed to Save Waste Details";
                }
            }


            return rs;
        }

        private async Task<ReturnClass.ReturnBool> AddWasteItem(WasteDetail wasteDetail)
        {
            string query = "";
            List<MySqlParameter> pm1 = new();
            query = @"INSERT INTO wastedetail (wasteCategoryId,wasteCategory,quantity,remark,
                                                brandId,brandName,batchId,itemId,itemName,itemStockId,
                                                active,clientIp,userId) 
                                                VALUES 
                                    (@wasteCategoryId,@wasteCategory,@quantity,@remark,
                                                @brandId,@brandName,@batchId,@itemId,@itemName,@itemStockId,
                                                @active,@clientIp,@userId)";
            MySqlParameter[] pm = new MySqlParameter[] {
              new MySqlParameter("@wasteCategoryId", MySqlDbType.Int64) { Value = wasteDetail.wasteCategoryId},
              new MySqlParameter("@wasteCategory", MySqlDbType.Int64) { Value = wasteDetail.wasteCategory},
              new MySqlParameter("@quantity", MySqlDbType.Decimal) { Value = wasteDetail.quantity},
               new MySqlParameter("@brandId", MySqlDbType.Int32) { Value =wasteDetail.brandId},
              new MySqlParameter("@brandName", MySqlDbType.VarChar) { Value = wasteDetail.brandName},
               new MySqlParameter("@batchId", MySqlDbType.Int64) { Value =wasteDetail.batchId},
                new MySqlParameter("@itemId", MySqlDbType.Int32) { Value =wasteDetail.itemId},
              new MySqlParameter("@itemName", MySqlDbType.VarChar) { Value = wasteDetail.itemName},
               new MySqlParameter("@itemStockId", MySqlDbType.Int64) { Value =wasteDetail.itemStockId},
              new MySqlParameter("@remark", MySqlDbType.VarChar) { Value = wasteDetail.remark},
              new MySqlParameter("@active", MySqlDbType.Int16) { Value =( Int16)IsActive.Yes},
               new MySqlParameter("@userId", MySqlDbType.Int64) { Value = wasteDetail.userId},
                new MySqlParameter("@clientIp", MySqlDbType.String) { Value = wasteDetail.clientIp},
                };
            rb = await db.ExecuteQueryAsync(query, pm, "insertwastedetail");

            return rb;
        }
        /// <summary>
        /// 
        /// Get Dispatch List
        /// </summary>
        /// <returns></returns>
        public async Task<ReturnDataSet> GetWasteList(WasteDetail WasteDetail)
        {
            string query = "";
            ReturnDataSet ds = new();
            WasteDetail.batchId = WasteDetail.batchId == null ? 0 : WasteDetail.batchId;
            WasteDetail.brandId = WasteDetail.brandId == null ? 0 : WasteDetail.brandId;
            WasteDetail.itemId = WasteDetail.itemId == null ? 0 : WasteDetail.itemId;
            WasteDetail.itemStockId = WasteDetail.itemStockId == null ? 0 : WasteDetail.itemStockId;
            WasteDetail.brandId = WasteDetail.brandId == null ? 0 : WasteDetail.brandId;


            MySqlParameter[] pm = new MySqlParameter[]
           {


               new MySqlParameter("wasteCategoryId", MySqlDbType.Int16) { Value = WasteDetail.wasteCategoryId},
               new MySqlParameter("brandId", MySqlDbType.Int64) { Value = WasteDetail.brandId},
               new MySqlParameter("itemId", MySqlDbType.Int64) { Value = WasteDetail.itemId},
               new MySqlParameter("itemStockId", MySqlDbType.Int64) { Value = WasteDetail.itemStockId},
               new MySqlParameter("batchId", MySqlDbType.Int64) { Value = WasteDetail.batchId},
               //new MySqlParameter("stockDate", MySqlDbType.DateTime) { Value = dispatch.stockDate},
               //new MySqlParameter("lastIssueDate", MySqlDbType.DateTime) { Value = dispatch.lastIssueDate},
               new MySqlParameter("active", MySqlDbType.Int16) { Value = (Int16)YesNo.Yes},


           };
            String WHERE = "";
            if (WasteDetail.brandId > 0)
                WHERE += @" AND w.brandId=@brandId ";
            if (WasteDetail.itemId > 0)
                WHERE += @" AND w.itemId=@itemId ";
            if (WasteDetail.itemStockId > 0)
                WHERE += @" AND w.itemStockId=@itemStockId ";
            if (WasteDetail.batchId > 0)
                WHERE += @" AND w.batchId=@batchId ";

            query = @"SELECT w.wasteId,w.wasteCategoryId,w.wasteCategory,w.itemId,
                            w.itemStockId,w.quantity,w.remark,w.itemName,w.brandName
                        FROM wastedetail w 
                        WHERE w.wasteCategoryId=@wasteCategoryId AND w.active=@active
                         " + WHERE + " ORDER BY w.creationTimeStamp DESC;";
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            if (dt.table.Rows.Count > 0)
            {
                ds.status = true;
                ds.dataset.Tables.Add(dt.table);

            }
            return ds;
        }

        public async Task<ReturnClass.ReturnBool> wastageItemfromStockAsync(Int64 ItemStockId)
        {
            ReturnBool rb = new();
            ReturnDataTable dt1 = await GetItemQuantityInStock(ItemStockId);
            if (dt1.table.Rows.Count == 0)
            {
                rb.message = "Invalid Details Provided.";
                return rb;
            }
            Int32 itemId = Convert.ToInt32(dt1.table.Rows[0]["itemId"].ToString());
            Int64 quantity = Convert.ToInt64(dt1.table.Rows[0]["quantity"].ToString());

            MySqlParameter[] pm = new MySqlParameter[] {

                    new MySqlParameter("@itemStockId", MySqlDbType.Int64) { Value = ItemStockId},
                     new MySqlParameter("@itemId", MySqlDbType.Int32) { Value = itemId},
                     new MySqlParameter("@quantity", MySqlDbType.Int64) { Value = quantity},
                };


            string query = @"INSERT INTO itemstockdetaillog
                                    SELECT * FROM itemstockdetail i
                                    WHERE i.itemStockId = @itemStockId; ";
            using (TransactionScope ts = new(TransactionScopeAsyncFlowOption.Enabled))
            {

                rb = await db.ExecuteQueryAsync(query, pm, "Saveitemstockdetaillog");
                if (rb.status)
                {
                    query = @"UPDATE itemstockdetail SET quantity=0 
                                    WHERE itemStockId = @itemStockId; ";
                    if (rb.status)
                        rb = await db.ExecuteQueryAsync(query, pm, "Wastageitemstockdetail");
                    if (rb.status)
                        rb = await DecreaseItems((Int32)itemId!, (long)quantity!);
                    if (rb.status)
                        ts.Complete();
                }


            }

            return rb;
        }

        public async Task<ReturnClass.ReturnBool> wastageItemfromBlendingProcess(Int64 batchId, Int32 itemId)
        {
            ReturnBool rb = new();
            ReturnDataTable dt1 = await GetItemQuantityfromBlendingProcess(batchId, itemId);
            if (dt1.table.Rows.Count == 0)
            {
                rb.message = "Invalid Details Provided.";
                return rb;
            }
            itemId = Convert.ToInt32(dt1.table.Rows[0]["itemId"].ToString());
            Int64 quantity = Convert.ToInt64(dt1.table.Rows[0]["quantity"].ToString());

            MySqlParameter[] pm = new MySqlParameter[] {

                    new MySqlParameter("@batchId", MySqlDbType.Int64) { Value = batchId},
                     new MySqlParameter("@itemId", MySqlDbType.Int32) { Value = itemId},
                     new MySqlParameter("@quantity", MySqlDbType.Int64) { Value = quantity},
                };
            string query = @"INSERT INTO blendingitemlog
                                    SELECT * FROM blendingitem i
                                    WHERE i.batchId = @batchId AND i.itemId=@itemId ; ";
            using (TransactionScope ts = new(TransactionScopeAsyncFlowOption.Enabled))
            {

                rb = await db.ExecuteQueryAsync(query, pm, "Saveblendingitemlog");
                if (rb.status)
                {
                    query = @"UPDATE blendingitem SET quantity=0
                                    WHERE batchId = @batchId AND itemId=@itemId; ";
                    if (rb.status)
                        rb = await db.ExecuteQueryAsync(query, pm, "Wastageblendingitem");
                    if (rb.status)
                        rb = await DecreaseBlendingMaster((long)batchId!, (long)quantity!);
                    if (rb.status)
                        ts.Complete();
                }


            }

            return rb;
        }
        public async Task<ReturnClass.ReturnBool> wastageInFinalProductDuringDispatch(Int64 batchId, Int32 brandId, Int64 quantity)
        {
            ReturnBool rb = new();
            rb = await DecreaseFinalProduct((long)batchId!, (long)brandId, (long)quantity);
            if (!rb.status)
            {
                rb.status = false;
                rb.message = "Something Went Wrong";
                return rb;
            }

            return rb;
        }
        #endregion



        #region Item Master Sale And purches
        private async Task<ReturnClass.ReturnBool> IncreaseItems(Int32 itemId, long quantity)
        {
            string updateQuery = @"UPDATE itemmaster SET 
                                            quantity= quantity + @quantity 
                                            WHERE itemId=@itemId ;";
            MySqlParameter[] pm = new MySqlParameter[] {
              new MySqlParameter("@itemId", MySqlDbType.Int32) { Value = itemId},
              new MySqlParameter("@quantity", MySqlDbType.Int64) { Value = quantity}
            };
            return await db.ExecuteQueryAsync(updateQuery, pm.ToArray(), "IncreaseItemsMaster");

        }
        private async Task<ReturnClass.ReturnBool> DecreaseItems(Int32 itemId, long quantity)
        {
            string updateQuery = @"UPDATE itemmaster SET 
                                            quantity= quantity - @quantity 
                                            WHERE itemId=@itemId ;";
            MySqlParameter[] pm = new MySqlParameter[] {
              new MySqlParameter("@itemId", MySqlDbType.Int32) { Value = itemId},
              new MySqlParameter("@quantity", MySqlDbType.Int64) { Value = quantity}
            };
            return await db.ExecuteQueryAsync(updateQuery, pm.ToArray(), "DecreaseItemsMaster");

        }
        #endregion
        #region Final Product Sale And purches
        private async Task<ReturnClass.ReturnBool> IncreaseFinalProduct(Int64 batchId, Int64 brandId, long quantity)
        {
            string updateQuery = @"UPDATE finishedproducmaster SET 
                                            
                                        balanceQuantity= balanceQuantity + @quantity 
                                            WHERE batchId=@batchId AND brandId=@brandId ;";
            //totalQuantity= totalQuantity + @quantity ,
            MySqlParameter[] pm = new MySqlParameter[] {
              new MySqlParameter("@batchId", MySqlDbType.Int32) { Value = batchId},
              new MySqlParameter("@brandId", MySqlDbType.Int32) { Value = brandId},
              new MySqlParameter("@quantity", MySqlDbType.Int64) { Value = quantity}
            };
            return await db.ExecuteQueryAsync(updateQuery, pm.ToArray(), "IncreaseFinalProduct");

        }
        private async Task<ReturnClass.ReturnBool> DecreaseFinalProduct(Int64 batchId, Int64 brandId, long quantity)
        {
            string updateQuery = @"UPDATE finishedproducmaster SET                                            
                                        balanceQuantity= balanceQuantity - @quantity 
                                            WHERE batchId=@batchId AND brandId=@brandId  ;";
            // totalQuantity= totalQuantity - @quantity ,
            MySqlParameter[] pm = new MySqlParameter[] {
              new MySqlParameter("@batchId", MySqlDbType.Int32) { Value = batchId},
              new MySqlParameter("@brandId", MySqlDbType.Int32) { Value = brandId},
              new MySqlParameter("@quantity", MySqlDbType.Int64) { Value = quantity}
            };
            return await db.ExecuteQueryAsync(updateQuery, pm.ToArray(), "DecreaseFinalProduct");

        }


        #endregion

        #region Blending Master Production
        private async Task<ReturnClass.ReturnBool> IncreaseBlendingMaster(Int64 batchId, long quantity)
        {
            string updateQuery = @"UPDATE blendingmaster SET 
                                            
                                        balanceQuantity= balanceQuantity + @quantity 
                                            WHERE batchId=@batchId AND brandId=@brandId ;";
            //totalQuantity= totalQuantity + @quantity ,
            MySqlParameter[] pm = new MySqlParameter[] {
              new MySqlParameter("@batchId", MySqlDbType.Int32) { Value = batchId},
              new MySqlParameter("@quantity", MySqlDbType.Int64) { Value = quantity}
            };
            return await db.ExecuteQueryAsync(updateQuery, pm.ToArray(), "IncreaseFinalProduct");

        }
        private async Task<ReturnClass.ReturnBool> DecreaseBlendingMaster(Int64 batchId, long quantity)
        {
            string updateQuery = @"UPDATE blendingmaster SET 
                                            
                                        balanceQuantity= balanceQuantity - @quantity 
                                            WHERE batchId=@batchId AND brandId=@brandId  ;";
            //totalQuantity= totalQuantity + @quantity ,
            MySqlParameter[] pm = new MySqlParameter[] {
              new MySqlParameter("@batchId", MySqlDbType.Int32) { Value = batchId},
              new MySqlParameter("@quantity", MySqlDbType.Int64) { Value = quantity}
            };
            return await db.ExecuteQueryAsync(updateQuery, pm.ToArray(), "DecreaseBlendingMaster");

        }


        #endregion


    }


}

