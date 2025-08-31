using BaseClass;
using Microsoft.JSInterop;
using MySqlConnector;
using ScottmenMainApi.Models.BLayer;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Transactions;
using static BaseClass.ReturnClass;
using static ScottmenMainApi.Models.BLayer.BlCommon;
using ListValue = BaseClass.ListValue;

namespace ScottmenMainApi.Models.DLayer
{
    public class DlCommon
    {
        readonly DBConnection db = new();
        ReturnClass.ReturnDataTable dt = new();
        ReturnClass.ReturnBool rb = new();
        //IJSRuntime js;
        #region Verify Captch
        /// <summary>
        /// Verify captcha 
        /// </summary>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnBool> VerifyCaptchaAsync(string captchaID, string userEnteredCaptcha, string verificationUrl)
        {
            Uri url = new Uri(verificationUrl);
            HttpClient client = new();
            client.BaseAddress = url;
            client.DefaultRequestHeaders.Accept.Clear();
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));   //ACCEPT header
            rb = new();
            try
            {
                var request = new CaptchaReturnType
                {
                    captchaID = captchaID,
                    userEnteredCaptcha = userEnteredCaptcha
                };

                var content = JsonSerializer.Serialize(request);
                HttpResponseMessage response = await client.PostAsJsonAsync(verificationUrl, request);
                response.EnsureSuccessStatusCode(); // throws if not 200-299
                var contentStream = await response.Content.ReadAsStreamAsync();
                rb = await JsonSerializer.DeserializeAsync<ReturnClass.ReturnBool>(contentStream);
            }
            catch (Exception ex)
            {
                WriteLog.Error("VerifyCaptcha", ex);
            }
            return rb;
        }

        internal Task<List<ListValue>> GetCommonList(string category, LanguageSupported language, string v)
        {
            throw new NotImplementedException();
        }
        #endregion
        public async Task<List<ListValue>> GetStateAsync(LanguageSupported language)
        {
            string fieldLanguage = language == LanguageSupported.Hindi ? "Local" : "English";
            dt = await db.ExecuteSelectQueryAsync(@"SELECT  s.stateId as id, s.stateName" + fieldLanguage + @" as name
                                                    FROM state s
                                                    ORDER BY name");
            List<ListValue> lv = Helper.GetGenericDropdownList(dt.table);
            return lv;
        }
        /// <summary>
        /// Get List of District
        /// </summary>
        /// <returns></returns>
        public async Task<List<ListValue>> GetDistrictAsync(int stateId, LanguageSupported language)
        {
            string fieldLanguage = language == LanguageSupported.Hindi ? "Local" : "English";
            string query = @"SELECT d.districtId AS id, d.districtName" + fieldLanguage + @" AS name
                             FROM district d
                             WHERE d.stateId = @stateId
                             ORDER BY name";
            MySqlParameter[] pm = new MySqlParameter[]
            {
                new MySqlParameter("stateId", MySqlDbType.Int16) { Value= stateId }
            };
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            List<ListValue> lv = Helper.GetGenericDropdownList(dt.table);
            return lv;
        }
        public async Task<List<ListValue>> GetBaseDepartmentAsync(int stateId, LanguageSupported language)
        {
            string fieldLanguage = language == LanguageSupported.Hindi ? "Local" : "English";
            string query = @"SELECT b.baseDeptId AS id, b.deptName" + fieldLanguage + @" as name 
                             FROM basedepartment b
                             WHERE b.stateId = @stateId and b.isActive = @isActive
                             ORDER BY name";
            MySqlParameter[] pm = new MySqlParameter[]
            {
                new MySqlParameter("isActive", MySqlDbType.Int16) { Value = IsActive.Yes },
                new MySqlParameter("stateId", MySqlDbType.Int16) { Value = stateId }
            };
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            List<ListValue> lv = Helper.GetGenericDropdownList(dt.table);
            return lv;
        }
        #region Get Common List from DDL Cat List
        /// <summary>
        ///Get Category List from ddlCat
        /// </summary>
        /// <returns></returns>
        public async Task<List<ListValue>> GetCommonListAsync(string category, LanguageSupported language)
        {
            string fieldLanguage = language == LanguageSupported.Hindi ? "Local" : "English";
            string query = @"SELECT d.id AS id, d.name" + fieldLanguage + @" AS name, d.grouping as extraField,
                                    d.remark AS extraField1
                                 FROM ddlcatlist d
                             WHERE d.isActive = @isActive AND d.category = @category
                                AND d.hideFromPublicAPI = @hideFromPublicAPI AND d.isStateSpecific=@isStateSpecific
                             ORDER BY d.sortOrder";
            MySqlParameter[] pm = new MySqlParameter[]
            {
                new MySqlParameter("hideFromPublicAPI", MySqlDbType.Int16){ Value=(int) YesNo.No},
                new MySqlParameter("isActive", MySqlDbType.Int16){ Value = (int) IsActive.Yes},
                new MySqlParameter("isStateSpecific", MySqlDbType.Int16){ Value= (int)YesNo.No},
                new MySqlParameter("category", MySqlDbType.String) { Value= category }
            };
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            List<ListValue> lv = Helper.GetGenericDropdownList(dt.table);
            return lv;
        }
        /// <summary>
        ///Get Sub category List from ddlCat
        /// </summary>
        /// <returns></returns>
        public async Task<List<ListValue>> GetSubCommonListAsync(string category, string id, LanguageSupported language)
        {
            string fieldLanguage = language == LanguageSupported.Hindi ? "Local" : "English";
            string query = @"SELECT d.id AS id, d.name" + fieldLanguage + @" AS name, d.grouping AS extraField
                             FROM ddlcatlist d
                             WHERE d.isActive = @isActive AND d.category = @category AND d.referenceId=@referenceId AND d.hideFromPublicAPI = @hideFromPublicAPI AND 
                                   d.isStateSpecific=@isStateSpecific
                             ORDER BY d.sortOrder, name";
            MySqlParameter[] pm = new MySqlParameter[]
            {
                new MySqlParameter("hideFromPublicAPI", MySqlDbType.Int16){ Value=(int) YesNo.No},
                new MySqlParameter("isActive", MySqlDbType.Int16){ Value = (int) IsActive.Yes},
                new MySqlParameter("isStateSpecific", MySqlDbType.Int16){ Value= (int)YesNo.No},
                new MySqlParameter("category", MySqlDbType.String) { Value= category },
                new MySqlParameter("referenceId", MySqlDbType.Int16){ Value= id},
            };
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            List<ListValue> lv = Helper.GetGenericDropdownList(dt.table);
            return lv;
        }
        #endregion
        #region Question Entry 

        public async Task<List<ListValue>> GetProjecttList(LanguageSupported language)
        {
            string fieldLanguage = language == LanguageSupported.Hindi ? "Local" : "English";
            string query = @"SELECT srp.swsProjectId AS id,srp.deptName" + fieldLanguage + @" AS name,srp.baseDeptId as extraField
	                           FROM swsregisteredprojects AS srp WHERE srp.accountVerificationStatus=@accountVerificationStatus ORDER BY name  ";
            MySqlParameter[] pm = new MySqlParameter[]
            {
                new MySqlParameter("accountVerificationStatus", MySqlDbType.Int16){ Value=(int) ActionStatus.Approved},

            };
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            List<ListValue> lv = Helper.GetGenericDropdownList(dt.table);
            return lv;
        }
        public async Task<List<ListValue>> GetServicetList(Int64 swsProjectId, LanguageSupported language)
        {
            string fieldLanguage = language == LanguageSupported.Hindi ? "Local" : "English";

            string query = @"SELECT sr.swsServiceId AS id,sr.serviceName AS name,sr.swsProjectId as extraField 
                            FROM swsserviceregistration sr 
                            WHERE sr.serviceVerificationStatus = @serviceVerificationStatus 
                            AND sr.swsProjectId=@swsProjectId AND sr.isActive=@isActive ORDER BY name ";
            MySqlParameter[] pm = new MySqlParameter[]
            {
                new MySqlParameter("serviceVerificationStatus", MySqlDbType.Int16){ Value=(int) ActionStatus.Approved},
                 new MySqlParameter("swsProjectId", MySqlDbType.Int64){ Value=swsProjectId},
                 new MySqlParameter("isActive", MySqlDbType.Int16){ Value=(int) IsActive.Yes},

            };
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            List<ListValue> lv = Helper.GetGenericDropdownList(dt.table);
            return lv;
        }
        public async Task<List<ListValue>> GetLiveServicetList(Int64 swsProjectId, LanguageSupported language)
        {
            string fieldLanguage = language == LanguageSupported.Hindi ? "Local" : "English";
            string where = "", addOther = "";
            if (swsProjectId > 0)
            {
                where = " AND sr.swsProjectId=@swsProjectId ";
            }
            else
                addOther = @"SELECT 0 AS id,'OTHER' AS NAME,0 as extraField ,1 as orderby
                                UNION ALL ";

            string query = addOther + @" 
                            SELECT sr.swsServiceId AS id,sr.serviceName AS name,sr.swsProjectId as extraField,0 as orderby 
                            FROM swsserviceregistration sr 
                            WHERE sr.serviceVerificationStatus = @serviceVerificationStatus " + where + @"
                            AND sr.isServiceLive=@isServiceLive AND sr.isActive=@isActive ORDER BY orderby,  name ";
            MySqlParameter[] pm = new MySqlParameter[]
            {
                new MySqlParameter("serviceVerificationStatus", MySqlDbType.Int16){ Value=(int) ActionStatus.Approved},
                 new MySqlParameter("isServiceLive", MySqlDbType.Int16){ Value=(int) YesNo.Yes},
                 new MySqlParameter("swsProjectId", MySqlDbType.Int64){ Value=swsProjectId},
                 new MySqlParameter("isActive", MySqlDbType.Int16){ Value=(int) IsActive.Yes},

            };
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            List<ListValue> lv = Helper.GetGenericDropdownList(dt.table);
            return lv;
        }
        #endregion   

        #region Event Log
        /// <summary>
        /// Generate Event Log
        /// </summary>
        /// <param name="el"></param>
        /// <returns></returns>
        public async Task<ReturnBool> CreateEventLog(EventLog el)
        {
            string query = @" INSERT INTO eventlog(logDescription, logCategory, logLevel, userId, sessionId, clientIp, clientOs, 
                                                   clientBrowser, userAgent) 
                                            VALUES(@logDescription, @logCategory, @logLevel, @userId, @sessionId, @clientIp, @clientOs, 
                                                   @clientBrowser, @userAgent) ";
            MySqlParameter[] pm = new MySqlParameter[]
            {
                new MySqlParameter("logDescription", MySqlDbType.VarChar) { Value = el.logDescription },
                new MySqlParameter("logCategory", MySqlDbType.Int16) { Value = (int)el.logCategory },
                new MySqlParameter("logLevel", MySqlDbType.Int16) { Value = (int)el.logLevel },
                new MySqlParameter("userId", MySqlDbType.Int64) { Value = el.userId },
                new MySqlParameter("sessionId", MySqlDbType.Int64) { Value = el.sessionId },
                new MySqlParameter("clientIp", MySqlDbType.VarChar) { Value = el.clientIp },
                new MySqlParameter("clientOs", MySqlDbType.VarChar) { Value = el.clientOs },
                new MySqlParameter("clientBrowser", MySqlDbType.VarChar) { Value = el.clientBrowser },
                new MySqlParameter("userAgent", MySqlDbType.VarString) { Value = el.userAgent },
            };
            rb = await db.ExecuteQueryAsync(query, pm, "CreateEventLog");
            return rb;
        }
        #endregion

        #region SMS Service
        /// <summary>
        /// Save Sent SMS Details
        /// </summary>
        /// <param name="sb"></param>
        /// <returns></returns>
        public async Task<ReturnBool> SendSmsSaveAsync(AlertMessageBody sb)
        {
            sb.messageServerResponse = sb.messageServerResponse == null ? "" : sb.messageServerResponse;
            sb.mobileNo = Convert.ToInt64(sb.mobileNo.ToString().Substring(sb.mobileNo.ToString().Length - 10));
            string query = @"INSERT INTO smssentdetail
                                          (msgId,msgServerResponse,mobileNo,emailId,msgCategory,msgBody,msgOtp,
                                           isOtpVerified,registrationId,actionId,clientIp)
                             VALUES(@msgId,@msgServerResponse,@mobileNo,@emailId,@msgCategory,@msgBody,@msgOtp,
                                           @isOtpVerified,@registrationId,@actionId,@clientIp)";
            //sb.msgId = Guid.NewGuid().ToString();
            sb.msgId = await GenerateSMSMsgId();

            List<MySqlParameter> pm = new()
            {
                new MySqlParameter("msgId", MySqlDbType.String) { Value = sb.msgId },
                new MySqlParameter("msgServerResponse", MySqlDbType.String) { Value = sb.messageServerResponse },
                new MySqlParameter("mobileNo", MySqlDbType.Int64) { Value = sb.mobileNo },
                new MySqlParameter("emailId", MySqlDbType.VarChar) { Value = sb.emailToReceiver },
                new MySqlParameter("msgCategory", MySqlDbType.Int16) { Value = sb.msgCategory },
                new MySqlParameter("msgBody", MySqlDbType.String) { Value = sb.smsBody },
                new MySqlParameter("msgOtp", MySqlDbType.VarChar) { Value = sb.OTP.ToString() },
                new MySqlParameter("isOtpVerified", MySqlDbType.Int32) { Value = (int)IsActive.No },
                new MySqlParameter("registrationId", MySqlDbType.Int64) { Value = sb.applicationId },
                new MySqlParameter("actionId", MySqlDbType.Int16) { Value = sb.actionId },
                new MySqlParameter("clientIp", MySqlDbType.String) { Value = sb.clientIp }
            };
            ReturnBool rb = await db.ExecuteQueryAsync(query, pm.ToArray(), "SaveSentSMS");
            if (rb.status)
                rb.message = sb.msgId;
            return rb;
        }
        /// <summary>
        /// Resend OTP 
        /// </summary>
        /// <returns></returns>
        public async Task<ReturnString> GetOTPMsgForResend(string msgId)
        {
            ReturnString rs = new();
            BlCommon bl = new();
            string query = @" SELECT s.mobileNo,s.msgBody,
                                    TIMESTAMPDIFF(MINUTE, s.sendingDatetime, CURRENT_TIMESTAMP()) AS SMSSentTime,
                                    TIMESTAMPDIFF(SECOND, s.sendingDatetime, CURRENT_TIMESTAMP()) AS SMSSentTimeInSecond
                            FROM smssentdetail s 
                            WHERE s.msgId=@msgId AND s.isOtpVerified=@isOtpVerified";
            List<MySqlParameter> pm = new List<MySqlParameter>
            {
                new MySqlParameter("msgId", MySqlDbType.String) { Value = msgId },
                new MySqlParameter("isOtpVerified", MySqlDbType.Int16) { Value = (int)IsActive.No }
            };
            ReturnDataTable dt = await db.ExecuteSelectQueryAsync(query, pm.ToArray());
            if (dt.table.Rows.Count > 0)
            {
                long validity = Convert.ToInt64(dt.table.Rows[0]["SMSSentTime"].ToString());
                if (validity > bl.smsvalidity)
                {
                    rs.status = false;
                    rs.message = "OTP expired!!!";
                }
                else
                {
                    rs.message = dt.table.Rows[0]["msgBody"].ToString();
                    rs.value = dt.table.Rows[0]["mobileNo"].ToString();
                    rs.status = true;
                }
            }
            return rs;
        }
        #endregion
        #region Email Service
        /// <summary>
        /// Save Sent SMS Details
        /// </summary>
        /// <param name="sb"></param>
        /// <returns></returns>
        public async Task<ReturnBool> SendEmailSaveAsync(AlertMessageBody sb)
        {
            //sb.msgId = Guid.NewGuid().ToString();
            //sb.mobileNo = Convert.ToInt64(sb.mobileNo.ToString().Substring(sb.mobileNo.ToString().Length - 10));
            sb.messageServerResponse = sb.messageServerResponse == null ? "0" : sb.messageServerResponse;
            string query = @"INSERT INTO emailsentdetail
                                            (msgId,msgServerResponse,mobileNo,emailId,msgCategory,msgBody,msgOtp,
                                             isOtpVerified,registrationId,actionId,clientIp)
                          VALUES(@msgId,@msgServerResponse,@mobileNo,@emailId,@msgCategory,@msgBody,@msgOtp,
                                             @isOtpVerified,@registrationId,@actionId,@clientIp)";
            List<MySqlParameter> pm = new()
            {
                new MySqlParameter("msgId", MySqlDbType.String) { Value = sb.msgId },
                new MySqlParameter("msgServerResponse", MySqlDbType.String) { Value = sb.messageServerResponse },
                new MySqlParameter("mobileNo", MySqlDbType.Int64) { Value = sb.mobileNo },
                new MySqlParameter("emailId", MySqlDbType.VarChar) { Value = sb.emailToReceiver },
                new MySqlParameter("msgCategory", MySqlDbType.Int16) { Value = sb.msgCategory },
                new MySqlParameter("msgBody", MySqlDbType.String) { Value = sb.emailBody },
                new MySqlParameter("msgOtp", MySqlDbType.VarChar) { Value = sb.emailOTP },
                new MySqlParameter("isOtpVerified", MySqlDbType.Int32) { Value = (int)IsActive.No },
                new MySqlParameter("registrationId", MySqlDbType.Int64) { Value = sb.applicationId },
                new MySqlParameter("actionId", MySqlDbType.Int16) { Value = sb.actionId },
                new MySqlParameter("clientIp", MySqlDbType.String) { Value = sb.clientIp }
            };
            ReturnBool rb = await db.ExecuteQueryAsync(query, pm.ToArray(), "SendEmailSaveAsync");

            if (rb.status)
                rb.message = sb.msgId;

            return rb;
        }
        /// <summary>
        /// Resend OTP 
        /// </summary>
        /// <returns></returns>
        public async Task<ReturnString> GetOTPemailForResend(string msgId)
        {
            ReturnString rs = new();
            BlCommon bl = new();
            string query = @" SELECT s.mobileNo,s.msgBody,
                                    TIMESTAMPDIFF(MINUTE, s.sendingDatetime, CURRENT_TIMESTAMP()) AS SMSSentTime
                             FROM emailsentdetail s 
                             WHERE s.msgId=@msgId AND s.isOtpVerified=@isOtpVerified";
            List<MySqlParameter> pm = new()
            {
                new MySqlParameter("msgId", MySqlDbType.String) { Value = msgId },
                new MySqlParameter("isOtpVerified", MySqlDbType.Int16) { Value = (int)IsActive.No }
            };
            ReturnDataTable dt = await db.ExecuteSelectQueryAsync(query, pm.ToArray());
            if (dt.table.Rows.Count > 0)
            {
                long validity = Convert.ToInt64(dt.table.Rows[0]["SMSSentTime"].ToString());
                if (validity > bl.smsvalidity)
                {
                    rs.status = false;
                    rs.message = "OTP expired!!!";
                }
                else
                {
                    rs.message = dt.table.Rows[0]["msgBody"].ToString();
                    rs.value = dt.table.Rows[0]["mobileNo"].ToString();
                    rs.status = true;
                }
            }
            return rs;
        }
        #endregion

        public async Task<List<ListData>> GetActivityList(ActivitySearch activitySearch)
        {
            MySqlParameter[] pm = new MySqlParameter[]
          {
                new MySqlParameter("activityName", MySqlDbType.String) { Value= activitySearch.activityName }
          };
            if (string.IsNullOrEmpty(activitySearch.activityName))
            {
                dt.message = "Activity Name Should not be Empty!!!";
            }
            string query = @"SELECT  * FROM  (SELECT  p.productCode  as id,p.description  as name, 1 AS label,'Manufacturing' AS extraField
                                FROM  productactivity p 
                                WHERE  p.productCode <> 0 AND  p.description LIKE '" + activitySearch.activityName + @"%'
                                UNION  
                                SELECT  p.productCode as id,p.description as name, 2 AS label, 'service' AS extraField
                                FROM  serviceactivity p 
                                WHERE   p.productCode <> 0 AND  p.description LIKE '" + activitySearch.activityName + @"%')tbl 
                                LIMIT  10";
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            List<ListData> lv = Helper.GetGenericlist(dt.table);
            return lv;

        }
        public async Task<List<ListValue>> GetSourceOfEnergy(LanguageSupported language)
        {
            string fieldLanguage = language == LanguageSupported.Hindi ? "Local" : "English";
            //
            string query = @"SELECT s.sourceOfEnergyId  AS id,s.sourceOfEnergyName AS name,s.unit AS extraField FROM sourceofenergy s ";
            dt = await db.ExecuteSelectQueryAsync(query);
            List<ListValue> lv = Helper.GetGenericDropdownList(dt.table);
            return lv;
        }

        public async Task<List<ListValue>> GetHSNList(ActivitySearch activitySearch)
        {
            string query = "";
            if (activitySearch.activityId == null)
                activitySearch.activityId = 0;
            List<ListValue> lv = new List<ListValue>();
            MySqlParameter[] pm = new MySqlParameter[]
          {
                new MySqlParameter("activityName", MySqlDbType.String) { Value= activitySearch.activityName },
                new MySqlParameter("activityId", MySqlDbType.Int16) { Value= activitySearch.activityId }
          };
            if (activitySearch.activityId != 0)
            {
                if (string.IsNullOrEmpty(activitySearch.activityName))
                {
                    dt.message = "Activity Name Should not be Empty!!!";
                }
                query = @"SELECT t.sacCode AS id,t.sacDetail AS name FROM saclist t WHERE t.SACType=3 AND t.SACDetail LIKE '" + activitySearch.activityName + @"%' LIMIT  10";
                if (activitySearch.activityId == 1)
                {
                    query = @"SELECT t.HSNcode AS id,t.HSNDetail AS name FROM hsnlist t WHERE  t.HSNType=4 AND t.HSNDetail LIKE '" + activitySearch.activityName + @"%' LIMIT  10";
                }
                dt = await db.ExecuteSelectQueryAsync(query, pm);
            }
            if (dt.table.Rows.Count > 0)
                lv = Helper.GetGenericDropdownList(dt.table);

            return lv;

        }
        /// <summary>
        /// Get List of tehsil
        /// </summary>
        /// <returns></returns>
        public async Task<List<ListValue>> GetTehsilAsync(int districtId, LanguageSupported language)
        {
            string fieldLanguage = language == LanguageSupported.Hindi ? "Local" : "English";
            string query = @"SELECT DISTINCT t.tehsilId AS id,t.tehsilName AS name FROM tehsilview t 
                                WHERE t.districtId=@districtId
                             ORDER BY name";
            MySqlParameter[] pm = new MySqlParameter[]
            {
                new MySqlParameter("districtId", MySqlDbType.Int16) { Value= districtId }
            };
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            List<ListValue> lv = Helper.GetGenericDropdownList(dt.table);
            return lv;
        }
        /// <summary>
        /// Get List of Village
        /// </summary>
        /// <returns></returns>
        public async Task<List<ListValue>> GetVillageAsync(int districtId, int tehsilId, LanguageSupported language)
        {
            string fieldLanguage = language == LanguageSupported.Hindi ? "Local" : "English";
            string query = @"SELECT DISTINCT v.villageId AS id ,v.villageNameEnglish AS name,v.villageNameLocal AS extraField  
                             FROM villageview v 
                                WHERE v.districtId=@districtId AND  v.tehsilId=@tehsilId
                             ORDER BY name";
            MySqlParameter[] pm = new MySqlParameter[]
            {
                new MySqlParameter("districtId", MySqlDbType.Int16) { Value= districtId },
                 new MySqlParameter("tehsilId", MySqlDbType.Int32) { Value= tehsilId }
            };
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            List<ListValue> lv = Helper.GetGenericDropdownList(dt.table);
            return lv;
        }
        /// <summary>
        /// Get List of ULB
        /// </summary>
        /// <returns></returns>
        public async Task<List<ListValue>> GetULBAsync(int districtId, LanguageSupported language)
        {
            string fieldLanguage = language == LanguageSupported.Hindi ? "Local" : "English";
            string query = @"SELECT DISTINCT u.ulbId AS id,u.ulbName AS name ,u.ulbNameLocal AS extraField 
                                FROM ulbview u 
                                WHERE u.districtId=@districtId
                             ORDER BY name";
            MySqlParameter[] pm = new MySqlParameter[]
            {
                new MySqlParameter("districtId", MySqlDbType.Int16) { Value= districtId }
            };
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            List<ListValue> lv = Helper.GetGenericDropdownList(dt.table);
            return lv;
        }
        /// <summary>
        ///Get Category List from ddlCat
        /// </summary>
        /// <returns></returns>
        public async Task<List<ListData>> GetCommonDataAsync(string category, LanguageSupported language)
        {
            string fieldLanguage = language == LanguageSupported.Hindi ? "Local" : "English";
            string query = @"SELECT d.id AS id, d.name" + fieldLanguage + @" AS name, d.grouping as extraField,remark AS label,
                                    d.referenceId AS actionOrder
                             FROM ddlcatlist d
                             WHERE d.isActive = @isActive AND d.category = @category AND d.hideFromPublicAPI = @hideFromPublicAPI AND d.isStateSpecific=@isStateSpecific
                             ORDER BY d.sortOrder, name";
            MySqlParameter[] pm = new MySqlParameter[]
            {
                new MySqlParameter("hideFromPublicAPI", MySqlDbType.Int16){ Value= YesNo.No},
                new MySqlParameter("isActive", MySqlDbType.Int16){ Value = IsActive.Yes},
                new MySqlParameter("isStateSpecific", MySqlDbType.Int16){ Value= YesNo.No},
                new MySqlParameter("category", MySqlDbType.String) { Value= category }
            };
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            List<ListData> lv = Helper.GetGenericlist(dt.table);
            return lv;
        }
        /// <summary>
        ///Get Year For Unit
        /// </summary>
        /// <returns></returns>
        public async Task<List<ListValue>> GetYearForUnitAsync()
        {
            int year = DateTime.Now.Year;
            List<ListValue> lv = new List<ListValue>();
            ListValue ld = new();
            ld.name = year.ToString();
            ld.label = year.ToString();
            ld.value = year.ToString();
            lv.Add(ld);
            for (int i = 0; i < 5; i++)
            {
                year = year + 1;
                ld = new();
                ld.name = year.ToString();
                ld.label = year.ToString();
                ld.value = year.ToString();
                lv.Add(ld);

            }
            return lv;
        }

        /// <summary>
        ///Send Message Via Sandesh appsync with Template
        /// </summary>
        /// <returns></returns>
        public async Task<ReturnBool> SendSandesh(sandeshMessageBody sandeshMessageBody, SMSParam sMSParam)
        {
            SandeshResponse returnBool = new SandeshResponse();
            string mobileno = sandeshMessageBody.contact.Substring(sandeshMessageBody.contact.ToString().Length - 10);
            Match match = Regex.Match(mobileno.ToString(),
                              @"^[6-9]\d{9}$", RegexOptions.IgnoreCase);
            if (match.Success == false)
            {
                rb.status = false;
                rb.message = "Invalid Mobile Number";
                return rb;
            }
            SandeshSms sms = new SandeshSms();
            sandeshMessageBody.contact = mobileno;
            sandeshMessageBody.msgCategory = (Int16)SandeshmsgCategory.Info;
            sandeshMessageBody.msgPriority = (Int16)SandeshmsgPriority.HighVolatile;
            sandeshMessageBody.templateId = sandeshMessageBody.templateId == null ? 0 : sandeshMessageBody.templateId;

            EmailResponse smsResponse = new EmailResponse();
            smsResponse.status = "true";
            string sandeshSmsisActive = Utilities.GetAppSettings("sandeshSmsConfig", "isActive").message;
            ReturnDataTable dtsmstemplate = await GetSMSEmailTemplate((Int32)sandeshMessageBody.templateId!);
            if (dtsmstemplate.table.Rows.Count > 0)
            {
                #region create Parameter To send SMS
                sandeshMessageBody.templateId = Convert.ToInt64(dtsmstemplate.table.Rows[0]["templateId"].ToString()!);
                sandeshMessageBody.message = dtsmstemplate.table.Rows[0]["msgBody"].ToString()!;
                object[] values = new object[] { sMSParam.value1, sMSParam.value2, sMSParam.value3,
                sMSParam.value4,sMSParam.value5,sMSParam.value6,sMSParam.value7,sMSParam.value8,sMSParam.value9,
                sMSParam.value10};
                sandeshMessageBody.message = DlCommon.GetFormattedMsg(sandeshMessageBody.message, values);

                AlertMessageBody smsbody = new();
                smsbody.OTP = sandeshMessageBody.isOTP == true ? sandeshMessageBody.OTP : 0;
                //smsbody.OTP = sandeshMessageBody.OTP;
                smsbody.smsTemplateId = 1;
                smsbody.isOtpMsg = (bool)sandeshMessageBody.isOTP;
                smsbody.applicationId = 0;
                smsbody.mobileNo = Convert.ToInt64(mobileno);
                smsbody.msgCategory = sandeshMessageBody.msgCategory;
                smsbody.smsBody = sandeshMessageBody.message;
                smsbody.clientIp = sandeshMessageBody.clientIp;
                smsbody.smsLanguage = LanguageSupported.English;
                smsbody.actionId = 1;
                //smsbody.emailToReceiver = sandeshMessageBody.emailId;
                //smsbody.emailSubject = "OTP Verification";
                smsbody.messageServerResponse = returnBool.status;
                #endregion
                try
                {
                    #region Send sansesh SMS
                    if (sandeshSmsisActive.ToUpper() == "TRUE")
                        returnBool = await sms.callSandeshAPI(sandeshMessageBody);
                    #endregion

                    #region Send Normal SMS
                    string normalSMSServiceActive = Utilities.GetAppSettings("SmsConfiguration", "isActive").message;
                    if (normalSMSServiceActive.ToUpper() == "TRUE")
                        returnBool = await sms.CallSMSAPI(sandeshMessageBody);
                    #endregion
                    if (normalSMSServiceActive.ToUpper() == "TRUE" || sandeshSmsisActive.ToUpper() == "TRUE")
                    {
                        #region Save SMS Detail
                        rb = await SendSmsSaveAsync(smsbody);
                        #endregion
                    }
                    if ((normalSMSServiceActive.ToUpper() == "FALSE" && sandeshSmsisActive.ToUpper() == "FALSE") || returnBool.status.ToLower() == "success")
                        rb.status = true;
                }
                catch (Exception)
                {
                    throw;
                }
            }
            else
                rb.message = "SMS template Not Available.";




            return rb;
        }

        /// <summary>
        ///Send Message Via Sandesh app Only Without template
        /// </summary>
        /// <returns></returns>
        public async Task<ReturnBool> SendSandesh(sandeshMessageBody sandeshMessageBody)
        {
            SandeshResponse returnBool = new SandeshResponse();
            string mobileno = sandeshMessageBody.contact.Substring(sandeshMessageBody.contact.ToString().Length - 10);
            sandeshMessageBody.templateId = sandeshMessageBody.templateId == null ? 0 : sandeshMessageBody.templateId;
            Match match = Regex.Match(mobileno.ToString(),
                              @"^[6-9]\d{9}$", RegexOptions.IgnoreCase);

            if (match.Success == false)
            {
                rb.status = false;
                rb.message = "Invalid Mobile Number";
                return rb;
            }
            #region create Parameter To send SMS
            SandeshSms sms = new SandeshSms();
            sandeshMessageBody.contact = mobileno;
            sandeshMessageBody.msgCategory = (Int16)SandeshmsgCategory.Info;
            sandeshMessageBody.msgPriority = (Int16)SandeshmsgPriority.HighVolatile;
            sandeshMessageBody.templateId = sandeshMessageBody.templateId == null ? 0 : sandeshMessageBody.templateId;
            EmailResponse smsResponse = new EmailResponse();
            smsResponse.status = "true";
            //Get SMS Template
            if ((Int32)sandeshMessageBody.templateId > 0)
            {
                ReturnDataTable dtsmstemplate = await GetSMSEmailTemplate((Int32)sandeshMessageBody.templateId!);
                if (dtsmstemplate.table.Rows.Count > 0)
                {
                    sandeshMessageBody.templateId = Convert.ToInt64(dtsmstemplate.table.Rows[0]["templateId"].ToString()!);
                    sandeshMessageBody.message = dtsmstemplate.table.Rows[0]["msgBody"].ToString();
                    object[] values = new object[] { "", "" };
                    sandeshMessageBody.message = DlCommon.GetFormattedMsg(sandeshMessageBody.message!, values);
                }

            }
            #endregion

            #region Send sansesh SMS
            string sandeshSmsisActive = Utilities.GetAppSettings("sandeshSmsConfig", "isActive").message;
            if (sandeshSmsisActive.ToUpper() == "TRUE")
                returnBool = await sms.callSandeshAPI(sandeshMessageBody);
            #endregion

            #region Send Normal SMS
            string normalSMSServiceActive = Utilities.GetAppSettings("SmsConfiguration", "isActive").message;
            if (normalSMSServiceActive.ToUpper() == "TRUE")
                returnBool = await sms.CallSMSAPI(sandeshMessageBody);
            #endregion

            #region Save SMS Detail
            AlertMessageBody smsbody = new();
            smsbody.OTP = sandeshMessageBody.isOTP == true ? sandeshMessageBody.OTP : 0;
            //smsbody.OTP = sandeshMessageBody.OTP;
            smsbody.smsTemplateId = 1;
            smsbody.isOtpMsg = (bool)sandeshMessageBody.isOTP;
            smsbody.applicationId = 0;
            smsbody.mobileNo = Convert.ToInt64(mobileno);
            smsbody.msgCategory = sandeshMessageBody.msgCategory;
            smsbody.clientIp = sandeshMessageBody.clientIp;
            smsbody.smsLanguage = LanguageSupported.English;
            //smsbody.emailToReceiver = sandeshMessageBody.emailId;
            //smsbody.emailSubject = "OTP Verification";
            smsbody.messageServerResponse = returnBool.status;
            smsbody.actionId = 1;
            rb = await SendSmsSaveAsync(smsbody);
            #endregion
            if (returnBool.status.ToLower() == "success")
                rb.status = true;



            return rb;
        }




        public Task<string> GetSwsServiceAPIUrl()
        {
            string buildType = Utilities.GetCurrentBuild();
            string url = Utilities.GetAppSettings("ServiceAPI", buildType, "URL").message;
            return Task.FromResult(url);
        }

        public async Task<ReturnClass.ReturnBool> SaveInStoreAPI(BlDocumentDoc blDoc, string methodName)
        {
            ReturnClass.ReturnBool rb = new();
            Uri url = new(await GetSwsStoreAPIUrl() + methodName);
            HttpClient client = new()
            {
                BaseAddress = url
            };
            client.DefaultRequestHeaders.Accept.Clear();
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));   //ACCEPT header
            //client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", responsePayload.authToken);
            try
            {
                var request = new BlDocumentDoc
                {
                    documentId = blDoc.documentId,
                    documentType = blDoc.documentType,
                    documentExtension = blDoc.documentExtension,
                    documentMimeType = blDoc.documentMimeType,
                    documentTag = blDoc.documentTag,
                    stateId = Convert.ToInt16(blDoc.stateId),
                    documentImageGroup = blDoc.documentImageGroup,
                    isDocumentShared = YesNo.Yes,
                    swsApplicationId = 0,
                    swsActionId = blDoc.swsActionId,
                    userId = blDoc.userId,
                    documentInByte = blDoc.documentInByte,
                    documentList = blDoc.documentList,
                    documentName = blDoc.documentName,
                    uploaded = 1,
                };
                HttpResponseMessage response = await client.PostAsJsonAsync(url, request);
                response.EnsureSuccessStatusCode(); // throws if not 200-299
                var contentStream = await response.Content.ReadAsStreamAsync();
#pragma warning disable CS8600 // Converting null literal or possible null value to non-nullable type.
                rb = await JsonSerializer.DeserializeAsync<ReturnClass.ReturnBool>(contentStream);
            }
            catch (Exception ex)
            {
                WriteLog.Error("SaveInStoreAPI", ex);
            }
            return rb!;
        }

        public async Task<ReturnClass.ReturnBool> SaveInStoreAPI(BlDocumentDoc blDoc, string methodName, string authHeaders)
        {
            ReturnClass.ReturnBool rb = new();
            Uri url = new(await GetSwsStoreAPIUrl() + methodName);
            HttpClient client = new()
            {
                BaseAddress = url
            };
            client.DefaultRequestHeaders.Accept.Clear();
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));   //ACCEPT header
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", authHeaders);
            try
            {
                var request = new BlDocumentDoc
                {
                    documentId = blDoc.documentId,
                    documentType = blDoc.documentType,
                    documentExtension = blDoc.documentExtension,
                    documentMimeType = blDoc.documentMimeType,
                    documentTag = blDoc.documentTag,
                    stateId = Convert.ToInt16(blDoc.stateId),
                    documentImageGroup = blDoc.documentImageGroup,
                    isDocumentShared = YesNo.Yes,
                    swsApplicationId = 0,
                    swsActionId = blDoc.swsActionId,
                    userId = blDoc.userId,
                    documentInByte = blDoc.documentInByte,
                    documentList = blDoc.documentList,
                    documentName = blDoc.documentName,
                    uploaded = 1,

                };
                HttpResponseMessage response = await client.PostAsJsonAsync(url, request);
                response.EnsureSuccessStatusCode(); // throws if not 200-299
                var contentStream = await response.Content.ReadAsStreamAsync();
#pragma warning disable CS8600 // Converting null literal or possible null value to non-nullable type.
                rb = await JsonSerializer.DeserializeAsync<ReturnClass.ReturnBool>(contentStream);
            }
            catch (Exception ex)
            {
                WriteLog.Error("SaveInStoreAPI", ex);
            }
            return rb!;
        }
        private Task<string> GetSwsStoreAPIUrl()
        {
            string buildType = Utilities.GetCurrentBuild();
            string url = Utilities.GetAppSettings("StoreAPI", buildType, "URL").message;
            return Task.FromResult(url);
        }
        public async Task<ReturnBool> CheckIfSessionExpired(LoginTrail ltr)
        {
            ReturnBool rb = new();
            string query = @"SELECT lt.sessionId
                             FROM logintrail lt
                             WHERE authToken = @authToken AND lt.isSessionRevoked = @isSessionRevoked ";
            MySqlParameter[] sp = new MySqlParameter[]
            {
                new MySqlParameter("authToken", MySqlDbType.VarString) { Value = ltr.currentAuthToken },
                new MySqlParameter("isSessionRevoked", MySqlDbType.VarString) { Value = (int)YesNo.No}
            };
            ReturnDataTable dt = await db.ExecuteSelectQueryAsync(query, sp);
            if (dt.table.Rows.Count > 0)
            {
                rb.status = true;
                rb.message = "Active Session Found.";
            }
            else
            {
                rb.status = false;
                rb.message = "Invalid Token OR Session Expired !!";
            }
            return rb;
        }

        #region Request Token
        /// <summary>
        /// Method for creating random number for post request
        /// </summary>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnString> GenerateRequestToken()
        {
            ReturnString returnString = new();
            Guid guid = Guid.NewGuid();
            string query = @"INSERT INTO requesttoken(guid)
                             VALUES (@guid)";
            MySqlParameter[] pm = new MySqlParameter[]
            {
                new MySqlParameter("guid", MySqlDbType.VarChar) { Value = guid.ToString() },
            };
            ReturnClass.ReturnBool rb = await db.ExecuteQueryAsync(query, pm, "GenerateRequestToken");
            if (rb.status)
            {
                returnString.status = true;
                returnString.msgId = guid.ToString();
            }
            return returnString;
        }

        public async Task<ReturnClass.ReturnBool> VerifyRequestToken(string requestToken)
        {
            ReturnBool rb = new();
            ReturnBool rbValidityPeriod = Utilities.GetAppSettings("AppSettings", "TokenValidityInMinutes");
            int validityPeriod = 10;
            if (rbValidityPeriod.status)
                validityPeriod = Convert.ToInt32(rbValidityPeriod.message);

            string query = @"SELECT p.tableKey, p.isUtilized, TIMESTAMPDIFF(MINUTE, p.entryDateTime, NOW()) as tokenValidity
                             FROM requesttoken p
                             WHERE p.guid = @guid "; //TIMESTAMPDIFF(MINUTE, p.entryDateTime, NOW()) 
            MySqlParameter[] pm = new MySqlParameter[]
            {
                new MySqlParameter("guid", MySqlDbType.VarChar) { Value = requestToken},
            };
            ReturnClass.ReturnDataTable dt = await db.ExecuteSelectQueryAsync(query, pm);
            if (dt.table.Rows.Count > 0)
            {
                if (dt.table.Rows[0]["isUtilized"].ToString() == "0")
                {
                    int tokenValidity = Convert.ToInt32(dt.table.Rows[0]["tokenValidity"].ToString());
                    if (tokenValidity <= validityPeriod)
                    {
                        rb.status = true;
                        await ExpireRequestToken(requestToken);
                    }
                    else
                        rb.message = "Token Expired";
                }
                else
                    rb.message = "Token Expired";
            }
            else
                rb.message = "Invalid Token";
            return rb;
        }

        private async Task<ReturnClass.ReturnBool> ExpireRequestToken(string requestToken)
        {
            string query = @" UPDATE requesttoken p
                              SET p.isUtilized = @isUtilized
                              WHERE p.guid = @guid ";
            MySqlParameter[] pm = new MySqlParameter[]
            {
                new MySqlParameter("isUtilized", MySqlDbType.Int16) { Value = (int)YesNo.Yes },
                new MySqlParameter("requestToken", MySqlDbType.VarChar) { Value = requestToken },
            };
            return await db.ExecuteQueryAsync(query, pm, "ExpireRequestToken");
        }
        #endregion

        public Task<bool> checkInternalExternal(string url)
        {
            bool isInternalService = true;
            if (url.StartsWith("http") || url.StartsWith("https"))
                isInternalService = false;
            return Task.FromResult(isInternalService);
        }
        public Task<string> GetSwsServiceAPICommonUrls(string method)
        {
            string url = Utilities.GetAppSettings("ServiceAPI", "CommonURL", method).message;
            return Task.FromResult(url);
        }
        public async Task<List<ListValue>> GetProjectServicecounter(LanguageSupported language)
        {
            string fieldLanguage = language == LanguageSupported.Hindi ? "Local" : "English";
            string query = @"SELECT sp.uniqueId AS id,sp.deptName" + fieldLanguage + @" AS name,
                                    COUNT(CASE WHEN sr.isServiceLive=@isServiceLive AND sc.serviceVerificationStatus=@serviceVerificationStatus THEN 1 END) AS extraField,dlogo.uniqueId AS extraField1
	                                FROM swsregisteredprojects AS sp 
                                    INNER JOIN swsserviceregistration sr ON sp.swsProjectId=sr.swsProjectId AND sr.serviceVerificationStatus=@accountVerificationStatus
                                    INNER JOIN servicecharter AS sc ON sc.swsProjectId=sr.swsProjectId AND sc.swsServiceId = sr.swsServiceId
                                    LEFT JOIN livedeclarationdetailstatus ls ON ls.swsServiceId=sr.swsServiceId AND ls.`status`=@accountVerificationStatus
                                    LEFT JOIN (SELECT dl.documentId,dl.uniqueId from departmentlogo AS dl 
										  				where dl.isActive = @isActive AND dl.verificationStatus = @verificationStatus )
									AS dlogo ON dlogo.documentId = sr.swsProjectId
                                WHERE sp.accountVerificationStatus=@accountVerificationStatus 
                                GROUP BY id,name 
                                ORDER BY name ";
            MySqlParameter[] pm = new MySqlParameter[]
            {
                new MySqlParameter("accountVerificationStatus", MySqlDbType.Int16){ Value=ActionStatus.Approved},
                new MySqlParameter("isServiceLive", MySqlDbType.Int16){ Value= YesNo.Yes },
                new MySqlParameter("isActive", MySqlDbType.Int16){ Value= YesNo.Yes },
                new MySqlParameter("verificationStatus", MySqlDbType.Int16){ Value= YesNo.Yes },
                new MySqlParameter("serviceVerificationStatus", MySqlDbType.Int16){ Value= YesNo.Yes },
            };
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            List<ListValue> lv = Helper.GetGenericDropdownList(dt.table);
            return lv;
        }

        public async Task<ReturnDataTable> GetSMSEmailTemplate(Int32 smsTemplateId)
        {

            string query = @"SELECT se.templateId,se.categoryName,se.isOTP,se.msgBody,se.emailBody,se.noofSMSParam,se.noofEmailParam,
                                        se.smsParamDescription,se.emailParamDescription,se.emailSubject
                                    FROM smsemailtemplate se
                                    WHERE se.id=@id AND se.isActive=@isActive ";
            MySqlParameter[] pm = new MySqlParameter[]
            {
                new MySqlParameter("id", MySqlDbType.Int32){ Value= smsTemplateId},
                new MySqlParameter("isActive", MySqlDbType.Int16){ Value= IsActive.Yes},
            };
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            if (dt.table.Rows.Count == 0)
                dt.message = "No Templates Available";
            return dt;
        }
        public static string GetFormattedMsg(string smsText, params object[] values)
        {
            return string.Format(smsText, values);
        }


        /// <summary>
        ///Send Mail Without Template 
        /// </summary>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnString> SendEmail(SendEmail bl, SMSParam smsParam)
        {
            ReturnClass.ReturnString rs = new();
            ReturnClass.ReturnBool rb = new ReturnClass.ReturnBool();
            bl.templateId = bl.templateId == null ? 0 : bl.templateId;
            Match match = Regex.Match(bl.emailId.ToString(),
                              @"^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+$", RegexOptions.IgnoreCase);
            if (match.Success == false)
            {
                rs.status = false;
                rs.message = "email id is not valid.";
                return rs;
            }
            string emailServiceActive = Utilities.GetAppSettings("EmailConfiguration", "isActive").message;
            string buildVersion = Utilities.GetAppSettings("Build", "Version").message;
            AlertMessageBody smsbody = new();
            SandeshResponse rbs = new();
            if (emailServiceActive.ToUpper() == "TRUE" && buildVersion.ToLower() == "production")
            {
                if ((Int32)bl.templateId! > 0)
                {
                    ReturnDataTable dtsmstemplate = await GetSMSEmailTemplate((Int32)bl.templateId!);
                    if (dtsmstemplate.table.Rows.Count > 0)
                    {
                        bl.templateId = Convert.ToInt64(dtsmstemplate.table.Rows[0]["templateId"].ToString()!);
                        bl.message = dtsmstemplate.table.Rows[0]["msgBody"].ToString();
                        bl.subject = dtsmstemplate.table.Rows[0]["emailSubject"].ToString();
                        object[] values = new object[] { smsParam.value1, smsParam.value2, smsParam.value3, smsParam.value4,
                        smsParam.value5,smsParam.value6,smsParam.value7,smsParam.value8,smsParam.value9,smsParam.value10};
                        bl.message = DlCommon.GetFormattedMsg(bl.message!, values);
                    }
                }
                rs.secondryId = "0";
                Email em = new();
                //await em.SendAsync(bl.emailId, bl.subject!, bl.message!, null);
                //New code To Send Email From 31.103
                emailSenderClass emailSenderClass = new();
                emailSenderClass.emailSubject = bl.subject!;
                emailSenderClass.emailBody = bl.message!;
                emailSenderClass.emailToId = bl.emailId!;
                emailSenderClass.emailToName = "";
               // await em.SendEmailViaURLAsync(emailSenderClass);
                #region Send OTP
                smsbody.OTP = 0;
                smsbody.smsTemplateId = 1;
                smsbody.isOtpMsg = true;
                smsbody.applicationId = 0;
                smsbody.mobileNo = 0;
                smsbody.msgCategory = (Int16)MessageCategory.OTP;
                smsbody.clientIp = bl.clientIp;
                smsbody.smsLanguage = LanguageSupported.English;
                smsbody.emailToReceiver = bl.emailId;
                smsbody.emailSubject = bl.subject;
                smsbody.messageServerResponse = rbs.status;
                smsbody.actionId = 1;
                //smsbody.msgId = Guid.NewGuid().ToString();
                smsbody.msgId = await GenerateEmailMsgId();
                rb = await SendEmailSaveAsync(smsbody);
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
        ///Send Mail With Template 
        /// </summary>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnString> SendEmail(SendEmail bl)
        {
            ReturnClass.ReturnString rs = new();
            ReturnClass.ReturnBool rb = new ReturnClass.ReturnBool();
            bl.templateId = bl.templateId == null ? 0 : bl.templateId;
            Match match = Regex.Match(bl.emailId.ToString(),
                              @"^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+$", RegexOptions.IgnoreCase);
            if (match.Success == false)
            {
                rs.status = false;
                rs.message = "Email id is not valid.";
                return rs;
            }
            if (bl.message == string.Empty)
            {
                rs.status = false;
                rs.message = "message Should not be Empty.";
                return rs;
            }
            if (bl.subject == string.Empty)
            {
                rs.status = false;
                rs.message = "subject Should not be Empty.";
                return rs;
            }
            string emailServiceActive = Utilities.GetAppSettings("EmailConfiguration", "isActive").message;
            string buildVersion = Utilities.GetAppSettings("Build", "Version").message;
            AlertMessageBody smsbody = new();
            SandeshResponse rbs = new();

            if (emailServiceActive.ToUpper() == "TRUE")
            //if (emailServiceActive.ToUpper() == "TRUE" && buildVersion.ToLower() == "production")
            {
                rs.secondryId = "0";

                Email em = new Email();
                //Old Email Sender code 14-05-2024
                //await em.SendAsync(bl.emailId, bl.subject!, bl.message!, null, bl.ccEmailId);

                //New code To Send Email From 31.103
                emailSenderClass emailSenderClass = new();
                emailSenderClass.emailSubject = bl.subject!;
                emailSenderClass.emailBody = bl.message!;
                emailSenderClass.emailToId = bl.emailId!;
                emailSenderClass.emailToName = "";
                //await em.SendEmailViaURLAsync(emailSenderClass);
                //
                #region Send OTP
                smsbody.OTP = 0;
                smsbody.smsTemplateId = 1;
                smsbody.isOtpMsg = true;
                smsbody.applicationId = 0;
                smsbody.mobileNo = 0;
                smsbody.msgCategory = (Int16)MessageCategory.OTP;
                smsbody.clientIp = bl.clientIp;
                smsbody.smsLanguage = LanguageSupported.English;
                smsbody.emailToReceiver = bl.emailId;
                smsbody.emailSubject = bl.subject;
                smsbody.messageServerResponse = rbs.status;
                smsbody.actionId = 1;
                //smsbody.msgId = Guid.NewGuid().ToString();
                smsbody.msgId = await GenerateSMSMsgId();
                try
                {
                    rb = await SendEmailSaveAsync(smsbody);
                    if (rb.status)
                    {
                        rs.msgId = rb.message;
                        rs.status = true;
                    }
                }
                catch (Exception e) { }
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
        /// Get swsProjectId by uniqueId
        /// </summary>
        /// <returns></returns>
        public async Task<Int64> GetSWSprojectId(string uniqueId)
        {
            ReturnString returnString = new();
            Int64 swsProjectId = 0;
            string query = @" SELECT srp.swsProjectId FROM swsregisteredprojects AS srp WHERE srp.uniqueId=@uniqueId";
            MySqlParameter[] pm = new MySqlParameter[]
            {
                new MySqlParameter("uniqueId", MySqlDbType.VarChar) { Value = uniqueId },
            };
            ReturnClass.ReturnDataTable dt = await db.ExecuteSelectQueryAsync(query, pm);
            if (dt.table.Rows.Count > 0)
            {
                swsProjectId = Convert.ToInt64(dt.table.Rows[0]["swsProjectId"].ToString());
            }
            return swsProjectId;
        }


        public async Task<string> GenerateEmailMsgId()
        {

        ReExecute:
            string msgId = Guid.NewGuid().ToString();
            bool isExist = await VerifyEmailMsgId(msgId);
            if (isExist)
                goto ReExecute;
            else
                return msgId;
        }

        /// <summary>
        /// check emailMsgId
        /// </summary>
        /// <param name="msgId"></param>
        /// <returns></returns>
        private async Task<bool> VerifyEmailMsgId(string msgId)
        {
            string query = @"SELECT d.msgId
                             FROM emailsentdetail AS d
                             WHERE d.msgId = @msgId;";
            MySqlParameter[] pm = new[]
            {
                new MySqlParameter("msgId", MySqlDbType.VarChar,100){  Value= msgId}
            };
            ReturnDataTable dataTable = await db.ExecuteSelectQueryAsync(query, pm);
            if (dataTable.table.Rows.Count > 0)
                return true;
            else
                return false;
        }

        public async Task<string> GenerateSMSMsgId()
        {

        ReExecute:
            string msgId = Guid.NewGuid().ToString();
            bool isExist = await VerifySMSMsgId(msgId);
            if (isExist)
                goto ReExecute;
            else
                return msgId;
        }

        /// <summary>
        /// check ssms MsgId
        /// </summary>
        /// <param name="msgId"></param>
        /// <returns></returns>
        private async Task<bool> VerifySMSMsgId(string msgId)
        {
            string query = @"SELECT d.msgId
                             FROM smssentdetail AS d
                             WHERE d.msgId = @msgId;";
            MySqlParameter[] pm = new[]
            {
                new MySqlParameter("msgId", MySqlDbType.VarChar,100){  Value= msgId}
            };
            ReturnDataTable dataTable = await db.ExecuteSelectQueryAsync(query, pm);
            if (dataTable.table.Rows.Count > 0)
                return true;
            else
                return false;
        }

        public async Task<ReturnClass.ReturnDataTable> RenewDetails(Int64 unitNumber, Int64 swsServiceId)
        {
            Int64 parentSwsServiceId = 0;
            ReturnClass.ReturnDataTable dt = new();
            string query = @" SELECT sr.parentSwsServiceId FROM swsserviceregistration as sr WHERE sr.swsServiceId = @swsServiceId ";
            MySqlParameter[] pm;
            pm = new MySqlParameter[]
            {
                new MySqlParameter("swsServiceId", MySqlDbType.Int64) { Value = swsServiceId },
            };
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            parentSwsServiceId = Convert.ToInt64(dt.table.Rows[0]["parentSwsServiceId"]);

            //query = @" SELECT sr.swsServiceId AS parentSwsServiceId,sr.isSingleTimeApplication,sap.swsApplicationStatusCode
            //                        FROM swsserviceregistration AS sr INNER JOIN swsapplicationprogressstatus AS sap ON sr.swsServiceId = sap.swsServiceId
            //                    WHERE sr.swsServiceId = @parentSwsServiceId AND sap.unitNumber = @unitNumber";
            //pm = new MySqlParameter[]
            //{
            //    new MySqlParameter("parentSwsServiceId", MySqlDbType.Int64) { Value = parentSwsServiceId },
            //    new MySqlParameter("unitNumber", MySqlDbType.Int64) { Value = unitNumber },
            //};
            query = @" SELECT CASE WHEN (SELECT COUNT(sap.swsApplicationId) FROM swsserviceregistration AS sr 
													INNER JOIN swsapplicationprogressstatus AS sap ON sr.swsServiceId = sap.swsServiceId
                                WHERE sr.swsServiceId = @parentSwsServiceId 
										  	AND sap.swsApplicationStatusCode=@swsApplicationStatusCode) = 0 THEN @swsServiceId 
											  ELSE @parentSwsServiceId END AS parentSwsServiceId,sr.isSingleTimeApplication 
                            FROM swsserviceregistration as sr WHERE sr.swsServiceId = @swsServiceId ";
            pm = new MySqlParameter[]
               {
                    new MySqlParameter("swsServiceId", MySqlDbType.Int64) { Value = swsServiceId },
                    new MySqlParameter("parentSwsServiceId", MySqlDbType.Int64) { Value = parentSwsServiceId },
                    new MySqlParameter("swsApplicationStatusCode", MySqlDbType.Int16) { Value = SwsApplicationStatus.Approved },
               };
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            return dt;
        }




        /// <summary>
        ///Get Category List from ddlCat
        /// </summary>
        /// <returns></returns>
        public async Task<List<ListValue>> GetCommonListIndustryAsync(string category)
        {
            string query = @"select d.id AS id, d.name
                                    FROM industry_msme.ddl_cat_list AS d WHERE d.Category = @category ORDER BY d.Sort_order ";
            MySqlParameter[] pm = new MySqlParameter[]
            {
                new MySqlParameter("category", MySqlDbType.String) { Value= category }
            };
            dt = await db.ExecuteSelectQueryAsync(query, pm, DBConnectionList.TransactionIndustryDB);
            List<ListValue> lv = Helper.GetGenericDropdownList(dt.table);
            return lv;
        }
        public async Task<List<ListValue>> GetCommonListIndustryProdAsync(string category)
        {
            string query = @"select d.id AS id, d.name
                                    FROM industry_msme.prod_ddl_cat_list AS d WHERE d.Category = @category ORDER BY d.sort ";
            MySqlParameter[] pm = new MySqlParameter[]
            {
                new MySqlParameter("category", MySqlDbType.String) { Value= category }
            };
            dt = await db.ExecuteSelectQueryAsync(query, pm, DBConnectionList.TransactionIndustryDB);
            List<ListValue> lv = Helper.GetGenericDropdownList(dt.table);
            return lv;
        }

        public async Task<List<ListValue>> GetDistrict(Int64 userId)
        {
            string query = "";
            MySqlParameter[] pm = new MySqlParameter[]
            {
                new MySqlParameter("userId", MySqlDbType.Int64) { Value= userId }
            };

            if (userId != 0)
                query = @"SELECT d.district_id AS id, d.district_name_en AS name
	                     FROM industry_msme.emp_office_mapping AS a  
		                    INNER JOIN industry_msme.office AS b ON a.Office_Code = b.Office_Code
		                    INNER JOIN industry_msme.districts AS d ON d.district_id = b.Dist_Code
	                    WHERE a.Emp_Id=@userId  ORDER BY d.district_name_en ";
            else
                query = @" SELECT dist.district_id AS id, dist.district_name_en as name FROM industry_msme.districts AS dist 
                            ORDER BY dist.district_name_en ";
            dt = await db.ExecuteSelectQueryAsync(query, DBConnectionList.TransactionIndustryDB);
            List<ListValue> lv = Helper.GetGenericDropdownList(dt.table);
            return lv;
        }

        public async Task<Int32> GetNextActionOrder(Int64 actionOrder)
        {
            Int32 nextActionOrder = 0;
            try
            {
                string query = @" SELECT nextActionOrder
		                                     FROM ( SELECT mom.actionOrder,lead(mom.actionOrder) 
		 			                                    over (ORDER BY mom.actionOrder,mom.officeId,mom.modStageMappingId) AS nextactionorder
					                                    FROM modulestageofficemapping AS mom 
					                                    WHERE mom.active=1 
				                                    ) AS t
		                                     WHERE actionOrder=@actionOrder
                                ";
                MySqlParameter[] pm = new MySqlParameter[]
                {
                     new MySqlParameter("actionOrder",MySqlDbType.Int64) { Value = actionOrder},
                };
                dt = await db.ExecuteSelectQueryAsync(query, pm);
                if (dt.table.Rows.Count > 0)
                {
                    nextActionOrder = Convert.ToInt32(dt.table.Rows[0]["nextActionOrder"]);
                }
            }
            catch (Exception ex)
            {
                dt.status = false;
                dt.message = ex.Message;
            }
            return nextActionOrder;
        }
        public async Task<Int32> GetCurrentActionOrder(Int64 vikalpApplicationId)
        {
            Int32 currentActionOrder = 0;
            try
            {
                string query = @" SELECT vik.actionOrder FROM vikalp AS vik WHERE vik.vikalpApplicationId = @vikalpApplicationId
                                ";
                MySqlParameter[] pm = new MySqlParameter[]
                {
                     new MySqlParameter("vikalpApplicationId",MySqlDbType.Int64) { Value = vikalpApplicationId},
                };
                dt = await db.ExecuteSelectQueryAsync(query, pm);
                if (dt.table.Rows.Count > 0)
                {
                    currentActionOrder = Convert.ToInt32(dt.table.Rows[0]["actionOrder"]);
                }
            }
            catch (Exception ex)
            {
                dt.status = false;
                dt.message = ex.Message;
            }
            return currentActionOrder;
        }
        public async Task<Int32> GetOfficeMappingIdNext(Int64 actionOrder)
        {
            Int32 empOfficeMappingId = 0;
            try
            {
                Int64 nextActionOrder = 0;
                nextActionOrder = await GetNextActionOrder(actionOrder);
                string query = @"SELECT mom.actionOrder,w.empOfficeMappingId,mom.stageId
                                     FROM modulestageofficemapping AS mom 
	                                    INNER JOIN workflow w ON w.modStageMappingId=mom.modStageMappingId
                                    WHERE mom.actionOrder = " + nextActionOrder;
                dt = await db.ExecuteSelectQueryAsync(query);
                if (dt.table.Rows.Count > 0)
                {
                    empOfficeMappingId = Convert.ToInt32(dt.table.Rows[0]["empOfficeMappingId"]);
                }
            }
            catch (Exception ex)
            {
                dt.status = false;
                dt.message = ex.Message;
            }
            return empOfficeMappingId;
        }

        public async Task<ReturnDataTable> GetReceiverDetails(Int64 userId)
        {
            string query = @" SELECT IFNULL(eom.chargeMappingKey,0) AS chargeMappingKey,eom.officeId,eom.empOfficeMappingId,msm.actionOrder
                                        FROM employeeofficemapping eom 
                                        INNER JOIN modulestageofficemapping msm ON msm.officeId=eom.officeId
                                    WHERE eom.employeeId = @userId
                                ";
            MySqlParameter[] pm = new MySqlParameter[]
            {
                     new MySqlParameter("userId",MySqlDbType.Int64) { Value = userId},
            };
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            return dt;
        }
        public async Task<ReturnDataTable> GetChargeMappingKey(Int64 empOfficeMappingId)
        {
            string query = @" SELECT IFNULL(eom.chargeMappingKey,0) AS chargeMappingKey 
                                FROM employeeofficemapping eom 
                               WHERE eom.empOfficeMappingId = @empOfficeMappingId   ";
            MySqlParameter[] pm = new MySqlParameter[]
            {
                     new MySqlParameter("empOfficeMappingId",MySqlDbType.Int64) { Value = empOfficeMappingId},
            };
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            return dt;
        }

        public async Task<ReturnDataTable> GetofficeMappingId(Int64 vikalpApplicationId)
        {
            string query = @" SELECT IFNULL(vik.officeMappingId,0) AS officeMappingId, IFNULL(vik.chargeMappingKey,0) AS chargeMappingKey
                                        FROM vikalp AS vik
                                    WHERE vik.vikalpApplicationId = @vikalpApplicationId
                                ";
            MySqlParameter[] pm = new MySqlParameter[]
            {
                     new MySqlParameter("vikalpApplicationId",MySqlDbType.Int64) { Value = vikalpApplicationId},
            };
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            return dt;
        }

        public async Task<List<ListValue>> EmployeeList(Int64 userId)
        {
            string query = @"SELECT b.Office_Code FROM employees as a
            	            INNER JOIN emp_office_mapping AS b ON a.Emp_Id = b.Emp_Id
            	            WHERE a.Emp_Id=@userId ";
            MySqlParameter[] pm = new MySqlParameter[]
            {
                     new MySqlParameter("userId",MySqlDbType.Int64) { Value = userId},
            };
            dt = await db.ExecuteSelectQueryAsync(query, pm, DBConnectionList.TransactionIndustryDB);
            Int32 officeCode = Convert.ToInt32(dt.table.Rows[0]["Office_Code"].ToString());
            query = @" select e.Emp_Id AS id , e.Emp_Name AS name
                        FROM employees e
	                        INNER JOIN emp_office_mapping ee ON ee.Emp_Id=e.Emp_Id
                        where Office_Code=@officeCode
                        and desig_id not in ('22001','22005') and e.active='A' ORDER BY desig_id DESC;
                                ";
            MySqlParameter[] pm1 = new MySqlParameter[]
           {
                     new MySqlParameter("officeCode",MySqlDbType.Int64) { Value = officeCode},
           };
            dt = await db.ExecuteSelectQueryAsync(query, pm1, DBConnectionList.TransactionIndustryDB);
            List<ListValue> lv = Helper.GetGenericDropdownList(dt.table);
            return lv;
        }

        /// <summary>
        ///Get Category List from ddlCat
        /// </summary>
        /// <returns></returns>
        public async Task<List<ListData>> GetCommonListChartAsync(string category, LanguageSupported language)
        {
            string fieldLanguage = language == LanguageSupported.Hindi ? "Local" : "English";

            string query = @"SELECT d.id AS id, d.name" + fieldLanguage + @" AS name,d.grouping as extraField,
                                    d.remark AS label
                                 FROM ddlcatlist d
                             WHERE d.isActive = @isActive AND d.category = @category
                                AND d.hideFromPublicAPI = @hideFromPublicAPI AND d.isStateSpecific=@isStateSpecific
                             ORDER BY d.sortOrder";
            MySqlParameter[] pm = new MySqlParameter[]
            {
                new MySqlParameter("hideFromPublicAPI", MySqlDbType.Int16){ Value=(int) YesNo.No},
                new MySqlParameter("isActive", MySqlDbType.Int16){ Value = (int) IsActive.Yes},
                new MySqlParameter("isStateSpecific", MySqlDbType.Int16){ Value= (int)YesNo.No},
                new MySqlParameter("category", MySqlDbType.String) { Value= category }
            };
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            List<ListData> lv = Helper.GetGenericlist(dt.table);
            return lv;
        }

        #region Create User
        /// <summary>
        /// Generate Event Log
        /// </summary>
        /// <param name="el"></param>
        /// <returns></returns>
        public async Task<ReturnBool> SaveUserLogin(UserLogin el)
        {
            bool userExist = await GetUserExist(el.userId);
            string modificationType = "User Create";
            if (userExist)
                modificationType = "User Update";

            string query = @" INSERT INTO userlogin (userName, userId, emailId, password, forceChangePassword, 
                                    isActive, clientIp, creationTimeStamp, modificationType, 
                                userTypeCode, userRole, registrationYear)
                                    VALUES 
                                (@userName,@userId,@emailId,@password,@forceChangePassword,
                                @isActive,@clientIp,NOW(),@modificationType,
                                  @userTypeCode,@userRole,@registrationYear); ";
            el.isActive = el.isActive == null ? (Int16)IsActive.Yes : el.isActive;
            MySqlParameter[] pm = new MySqlParameter[]
            {
                new MySqlParameter("userName", MySqlDbType.VarChar) { Value = el.userName },
                new MySqlParameter("userId", MySqlDbType.Int64) { Value = el.userId },
                new MySqlParameter("emailId", MySqlDbType.VarChar) { Value = el.emailId },
                new MySqlParameter("password", MySqlDbType.VarChar) { Value = el.password },
                new MySqlParameter("forceChangePassword", MySqlDbType.Int16) { Value =(Int16) YesNo.No },
                new MySqlParameter("isActive", MySqlDbType.Int16) { Value =el.isActive},
                new MySqlParameter("modificationType", MySqlDbType.VarChar) { Value = modificationType },
                new MySqlParameter("clientIp", MySqlDbType.VarChar) { Value = el.clientIp },
                new MySqlParameter("userTypeCode", MySqlDbType.Int16) { Value = 0},
                new MySqlParameter("userRole", MySqlDbType.Int16) { Value = el.userRole},
                new MySqlParameter("registrationYear", MySqlDbType.Int32) { Value =DateTime.Now.Year},
            };
            using (TransactionScope ts = new(TransactionScopeAsyncFlowOption.Enabled))
            {
                if (userExist)
                    rb = await DeleteExistingUser(el.userId);
                else
                    rb.status = true;
                if (rb.status)
                {
                    rb = await db.ExecuteQueryAsync(query, pm, "CreateUser");
                    if (rb.status)
                        ts.Complete();
                }
            }
            return rb;
        }

        /// <summary>
        /// Active/Inactive User Login
        /// </summary>
        /// <param name="el"></param>
        /// <returns></returns>
        public async Task<ReturnBool> UserActivation(UserLogin el)
        {
            string query = @" INSERT INTO userloginlog
                            SELECT * FROM userlogin WHERE  userId =@userId ";
            MySqlParameter[] pm = new MySqlParameter[]
            {

                new MySqlParameter("userId", MySqlDbType.Int64) { Value = el.userId },
                new MySqlParameter("isActive", MySqlDbType.Int16) { Value =el.isActive},
                new MySqlParameter("clientIp", MySqlDbType.VarChar) { Value = el.clientIp },

            };
            using (TransactionScope ts = new(TransactionScopeAsyncFlowOption.Enabled))
            {
                rb = await db.ExecuteQueryAsync(query, pm, "SaveUserloginLog");
                if (rb.status)
                {
                    query = @" UPDATE userlogin 
                            SET isActive=@isActive ,clientIp=@clientIp
                            WHERE  userId =@userId";
                    rb = await db.ExecuteQueryAsync(query, pm, "UserActive_Deactive");
                    if (rb.status)
                    {
                        ts.Complete();
                    }
                }
                return rb;
            }
        }

        public async Task<ReturnBool> DeleteExistingUser(Int64 userId)
        {
            string query = @" INSERT INTO userloginlog
                            SELECT * FROM userlogin WHERE  userId =@userId ";

            MySqlParameter[] pm = new MySqlParameter[]
            {
                new MySqlParameter("userId", MySqlDbType.Int64) { Value = userId },

            };

            rb = await db.ExecuteQueryAsync(query, pm, "SaveUserloginLog");
            if (rb.status)
            {

                query = @" DELETE FROM userlogin                             
                            WHERE  userId =@userId";
                rb = await db.ExecuteQueryAsync(query, pm, "DeleteUser");
            }
            return rb;
        }

        public async Task<bool> GetUserExist(Int64 userId)
        {
            bool userExists = false;
            string query = @"SELECT userId FROM userlogin WHERE  userId =@userId ";
            MySqlParameter[] pm = new MySqlParameter[]
            {
                     new MySqlParameter("userId",MySqlDbType.Int64) { Value = userId},
            };
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            if (dt.table.Rows.Count > 0)
                userExists = true;
            return userExists;
        }
        public async Task<ReturnDataTable> GetUserList()
        {

            string query = @"SELECT u.userName, u.userId, u.emailId,
                                    u.isActive,u.userRole,d.nameEnglish AS userRoleName
                                FROM userlogin  u
                                JOIN ddlcatlist d ON d.id=u.userRole AND d.category=@category
                                WHERE u.userRole!=@admin";
            MySqlParameter[] pm = new MySqlParameter[]
            {   new MySqlParameter("category",MySqlDbType.Int64) { Value = "userRole"},
              new MySqlParameter("admin",MySqlDbType.Int16) { Value = (Int16)UserRole.Administrator},
            };
            dt = await db.ExecuteSelectQueryAsync(query, pm);
            dt.status = false;
            if (dt.table.Rows.Count > 0)
                dt.status = true;
            return dt;
        }

        /// <summary>
        /// Active/Inactive User Login
        /// </summary>
        /// <param name="el"></param>
        /// <returns></returns>
        public async Task<ReturnBool> ResetPassword(UserLogin el)
        {
            string query = @" INSERT INTO userloginlog
                            SELECT * FROM userlogin WHERE  userId =@userId ";

            MySqlParameter[] pm = new MySqlParameter[]
            {

                new MySqlParameter("userId", MySqlDbType.Int64) { Value = el.userId },
                new MySqlParameter("password", MySqlDbType.Int16) { Value =el.password},
                new MySqlParameter("modificationType", MySqlDbType.VarChar) { Value = "Password Reset" },
                new MySqlParameter("clientIp", MySqlDbType.VarChar) { Value = el.clientIp },

            };
            using (TransactionScope ts = new(TransactionScopeAsyncFlowOption.Enabled))
            {
                rb = await db.ExecuteQueryAsync(query, pm, "SaveUserloginLog");
                if (rb.status)
                {
                    query = @" UPDATE userlogin 
                            SET password=@password,modificationType=@modificationType ,clientIp=@clientIp
                            WHERE  userId =@userId";

                    rb = await db.ExecuteQueryAsync(query, pm, "ResetPassword");
                    if (rb.status)
                    { ts.Complete(); }
                }
            }
            return rb;
        }
        #endregion

          public async Task<ReturnBool> CalculateDensity(SpiritDensity spiritDensity)
        {
            ReturnBool rb = new();
            if (spiritDensity.density > 0)
            {
                rb.status = true;
                spiritDensity.density = (spiritDensity.density / 100) + 1;
                decimal OtherVolume = Convert.ToDecimal(0.75);
                decimal cal_Val = Convert.ToDecimal((spiritDensity.avp * spiritDensity.density) / OtherVolume);
                rb.value = (Math.Round(cal_Val,2)).ToString();
            }
            return rb;
        }

    }
}