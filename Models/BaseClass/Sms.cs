using System.Net;
using System.Web;
namespace BaseClass
{
    /// <summary>
    /// Summary description for sms
    /// </summary>
    public class Sms
    {
        readonly string GatewayUrl;
        readonly string UserName;
        readonly string UserNameOtp;
        readonly string PasswordPlain;
        readonly string SenderId;
        readonly string EntityId;

        readonly string SandeshGatewayUrl;
        readonly string SandeshSenderId;
        readonly bool isActive;


        public Sms()
        {
            try
            {
                this.GatewayUrl = Utilities.GetAppSettings("SmsConfiguration", "GatewayUrl").message;
                this.UserName = Utilities.GetAppSettings("SmsConfiguration", "UserName").message;
                this.UserNameOtp = Utilities.GetAppSettings("SmsConfiguration", "UserNameOtp").message;
                this.PasswordPlain = Utilities.GetAppSettings("SmsConfiguration", "Password").message;
                this.SenderId = Utilities.GetAppSettings("SmsConfiguration", "SenderId").message;
                this.EntityId = Utilities.GetAppSettings("SmsConfiguration", "EntityId").message;
                this.isActive = Convert.ToBoolean(Utilities.GetAppSettings("SmsConfiguration", "isActive").message);
            }
            catch
            {
                throw;
            }
        }
        /// <summary>
        /// Send Asynchronoulsy SMS in English
        /// </summary>
        /// <param name="mobileNo">10 digit mobile number</param>
        /// <param name="smsTemplateBody"></param>
        /// <returns></returns>
        public async Task<string> Send(long mobileNo, SmsBody smsTemplateBody)
        {
            if (mobileNo.ToString().Length == 10)
            {
                string username = (bool)smsTemplateBody.IsOtp! ? UserNameOtp : UserName;

                string uniCodetag = smsTemplateBody.IsUniCodeMessage ? "&msgType=UC" : "";
                //"") HttpUtility.UrlEncode(
                string body = "username=" + username + "&pin=" + PasswordPlain + "&signature=" + SenderId + "&mnumber=91" + mobileNo
                            + "&message=" + smsTemplateBody.TemplateMessageBody + "&dlt_entity_id=" + EntityId + "&dlt_template_id=" + smsTemplateBody.TemplateId.ToString() + uniCodetag;

                SmsProxy sp = CheckProxySettings();
                //if (sp.ProxyEnabled)
                //{
#pragma warning disable CS8604 // Possible null reference argument.
                    return await SendMessage(GatewayUrl, body, proxyHttpClientHandler: sp.ProxyHttpClient);
#pragma warning restore CS8604 // Possible null reference argument.
                //}
                //else
                //    return await SendMessage(GatewayUrl, body);
            }
            else
                return "Invalid Mobile number supplied";
        }
        private static async Task<string> SendMessage(string gatewayUrl, string smsBody, HttpClientHandler proxyHttpClientHandler)
        {
            using HttpClient httpClient = new(proxyHttpClientHandler);

            try
            {
                var responseString = await httpClient.GetStringAsync(gatewayUrl + smsBody);
                return responseString;
            }
            catch (Exception ex)
            {
                return ex.Message.ToString();
            }
        }

        private static async Task<string> SendMessage(string gatewayUrl, string smsBody)
        {
            #region ByPass SSL Check for SMS Server
            HttpClientHandler clientHandler = new()
            {
                ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => { return true; }
            };
            #endregion
            using HttpClient httpClient = new(clientHandler);
            try
            {
                bool enableLog = Utilities.GetAppSettings("SmsConfiguration", "EnableErrorLog").message == "true" ? true : false;
                if (enableLog)
                    WriteLog.Error("SMS URL - " + gatewayUrl + smsBody);
                var responseString = await httpClient.GetStringAsync(gatewayUrl + smsBody);
                return responseString;
            }
            catch (Exception ex)
            {
                return ex.Message.ToString();
            }
        }
        private SmsProxy CheckProxySettings()
        {
            SmsProxy sp = new();
            sp.ProxyEnabled = false;
            try
            {
                ReturnClass.ReturnBool rbKey = Utilities.GetAppSettings("SmsConfiguration", "EnableProxy");
                string proxySettingsFound = rbKey.status ? rbKey.message : "";

                if (proxySettingsFound.ToLower().Trim() == "true")
                {
                    ReturnClass.ReturnBool rbProxyUri = Utilities.GetAppSettings("SmsConfiguration", "ProxyUrl");
                    string proxyUri = rbProxyUri.status ? rbProxyUri.message : "";
                    var webProxy = new WebProxy(new Uri(proxyUri), BypassOnLocal: false);
                    var proxyHttpClientHandler = new HttpClientHandler
                    {
                        Proxy = webProxy,
                        UseProxy = true,
                        ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
                    };
                    sp.ProxyHttpClient = proxyHttpClientHandler;
                    sp.ProxyEnabled = true;
                }
                else
                {
                    var proxyHttpClientHandler = new HttpClientHandler
                    {
                        ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
                    };
                    sp.ProxyHttpClient = proxyHttpClientHandler;
                }
            }
            catch (Exception ex)
            {
                WriteLog.Error("SmsPrxySettings", ex);
            }
            return sp;
        }
        private class SmsProxy
        {
            public bool ProxyEnabled;
            public HttpClientHandler? ProxyHttpClient;
        }
    }
}