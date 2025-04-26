using ScottmenMainApi.Models.BLayer;
using ScottmenMainApi.Models.DLayer;
using System.Net.Http.Headers;
using System.Reflection;
using System.Text.Json;
namespace BaseClass
{
    /// <summary>
    /// Business Class For sandesh SMS
    /// </summary>
    public class SandeshSms
    {

        readonly string SandeshGatewayUrl;
        readonly string ProjectName;
        readonly bool isActive;
        readonly string build;
        readonly bool isNormalSMSActive;



        public SandeshSms()
        {
            try
            {

                this.SandeshGatewayUrl = GetGatewayUrl();
                this.ProjectName = Utilities.GetAppSettings("sandeshSmsConfig", "ProjectName").message;
                this.isActive = Convert.ToBoolean(Utilities.GetAppSettings("sandeshSmsConfig", "isActive").message);
                this.build = Utilities.GetAppSettings("Build", "Version").message;
                this.isNormalSMSActive = Convert.ToBoolean(Utilities.GetAppSettings("SmsConfiguration", "isActive").message);

            }
            catch
            {
                throw;//
            }
        }

        public async Task<ReturnClass.SandeshResponse> callSandeshAPI(sandeshMessageBody sandeshMessageBody)
        {
            ReturnClass.SandeshResponse rsb = new ReturnClass.SandeshResponse();

            //Uri url = new Uri(SandeshGatewayUrl+ "SendMessage/SendSandesMessageAsync");
            Uri url = new Uri(SandeshGatewayUrl);
            HttpClient client = new();
            sandeshMessageBody.projectName = ProjectName;
            client.BaseAddress = url;
            client.DefaultRequestHeaders.Accept.Clear();
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));   //ACCEPT header         
            HttpResponseMessage response = await client.PostAsJsonAsync(url, sandeshMessageBody);
            response.EnsureSuccessStatusCode(); // throws if not 200-299
            var contentStream = await response.Content.ReadAsStreamAsync();
            rsb = await JsonSerializer.DeserializeAsync<ReturnClass.SandeshResponse>(contentStream);
            DlUser dlUser = new DlUser();
            SMSResponse smsResponse = new SMSResponse();
            try
            {

                smsResponse.status = rsb.status!;
                smsResponse.mobileNo = Convert.ToInt64(sandeshMessageBody.contact);
                smsResponse.message = rsb.message;
                smsResponse.code = rsb.code;
                smsResponse.notice = rsb.notice + " SandeshSMS";
                smsResponse.clientIp = sandeshMessageBody.clientIp;
                smsResponse.reqId = rsb.status!.ToLower() == "success" ? rsb.data.reqid : "0";
                await dlUser.InsertSMSResponse(smsResponse);
            }
            catch
            { throw; }
            return rsb;
        }
        public async Task<ReturnClass.SandeshResponse> CallSMSAPI(sandeshMessageBody sandeshMessageBody)
        {
            ReturnClass.SandeshResponse rsb = new ReturnClass.SandeshResponse();
            DlUser dlUser = new DlUser();
            SMSResponse smsResponse = new SMSResponse();
            try
            {
                // Send Normal SMS
                if (sandeshMessageBody.templateId != 0 && build.ToLower() == "production" && isNormalSMSActive == true)
                {
                    Sms sms = new Sms();
                    SmsBody sb = new();
                    sb.IsOtp = sandeshMessageBody.isOTP;
                    sb.IsUniCodeMessage = false;
                    sb.TemplateMessageBody = sandeshMessageBody.message;
                    sb.TemplateId = (long)sandeshMessageBody.templateId!;
                    rsb.status = await sms.Send(Convert.ToInt64(sandeshMessageBody.contact), sb);
                    smsResponse.status = rsb.status!;
                    smsResponse.mobileNo = Convert.ToInt64(sandeshMessageBody.contact);
                    smsResponse.message = rsb.message;
                    smsResponse.code = rsb.code;
                    smsResponse.notice = rsb.notice + " NormalSMS";
                    smsResponse.clientIp = sandeshMessageBody.clientIp;
                    smsResponse.reqId = sandeshMessageBody.templateId.ToString();
                    await dlUser.InsertSMSResponse(smsResponse);
                }
                else
                    rsb.status = "success";

            }
            catch
            { throw; }


            return rsb;
        }


        private string GetGatewayUrl()
        {
            string GatewayUrl = "";
            ReturnClass.ReturnBool rb = Utilities.GetAppSettings("Build", "Version");
            if (rb.status)
            {
                string buildType = rb.message!;
                GatewayUrl = Utilities.GetAppSettings("sandeshSmsConfig", buildType, "GatewayUrl").message!;

            }
            else
                GatewayUrl = rb.error;

            return GatewayUrl;
        }
        public string GetBaseUrl()
        {
            string baseUrl = "";
            ReturnClass.ReturnBool rb = Utilities.GetAppSettings("Build", "Version");
            if (rb.status)
            {
                string WebUrl = rb.message!;
                baseUrl = Utilities.GetAppSettings("sandeshSmsConfig", WebUrl, "WebUrl").message!;

            }
            else
                baseUrl = rb.error;

            return baseUrl;
        }
        private class SmsProxy
        {
            public bool ProxyEnabled;
            public HttpClientHandler? ProxyHttpClient;
        }
    }
}