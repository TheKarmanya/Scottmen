using BaseClass;
using System.Net.Mail;
using System.ComponentModel.DataAnnotations;
namespace ScottmenMainApi.Models.BLayer
{
    public class AlertMessageBody
    {
        public string? clientIp { get; set; }
        public long? mobileNo { get; set; }
        public string? smsBody { get; set; }
        public LanguageSupported smsLanguage { get; set; }
        public string? msgId { get; set; }
        public Int16 msgCategory { get; set; }
        public bool isOtpMsg { get; set; } = false;
        public long? OTP { get; set; }
        public long? emailOTP { get; set; }
        public long? applicationId { get; set; } = 0;
        public int? actionId { get; set; } = 0;
        public string? emailToReceiver { get; set; }
        public string? emailBody { get; set; }
        public List<Attachment>? emailAttachment { get; set; }
        public string? emailSubject { get; set; }
        public long loginId { get; set; }
        public string? messageServerResponse { get; set; }
        public Int16 smsTemplateId { get; set; }
    }
    public class sandeshMessageBody
    {
        public string? contact { get; set; }
        public string? message { get; set; }
        public string? projectName { get; set; }
        public Int16 msgPriority { get; set; }
        public Int16 msgCategory { get; set; }
        public bool? isOTP { get; set; } = false;
        public Int32? OTP { get; set; }
        public string? clientIp { get; set; }
        public long? templateId { get; set; } = 0;
    }
    public class emailSenderClass
    {
        public string? emailToId { get; set; }
        public string? emailToName { get; set; }
        public string? emailSubject { get; set; }
        public string? emailBody { get; set; }
    }
    public class SMSParam
    {
        public string? value1 { get; set; } = "";
        public string? value2 { get; set; } = "";
        public string? value3 { get; set; } = "";
        public string? value4 { get; set; } = "";
        public string? value5 { get; set; } = "";
        public string? value6 { get; set; } = "";
        public string? value7 { get; set; } = "";
        public string? value8 { get; set; } = "";
        public string? value9 { get; set; } = "";
        public string? value10 { get; set; } = "";

    }
}
