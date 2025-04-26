using BaseClass;

namespace BaseClass
{
    public class SmsTemplates
    {
        public static SmsBody OtpMessage(string type, int otp)
        {
            var ms = new SmsBody
            {
                IsOtp = true,
                TemplateId = 89898,
                TemplateMessageBody = string.Format(@" Your OTP is {1} for {0} \n SWS Chhattisgarh Portal .\n Regards SWS@Chhattisgarh", type, otp.ToString())
            };
            return ms;
        }
        public static SmsBody ApplicationSubmitToUserMessage(int applicationNo)
        {
            var ms = new SmsBody
            {
                TemplateId = 67198,
                TemplateMessageBody = string.Format(@"Your Application number {0} has been submiteed successfully. \n Regards SWS@Chhattisgarh", applicationNo.ToString())
            };
            return ms;
        }
        public static SmsBody OtpEmail(string type, int otp)
        {
            var ms = new SmsBody
            {
                IsOtp = true,
                TemplateId = 11111,
                TemplateMessageBody = string.Format(@" Your Email OTP is {1} for {0} \n SWS Chhattisgarh Portal .\n Regards SWS@Chhattisgarh", type, otp.ToString())
            };
            return ms;
        }      

        private static string Format(string text, params object[] values)
        {
            return string.Format(text, values);
        }
    }
}
