namespace BaseClass
{
    public class SmsBody
    {
        public SmsBody()
        {
            IsOtp = false;
            IsUniCodeMessage = false;
        }
        public long TemplateId { get; set; }
        public string? TemplateMessageBody { get; set; }
        /// <summary>
        /// Default value is false
        /// </summary>
        public bool? IsOtp { get; set; }
        /// <summary>
        /// Default Value is False
        /// </summary>
        public bool IsUniCodeMessage { get; set; }
    }
}
