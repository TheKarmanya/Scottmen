using BaseClass;

namespace ScottmenMainApi.Models.BLayer
{
    public class BlUser
    {
        public long? registrationId { get; set; }
        public string registrationUId { get; set; } = "";
        public long registrationCount { get; set; }
        public string msgId { get; set; } = "";

        public Int32 smsOTP { get; set; } = 0;
        public Int32 emailOTP { get; set; } = 0;
        public string? applicantFirstName { get; set; } = "";
        public string? applicantMiddleName { get; set; } = "";
        public string? applicantLastName { get; set; } = "";
        public string emailId { get; set; } = "";
        public long mobileNo { get; set; }
        public string? password { get; set; } = "";
        public YesNo isMobileVerified { get; set; }
        public DateTime? mobileVerificationDate { get; set; }
        public YesNo isEmailVerified { get; set; }
        public DateTime? emailVerificationDate { get; set; }
        public string? clientIp { get; set; } = "";
        public string? clientOs { get; set; } = "";
        public string? clientBrowser { get; set; } = "";
        public string? userAgent { get; set; } = "";
        public string? authToken { get; set; } = "";
        public string? captchaId { get; set; } = "";
        public string? userEnteredCaptcha { get; set; } = "";
        public string? oldPassword { get; set; } = "";
        public Int16? roleId { get; set; }
        public string? apiName { get; set; }
        public long? userId { get; set; } = 0;
        public string? responseStatus { get; set; } = "";
        public Int16? eventLogErrorId { get; set; } = 0;
        public object? requestBody { get; set; }
        public string? requestUUID { get; set; } = null;
        public string? message { get; set; }
    }
    public class UserLoginRequest
    {
        public string emailId { get; set; } = "";
        public string password { get; set; } = "";
        public string captchaId { get; set; } = "";
        public string? userEnteredCaptcha { get; set; } = "";
        public string? requestToken { get; set; } = "";
        public string? swsToken { get; set; } = "";
        public bool nswsRequest { get; set; } = false;

    }
    public class UserLoginResponse
    {
        public long userId { get; set; }
        public string userName { get; set; } = "";
        public string userFirstName { get; set; } = "";
        public string userMiddleName { get; set; } = "";
        public string userLastName { get; set; } = "";
        public int primaryRole { get; set; } = 0;
        public bool forceChangePassword { get; set; }
        public DateTime disabledTime { get; set; }
        //public int userRole { get; set; }
        public bool isNationalSingleWindowUser { get; set; }
        public int userTypeCode { get; set; }
        public bool isLoginSuccessful { get; set; } = false;
        public string message { get; set; } = "";
        public string authToken { get; set; } = "";
        public string refreshToken { get; set; } = "";
        public DateTime? refreshTokenExpiryTime { get; set; }
        public string emailId { get; set; } = "";
        public long mobileNo { get; set; }
        public string loginId { get; set; } = "";
        public Int16? isSingleWindowUser { get; set; } = 0;
        public string swsRedirectURL { get; set; } = "";

        public List<UserProjectResponse> userProjectResponse { get; set; }
        public Int16? openOTP { get; set; } = 0;
        public Int16? isDashboardMigrated { get; set; } = 1;
        public string? emp_id { get; set; }


    }
    public class UserLoginResponseFailure
    {
        public bool isLoginSuccessful { get; set; } = false;
        public string message { get; set; } = "";
    }
    public class UserProjectResponse
    {
        public Int16 stateId { get; set; }
        public long swsProjectId { get; set; }
        public Int16 districtId { get; set; } = 0;
        public string deptNameEnglish { get; set; }
        public string deptNameLocal { get; set; }
        public string deptShortName { get; set; }
        public Int32 baseDepartmentId { get; set; } = 0;
        public string baseDepartmentName { get; set; }

    }
    public class UserLoginResponseSessionExtension
    {
        public bool isLoginSuccessful { get; set; } = false;
        public string message { get; set; } = "";
        public string authToken { get; set; } = "";
        public string refreshToken { get; set; } = "";
        public DateTime? refreshTokenExpiryTime { get; set; }
    }
    public class LoginTrail
    {
        /// <summary>
        /// Login ID is the ID enetered by user to login 
        /// </summary>
        public string? loginId { get; set; } = "";
        public string? loginSource { get; set; } = "";
        public string? clientIp { get; set; } = "";
        public string? clientOs { get; set; } = "";
        public string? clientBrowser { get; set; } = "";
        public string? userAgent { get; set; } = "";
        public AccessMode accessMode { get; set; }
        public YesNo isLoginSuccessful { get; set; } = YesNo.No;
        public YesNo isSessionExtended { get; set; } = YesNo.No;
        public int attemptCount { get; set; }
        /// <summary>
        /// User ID Is system generated unique ID
        /// </summary>
        public long userId { get; set; } = 0;
        public EventLogCategory logCategory { get; set; }
        public string currentAuthToken { get; set; } = "";
        public string newAuthToken { get; set; } = "";
        public string refreshToken { get; set; } = "";
        public DateTime? refreshTokenExpiryTime { get; set; }
        public YesNo isAccountDisabled { get; set; } = YesNo.No;
        public int sessionExtensionCount { get; set; } = 0;
        public string? parentAuthToken { get; set; } = "";
        public Int16? isSingleWindowUser { get; set; } = 0;
        public Int64? swsProjectId { get; set; } = 0;
        public string? swsRedirectURL { get; set; } = "";

    }
    public class TokenModel
    {
        public string? authToken { get; set; } = "";
        public string? refreshToken { get; set; } = "";
    }
    public class SendOtp
    {
        public string? msgId { get; set; } = "";
        public string? emailId { get; set; } = "";
        public long? mobileNo { get; set; }
        public string? clientIp { get; set; } = "";
        public string? msgType { get; set; } = "";
        public Int32? OTP { get; set; }
        public long? id { get; set; }
        public Int16? loginFor { get; set; }
        public string? userId { get; set; }
        public string? swsToken { get; set; } = "";
        public string? requestToken { get; set; } = "";
        public bool nswsRequest { get; set; } = false;


    }
    public class UserLoginWithOTP
    {
        public string emailId { get; set; } = "";
        public string id { get; set; } = "0";
        public string? captchaId { get; set; } = "";
        public string? userEnteredCaptcha { get; set; } = "";
    }

    public class SMSResponse
    {
        public string? reqId { get; set; } = "";
        public string? status { get; set; } = "";
        public long? mobileNo { get; set; }
        public string? notice { get; set; } = "";
        public string? code { get; set; } = "";
        public string? message { get; set; } = "";
        public string? clientIp { get; set; } = "";



    }

    public class EmailResponse
    {
        public string? reqId { get; set; } = "";
        public string? status { get; set; } = "";
        public string? emailId { get; set; }
        public string? notice { get; set; } = "";
        public string? code { get; set; } = "";
        public string? message { get; set; } = "";
        public string? clientIp { get; set; } = "";



    }

    public class SendEmail
    {
        public string? emailId { get; set; } = "";
        public string? ccEmailId { get; set; } = "";
        public string? subject { get; set; } = "";
        public string? message { get; set; } = "";
        public long? templateId { get; set; } = 0;
        //public SmsEmailTemplate? SmsEmailTemplate { get; set; } = SmsEmailTemplate.
        public string? clientIp { get; set; } = "";

    }
    public class SendAdminOTP
    {
        public string? msgId { get; set; } = "";
        public long? mobileNo { get; set; }
        public long? mobileNo1 { get; set; }
        public long? mobileNo2 { get; set; }
        public long? mobileNo3 { get; set; }
        public string? clientIp { get; set; } = "";
        public string? msgType { get; set; } = "";
        public Int32? OTP { get; set; }
        public long? id { get; set; }
    }
    public class UserResetPassword
    {
        public string oldPassword { get; set; }
        public string password { get; set; }
        public string loginId { get; set; }
        public string roleId { get; set; }
        public string? requestToken { get; set; } = "";
        public string? clientIp { get; set; } = "";

    }

    public class swsToken
    {
        public string? token { get; set; } = "";
    }
    public class swsSSOId
    {
        public string? ssoId { get; set; } = "";
    }

    public class Employee
    {
        public long? empCode { get; set; }
        public string? firstName { get; set; }
        public string? lastName { get; set; }
        public long? contactNumber { get; set; }
        public string? email { get; set; }
        public string? dob { get; set; }
        public string? gender { get; set; }
        public string? nationality { get; set; }
        public string? joiningDate { get; set; }
        public string? shift { get; set; }
        public string? department { get; set; }
        public string? bloodGroup { get; set; }
        public string? emergencyContact1 { get; set; }
        public string? emergencyContact2 { get; set; }
        public string? address { get; set; }
        public string? country { get; set; }
        public string? state { get; set; }
        public string? city { get; set; }
        public Int32? zipcode { get; set; }
        public Int16? workingStatus { get; set; } = (Int16)YesNo.Yes;
        public Int16? recruitmentType { get; set; } = (Int16)YesNo.Yes;
        public Int16? active { get; set; } = (Int16)IsActive.Yes;
        public long? userId { get; set; }
        public string? clientIp { get; set; }

    }

    public class UnitMaster
    {
        public Int32? unitId { get; set; }
        public string? unitName { get; set; }
        public string? shortName { get; set; }
        public Int16? active { get; set; } = (Int16)IsActive.Yes;
        public long? userId { get; set; } = 0;
        public string? clientIp { get; set; }

    }
    public class ItemMaster
    {

        public Int32? itemId { get; set; }
        public Int32? unitId { get; set; }
        public string? unitName { get; set; }
        public string? itemName { get; set; }
        public string? shortName { get; set; }
        public Int16? active { get; set; } = (Int16)IsActive.Yes;
        public Int16? itemTypeId { get; set; }
        public string? itemTypeName { get; set; }
        public long? userId { get; set; }
        public string? clientIp { get; set; }

    }
    public class Vendor
    {
        public long? vendorId { get; set; }
        public string? vendorName { get; set; }
        public Int16? typeId { get; set; }
        public string? typeName { get; set; }
        public long? phone1 { get; set; }
        public long? phone2 { get; set; }
        public string? email { get; set; }
        public string? address { get; set; }
        public string? city { get; set; }
        public string? country { get; set; }
        public string? gst { get; set; }
        public string? pan { get; set; }
        public string? tan { get; set; }
        public string? tin { get; set; }

        public Int16? active { get; set; } = (Int16)IsActive.Yes;
        public long? userId { get; set; }
        public string? clientIp { get; set; }
        public List<VendorItem> vendorItems { get; set; }

    }
    public class VendorItem
    {
        public Int32? vendorId { get; set; }
        public Int32? itemId { get; set; }
        public string? itemName { get; set; }

    }
    public class GatePassItem
    {
        public long? Id { get; set; }
        public Int32? itemId { get; set; }
        public string? itemName { get; set; }

    }
    public class BrandMaster
    {
        public Int32? brandId { get; set; }
        public string? brandName { get; set; }
        public string? brandNameHindi { get; set; }
        public Int16? active { get; set; } = (Int16)IsActive.Yes;
        public long? userId { get; set; } = 0;
        public string? clientIp { get; set; }

    }

    public class UnloadingEntry
    {
        public long? unloadingId { get; set; }
        public string? personName { get; set; }
        public string? vehicleNo { get; set; }
        public string? personMobileNo { get; set; }
        public long? vendorId { get; set; }
        public string? vendorName { get; set; }
        public string? billTNo { get; set; }
        public string? entryTime { get; set; }
        public string? exitTime { get; set; }
        public string? remark { get; set; }
        public Int16? active { get; set; } = (Int16)IsActive.Yes;
        public long? userId { get; set; }
        public string? clientIp { get; set; }
        public List<GatePassItem> GatePassItems { get; set; }

    }
    public class LoadingEntry
    {
        public long? loadingId { get; set; }
        public string? personName { get; set; }
        public string? vehicleNo { get; set; }
        public string? personMobileNo { get; set; }
        public long? vendorId { get; set; }
        public string? vendorName { get; set; }
        public string? billTNo { get; set; }
        public string? entryTime { get; set; }
        public string? exitTime { get; set; }
        public string? remark { get; set; }
        public Int16? active { get; set; } = (Int16)IsActive.Yes;
        public long? userId { get; set; }
        public string? clientIp { get; set; }
        public List<GatePassItem> GatePassItems { get; set; }
    }


    public class VisitorEntry
    {
        public long? visitorId { get; set; }
        public string? personName { get; set; }
        public string? vehicleNo { get; set; }
        public string? personMobileNo { get; set; }
        public long? vendorId { get; set; }
        public string? vendorName { get; set; }
        public string? billTNo { get; set; }
        public string? entryTime { get; set; }
        public string? exitTime { get; set; }
        public string? remark { get; set; }
        public string? purpose { get; set; }
        public Int16? active { get; set; } = (Int16)IsActive.Yes;
        public long? userId { get; set; }
        public string? clientIp { get; set; }
    }

    public class GatePassSearch
    {
        public long? id { get; set; }
        public string? vehicleNo { get; set; } = string.Empty;
        public string? personMobileNo { get; set; } = string.Empty;
        public long? vendorId { get; set; }
        public string? vendorName { get; set; } = string.Empty;
        public string? billTNo { get; set; } = string.Empty;
        public string? fromDate { get; set; } = string.Empty;
        public string? toDate { get; set; } = string.Empty;
        public long? userId { get; set; }
        public Int16? active { get; set; } = (Int16)IsActive.Yes;

    }
    public class ItemStockMaster
    {
        public long? userId { get; set; } = 0;
        public string? clientIp { get; set; } = "";
        public List<ItemStock>? stock { get; set; }
    }
    public class ItemStock
    {
        public long? itemStockId { get; set; } = 0;
        public long? unloadingId { get; set; } = 0;
        public Int16? itemId { get; set; } = 0;
        public string? itemName { get; set; }
        public Int64? quantity { get; set; } = 0;
        public Int64? oldQuantity { get; set; } = 0;
        public Int64? updatedQuantity { get; set; } = 0;
        public Int16? unitId { get; set; } = 0;
        public string? unitName { get; set; } = "";
        public Int16? ageing { get; set; } = 0;
        public string? SerialNoFrom { get; set; } = "";
        public string? SerialNoTo { get; set; } = "";
        public DateTime? expiryDate { get; set; } = DateTime.Now;
        public string? remark { get; set; } = "";
        public decimal? amount { get; set; } = 0;
        public Int16? active { get; set; } = (Int16)IsActive.Yes;
        public long? userId { get; set; } = 0;
        public string? clientIp { get; set; } = "";


    }
    public class ItemStockSearch
    {
        public long? itemStockId { get; set; }
        public long? unloadingId { get; set; }
        public Int16? active { get; set; } = (Int16)IsActive.Yes;

    }

    public class Blending
    {
        public long? batchId { get; set; }
        public Int16? containerId { get; set; }

        public string? containerName { get; set; }
        public Int32? brandId { get; set; }
        public string? brandName { get; set; }
        public decimal? totalQuantity { get; set; }
        public decimal? balanceQuantity { get; set; }
        public Int16? unitId { get; set; }
        public string? unitName { get; set; }
        public string? remark { get; set; }
        public DateTime? startDate { get; set; }
        public DateTime? endDate { get; set; }
        public DateTime? emptyDate { get; set; }

        public Int16? active { get; set; } = (Int16)IsActive.Yes;
        public long? userId { get; set; }
        public string? clientIp { get; set; }
        public List<BlendingItems> blendingItems { get; set; }

    }
    public class BlendingItems
    {
        public Int32? itemId { get; set; }

        public string? itemName { get; set; }
        public Int64? quantity { get; set; }
        public Int64? updatedQuantity { get; set; } = 0;
        public Int64? oldQuantity { get; set; } = 0;
        public Int16? unitId { get; set; }
        public string? unitName { get; set; }

        public Int16? active { get; set; } = (Int16)IsActive.Yes;
        public long? userId { get; set; }
        public string? clientIp { get; set; }


    }

    public class IssueMaterial
    {
        public long? issueId { get; set; } = 0;
        public long? batchId { get; set; }

        public DateTime? issueDate { get; set; }
        public Int16? active { get; set; } = (Int16)IsActive.Yes;
        public long? userId { get; set; }
        public string? clientIp { get; set; }
        public List<IssuePackagingMaterial> IssuePackagingMaterials { get; set; }

    }
    public class IssuePackagingMaterial
    {
        public long? issueId { get; set; }
        public Int32? itemId { get; set; }

        public string? itemName { get; set; }

        public decimal? quantity { get; set; }
        public decimal? retunQuantity { get; set; }
        public decimal? updatedQuantity { get; set; } = 0;
        public decimal? issuedQuantity { get; set; } = 0;
        public Int16? unitId { get; set; }
        public string? unitName { get; set; }
        public string? remark { get; set; }



    }



    public class FinishedProduct
    {
        public long? productId { get; set; } = 0;
        public long? batchId { get; set; } = 0;

        public Int32? brandId { get; set; } = 0;
        public string? brandName { get; set; }
        public decimal? totalQuantity { get; set; } = 0;
        public decimal? balanceQuantity { get; set; } = 0;
        public Int16? unitId { get; set; } = 0;
        public string? unitName { get; set; }
        public string? remark { get; set; }
        public DateTime? stockDate { get; set; }
        public DateTime? lastIssueDate { get; set; }


        public Int16? active { get; set; } = (Int16)IsActive.Yes;
        public long? userId { get; set; }
        public string? clientIp { get; set; }
        //public List<FinishedProductDetail> finishedProductDetails { get; set; }

    }
    public class FinishedProductDetail
    {
        public long? productId { get; set; } = 0;
        public long? productDatailId { get; set; } = 0;

        public Int64? quantity { get; set; } = 0;
        public Int16? unitId { get; set; } = 0;
        public string? unitName { get; set; }

        public Int16? active { get; set; } = (Int16)IsActive.Yes;
        public long? userId { get; set; } = 0;
        public string? clientIp { get; set; }


    }
    public class Dispatch
    {
        public long? dispatchId { get; set; }
        public long? loadingId { get; set; }
        public string? remark { get; set; }
        public decimal? quantity { get; set; }
        public Int16? active { get; set; } = (Int16)IsActive.Yes;
        public long? userId { get; set; }
        public string? clientIp { get; set; }
        public List<DispatchDetail> dispatchDetails { get; set; }


    }

    public class DispatchDetail
    {
        public long? batchId { get; set; }
        public Int32? brandId { get; set; }
        public string? brandName { get; set; }
        public decimal? quantity { get; set; }
        public Int16? unitId { get; set; }
        public string? unitName { get; set; }
    }
    public class DispatchSearch
    {
        public long? dispatchId { get; set; }
        public long? loadingId { get; set; }
        public long? batchId { get; set; }
        public Int32? brandId { get; set; }
        public string? brandName { get; set; }
        public decimal? quantity { get; set; }
        public Int16? unitId { get; set; }
        public string? unitName { get; set; }
    }

}