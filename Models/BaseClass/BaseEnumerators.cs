#pragma warning disable CS1587 // XML comment is not placed on a valid language element
/// <summary>
/// Don't Add any additional enumerators in this code file. For Project Specific enumerator use CommonEnumerator.cs file
/// </summary>
namespace BaseClass
#pragma warning restore CS1587 // XML comment is not placed on a valid language element
{
    public enum HashingAlgorithmSupported
    {
        Md5,
        Sha256,
        Sha512
    }
    public enum LanguageSupported
    {
        Hindi = 1,
        English = 2,
    }
    public enum DBConnectionList
    {
        TransactionDb = 1,
        ReportingDb = 2,
        TransactionIndustryDB = 3,
        IndustryDB = 4,
    }
    public enum IsActive
    {
        No = 0,
        Yes = 1
    }
    public enum YesNo
    {
        No = 0,
        Yes = 1
    }
    public enum CircularRouteLevel
    {
        Level0 = 0,
        Level1 = 1,
        Level2 = 2,
    }
    public enum Modules
    {
        Project = 11,
        ServiceCharter = 12,
        Service = 13,
        Questionnaire = 14,
        IPWhiteListing = 15,
        Notice = 16,
        Circular = 17,
        Contactus = 18,
        Ticket = 19,
        UnitRegistration = 20,
        FAQ = 21,
        LiveService = 22,
        BusinessRegulation = 23,
        DepartmentLogo = 24,
        HomeHelp = 25,
        HomeContent = 26,
        UserManual = 27,
        PrioritySectorAproval = 28,
        Vikalp = 29,
    }
    public enum TicketStatus
    {
        Reply = 1,
        Forward = 2
    }
    public enum SandeshmsgPriority
    {
        Low = 0,
        Medium = 1,
        High = 2,
        HighVolatile = 3,
    }
    public enum SandeshmsgCategory
    {
        Info = 0,
        Alert = 1,
        EventType = 2,
    }

    public enum SwsApplicationStatus
    {
        UnderProcess = 1,
        ApplicationAccepted = 2,
        ObjectionRaised = 3,
        ApplicationResubmitted = 4,
        Approved = 5,
        Rejected = 6,
        Cancelled = 7,
        InspectorAllotted = 8,
        InspectionDateGiven = 9,
        InspectionReportSubmitted = 10,
        DraftIncompleteApplication = 11,
    }
    public enum LiveDeclaration
    {
        No = 0,
        Yes = 1,
        NA = 2
    }
    public enum MessageCategory
    {
        OTHER = 0,
        OTP = 1
    }
    public enum DefaultState
    {
        CG = 22
    }
    public enum PublicDocumentType
    {
        Circular = 1,
        Notification = 2,
        ActRules = 3,
        ByLaws = 4,
    }
    public enum OTPStatus
    {
        Pending = 0,
        Verified = 1,
        Expired = 2,
    }
    public enum SMSSendType
    {
        Send = 1,
        Resend = 2,
    }
    public enum NodalBaseDepartment
    {
        NodalBaseDept = 107011,

    }
    public enum InOut
    {
        In = 1,
        Out = 2,
    }
    public enum SmsEmailTemplate
    {
        OTPSWS = 3001,
        INDSWS_AppRecive = 3002,
        INDSWS_StampSubmission = 3003,
        INDSWS_UserIdRetrieval = 3004,
        INDSWS_Objection = 3005,
        ServiceLive = 3006,
        ServiceDowntime = 3007,
        PositiveFeedback = 3008,
        NegativeFeedback = 3009,
        ServiceAppStatusUpdated = 3010,
        ServiceAppApproval = 3011,
        TicketRegistration = 3012,
        UnitRegistration = 3013,
         

    }

    public enum PANResponse
    {
        Success = 1,
        SystemError = 2,
        AuthenticationFailure = 3,
        Usernotauthorized = 4,
        NoPANsEntered = 5,
        Uservalidityhasexpired = 6,
        NumberofPANsexceedsthelimit = 7,
        Notenoughbalance = 8,
        NotanHTTPsrequest = 9,
        POSTmethodnotused = 10,
        SLAB_CHANGE_RUNNING = 11,
        Invalidversionnumberentered = 12,
        UserIDnotsentinInputrequestandonlyPANsent = 15,
        CertificateRevocationListissuedbytheCertifyingAuthoritiesisexpired = 16,
        UseridDeactivated = 17,
        UserIDnotpresentindatabaseorWrongcertificateused = 18,
        Signaturesentininputrequestisblank = 19,
        UserIDandPANnotsentinInputrequest = 20,
        OnlysentinInputrequest = 21,
    }
    public enum SWSServiceType
    {
        New = 1,
        Renew = 2,
    }

    public enum OrganizationType
    {
        Proprietary = 1,
        HUF = 2,
        Partnership = 3,
        PublicLimitedCompany = 4,
        PrivateLimitedCompany = 5,
        LimitedLiabilityPartnership = 6,
        Society = 7,
        CoOperativeSociety = 8,
        SelfHelpGroup = 9,
        DepartmentalUndertakingGovt = 10,
    }

    public enum PANVerificationFor
    {
        BusinessRegistration = 1,
        ShopEstablishment = 2,
        Industry = 3,
        Internal = 4,

    }
    public enum IndustryRedirectURL
    {
        Incentive = 1,
        UnitRegistration = 2,
        amendment = 3,

    }
    public enum WasteCategory
    {
        Items = 1,
        Blending = 2,        
        Dispatch = 3,

    }
    public enum BrandCategory
    {
        Small = 1,
        Medium = 2,
        Large = 3,

    }
}