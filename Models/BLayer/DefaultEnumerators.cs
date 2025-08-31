namespace BaseClass
{
    public enum StateId
    {
        DefaultState = 22
    }
    public enum FailedAttempt
    {
        Limit = 5,
        Minutes = 60
    }
    public enum AccessMode
    {
        WebPortal = 1,
        MobileApp = 2,
    }
    public enum EventLogCategory
    {
        UserProfile = 1,
        PasswordChanged = 2,
        AccountLocked = 3,
        AccountAccess = 4,
        LoginExtended = 5,
        LogOut = 6,
        SwsServiceAccess = 7,
        UnitRegistrationAccess = 8,
        UnitRegistrationList = 9,
        RepositoryAccess = 10,
        SwsProfileAccess = 11,
        Acknowledgment = 12,
    }
    public enum EventLogLevel
    {
        Info = 1,
        Warning = 2,
        Error = 3,
    }
    public enum PrefixId
    {
        IndustryEmployee = 2,
        IndustrialUserRegistration = 3,
        SwsDepartmentalUserId = 4,
        SwsProjectRegistration = 5,
        SwsServiceId = 2,
        Office = 1,
        QuestionId = 3,
        BusinessEntityID = 4,
        UnitRegistrationNo = 2,
        SwsUserRepositoryDocumentId = 3,
        IPWhitelistRequest = 5,
        ServiceDwonTimeGroup = 3,
        Circular = 5,
        Notice = 6,
        DraftBusinessRegulations = 6,
        UserFeedback = 7,
        UserFeedbackDetail = 8,
        UserManualHead = 1,
        UserManual = 2,
        PrioritySectorApproval = 3,
        Visitor = 1,
        Unloading = 2,
        Loading = 3,
        MaterialIssue = 4,
        Employee = 6,
        Dispatch = 7,
        PurchaseOrder = 9,
    }
    public enum LoginSource
    {
        WebPortal = 1,
        MobileApp = 2
    }
    public enum ContactVerifiedType
    {
        Email = 1,
        Mobile = 2
    }
    public enum UserRoleOLD
    {
        Administrator = 1,
        Industrialist = 2,
        /// <summary>
        /// Service Provider/ Integrated Department User
        /// </summary>
        ServiceProviderDepartmentalUser = 3,
        /// <summary>
        /// Nodal / Industry Department Main User.
        /// </summary>
        NodalDepartmentUser = 4,
        /// <summary>
        /// Internal Department (In house Development).
        /// </summary>
        InternalDepartmentUser = 5,
        /// <summary>
        /// NIC Admin.
        /// </summary>
        NicAdmin = 6
    }
    public enum UserRole
    {
        Administrator = 1,
        FL9User = 2,
        ProductionSupervisor = 3,
        /// <summary>
        /// Service Provider/ Integrated Department User
        /// </summary>
        //no = 3,
        /// <summary>
        /// Nodal / Industry Department Main User.
        /// </summary>
        BlenderUser = 4,
        /// <summary>
        /// Internal Department (In house Development).
        /// </summary>
        RowMaterialEntry = 5,
        /// <summary>
        /// NIC Admin.
        /// </summary>
        GateKeeper = 6


    }

    public enum UserTypeCode
    {
        NotApplicable = 0,
        Secretary = 1,
        NodalOfficer = 2,
        StateDEO = 3,
        Employee = 4,
    }
    public enum ActionStatus
    {
        All = -1,

        Pending = 0,

        Approved = 1,
        ForwardTo = 2,

        Rejected = 3,
        ForRejection = 4,

        ObjectionRaised = 5,
        SuggestforApproval = 6,
        SuggestforRejection = 7,

        InspectionDateAllotted = 8,
        InspectionReportSubmitted = 9,

        ApplicationAccepted = 10,
        AppliationResubmitted = 11,

        Cancelled = 12,

        ForVerification = 13,
        JustificationRaised = 14,
        Draft = 15,

        TicketSubmitted = 31,
        TicketOpen = 32,
        TicketClosed = 33,
        TicketJustification = 34,
        ForwardForApporval = 35,
    }
    public enum ServiceType
    {
        New = 1,
        Renew = 2,
        Both = 3
    }
    public enum UnitSetupType
    {
        New = 1,
        Existing = 2,
        Both = 3,
    }
    public enum ActivityNature
    {
        Manufacturing = 1,
        Service = 2,
        Both = 3,
    }
    public enum EstablishmentStage
    {
        PreEstablishment = 1,
        PreOperational = 2,
        Both = 3
    }

    public enum InputChoiceControlType
    {
        RadioButton = 0,
        Dropdown = 1,
        Checkbox = 2
    }
    public enum ServerType
    {
        Production = 1,
        Staging = 2,
        Development = 3
    }
    public enum OnlineOffline
    {
        Online = 1,
        Offline = 2
    }
    public enum OfficeLevel
    {
        State = 1,
        Division = 2,
        District = 3,
        DIC = 5
    }
    public enum NotificationId
    {
        Id = 0
    }
    public enum DocumentType
    {
        UserRepositoryDocument = 1,
        SwsCertificate = 2,
        Timeline = 3,
        SOP = 4,
        Manual = 5,
        Notification = 6,
        Checklist = 7,
        FeeDetail = 8,
        Ticket = 9,
        Circular = 10,
        Notice = 11,
        Regulations = 12,
        DepartmentLogo = 13,
        UserManual = 14,
        PrioritySectorApprovals = 15,
        DPR = 17,
        SpokePackage = 18,
        OptedPolicy = 19,
        ProfitDocument = 20,
        PurchaseOrder = 21,
        CAReportBill = 22,
        Acknowledgement = 23,

    }
    public enum DocumentImageGroup
    {
        UserRepository = 1,
        SwsDocuments = 2,
        IndustrysServiceDocuments = 3,
        TicketDocuments = 4,
        CircularDocuments = 5,
        NoticeDocuments = 6,
        DepartmentDocuments = 7,
        UserManual = 8,
        Vikalp = 9,
    }
    public enum ReferenceDocumentType
    {
        Document = 1,
        ExternalURL = 2
    }
    public enum SWSApplicationCategory
    {
        UserApplication = 1,
        DepartmentApplcationForTesting = 2
    }
    public enum FAQType
    {
        Public = 1,
        User = 2,
        Department = 3
    }
    public enum ApplicationExpirationAlert
    {
        timePeriodInDays = 3
    }
    public enum UserManual
    {
        DepartmentManual = 1,
        InvestorManual = 2,
        PublicManual = 3,
        NodalManual = 4,
    }
    public enum TimelineStatus
    {
        processedWithinTimeline = 1,
        processedAboveTimeline = 2,
        aboutToExpire = 3,
    }

    public enum EventLogErrorCategory
    {
        UnauthorizedIP = 1,
        Validation = 2,
    }

    public enum ServiceCategory
    {
        SwsService = 1,
        InternalSubsidy = 2,
        Other = 3,
    }
}