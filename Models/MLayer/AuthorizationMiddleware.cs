using ScottmenMainApi.Models.BLayer;
using ScottmenMainApi.Models.DLayer;
using ScottmenMainApi.Models.MLayer;
using static BaseClass.ReturnClass;

namespace ScottmenMainApi.Models.MLayer
{
    public class AuthorizationMiddleware
    {
        //private readonly AppSettings _appSettings;
        private readonly RequestDelegate _next;

        public AuthorizationMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext httpContext)
        {
            string authHeaders = httpContext.Request.Headers.FirstOrDefault(x => x.Key == "Authorization").Value.FirstOrDefault();
            if (authHeaders is not null && authHeaders != "")
            {
                authHeaders = authHeaders.Replace("Bearer", "", StringComparison.CurrentCultureIgnoreCase).TrimStart();
                DlCommon dl = new DlCommon();
                LoginTrail ltr = new();
                ltr.currentAuthToken = authHeaders;
                ReturnBool rb = await dl.CheckIfSessionExpired(ltr);
                if (!rb.status)
                {
                    httpContext.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    return;
                }
            }

            await _next(httpContext);
        }
    }
}
