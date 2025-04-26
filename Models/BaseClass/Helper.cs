using Microsoft.IdentityModel.Tokens;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using static BaseClass.ReturnClass;

namespace BaseClass
{
    public class Helper
    {

        /// <summary>
        /// Get List Vale pair For Dropdowns and Radio
        /// </summary>
        /// <param name="dt"></param>
        /// <returns></returns>
        public static List<ListValue> GetGenericDropdownList(DataTable dt)
        {
            List<ListValue> lv = new();
            if (dt.Rows.Count > 0)
            {
                foreach (DataRow dr in dt.Rows)
                {
                    lv.Add(new ListValue
                    {
                        value = dr["id"].ToString(),
                        name = dr["name"].ToString(),
                        label = dt.Columns.Contains("name") ? dr["name"].ToString() : "",
                        type = dt.Columns.Contains("extraField") ? dr["extraField"].ToString() : "",
                        extraField1 = dt.Columns.Contains("extraField1") ? dr["extraField1"].ToString() : ""
                    });
                }
            }
            return lv;
        }

        /// <summary>
        /// Get List Vale pair For Dropdowns and Radio 
        /// </summary>
        /// <param name="dt"></param>
        /// <returns></returns>
        public static List<ListData> GetGenericlist(DataTable dt)
        {
            List<ListData> lv = new();
            if (dt.Rows.Count > 0)
            {
                foreach (DataRow dr in dt.Rows)
                {
                    lv.Add(new ListData
                    {
                        value = dr["id"].ToString(),
                        name = dr["name"].ToString(),
                        label = dt.Columns.Contains("label") ? dr["label"].ToString() : "",
                        actionOrder = dt.Columns.Contains("actionOrder") ? dr["actionOrder"].ToString() : "",
                        type = dt.Columns.Contains("extraField") ? dr["extraField"].ToString() : ""
                    });
                }
            }
            return lv;
        }
        public static string CreateAuthenticationToken(List<Claim> authClaims)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            ReturnBool rb = Utilities.GetAppSettings("Build", "Version");
            ReturnBool rbKey = Utilities.GetAppSettings("SessionSettings", rb.message);

            var key = rbKey.status ? Encoding.ASCII.GetBytes(rbKey.message) : Encoding.ASCII.GetBytes("");

            rbKey = Utilities.GetAppSettings("AppSettings", "SessionDurationInMinutes");
            var sessionDurationInMinutes = rbKey.status ? Convert.ToInt16(rbKey.message) : 30;

            rbKey = Utilities.GetAppSettings("AppSettings", "Issuer");
            var tokenIssuer = rbKey.status ? rbKey.message : "https://industries.cg.gov.in";            

            ClaimsIdentity subject = new(authClaims.ToArray());
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = tokenIssuer,
                Subject = subject,
                Expires = DateTime.UtcNow.AddMinutes(sessionDurationInMinutes),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            string authToken = tokenHandler.WriteToken(token);
            return authToken;
        }

        public static string GenerateRefreshToken()
        {
            var randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        public static ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token)
        {
            ReturnBool rb = Utilities.GetAppSettings("Build", "Version");
            ReturnBool rbKey = Utilities.GetAppSettings("SessionSettings", rb.message);

            var key = rbKey.status ? Encoding.ASCII.GetBytes(rbKey.message) : Encoding.ASCII.GetBytes("");

            rbKey = Utilities.GetAppSettings("AppSettings", "Issuer");
            var tokenIssuer = rbKey.status ? rbKey.message : "https://industries.cg.gov.in";

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateLifetime = false,
                ValidIssuer = tokenIssuer,
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
            if (securityToken is not JwtSecurityToken jwtSecurityToken ||
                !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");

            return principal;

        }
    }
}