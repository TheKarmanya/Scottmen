using BaseClass;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using ScottmenMainApi.Models.MLayer;
using System.Reflection;
using System.Text;
using static BaseClass.ReturnClass;

var builder = WebApplication.CreateBuilder(args);

ReturnBool rb = Utilities.GetAppSettings("Build", "Version");

#region Cors Policy
if (rb.message!.ToLower() == "production")
{
    builder.Services.AddCors(options =>
    {
        options.AddDefaultPolicy(
            builder =>
            {
                builder.WithOrigins("*").AllowAnyHeader().AllowAnyMethod();
            });
    });

}
else
{
    builder.Services.AddCors(options =>
    {
        options.AddDefaultPolicy(
            builder =>
            {
                builder.WithOrigins("*").AllowAnyHeader().AllowAnyMethod();

            });
    });
}
#endregion

#region Authentication
ReturnBool rbKey = Utilities.GetAppSettings("SessionSettings", rb.message);

var key = rbKey.status ? Encoding.ASCII.GetBytes(rbKey.message) : Encoding.ASCII.GetBytes("");

rbKey = Utilities.GetAppSettings("AppSettings", "Issuer");
var tokenIssuer = rbKey.status ? rbKey.message : "https://sdmcare.com";

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
        .AddJwtBearer(options =>
        {
            options.RequireHttpsMetadata = false;
            options.SaveToken = true;
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = true,
                ValidateAudience = false,
                RequireExpirationTime = true,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero,
                ValidIssuer = tokenIssuer,
            };
        });
#endregion

#region Swagger
rbKey = Utilities.GetAppSettings("Project", "Name");
var projectName = rbKey.status ? rbKey.message : "Not defined";

rbKey = Utilities.GetAppSettings("Project", "Version");
var projectVersion = rbKey.status ? rbKey.message : "Not Set";
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Version = projectVersion,
        Title = projectName
    });
    options.AddSecurityDefinition(
            "Bearer",
            new OpenApiSecurityScheme
            {
                Type = SecuritySchemeType.ApiKey,
                BearerFormat = "JWT",
                Scheme = "Bearer",
                In = ParameterLocation.Header,
                Name = "Authorization",
                Description = "Put **_ONLY_** your JWT Bearer token on textbox below!",
            }
        ); ;
    options.AddSecurityRequirement(
           new OpenApiSecurityRequirement
           {
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id = "Bearer"
                        },Scheme = JwtBearerDefaults.AuthenticationScheme,
                        Name = "Bearer",
                         In = ParameterLocation.Header,
                    },
                    new List<string>()
                }
           }
       );
    #region Swagger XMl Documentation  
    var xmlFilename = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
    options.IncludeXmlComments(Path.Combine(AppContext.BaseDirectory, xmlFilename));
    #endregion
});
#endregion
// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddControllers().AddNewtonsoftJson(options =>
options.SerializerSettings.ReferenceLoopHandling = Newtonsoft.Json.ReferenceLoopHandling.Ignore
);
builder.Services.Configure<ApiBehaviorOptions>(options =>
{
    // Disable the default model validation
    options.SuppressModelStateInvalidFilter = true;
});
builder.Services.AddEndpointsApiExplorer();
#region IP Forwarding Settings
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
});
#endregion

var app = builder.Build();
// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
//else
//{
//    app.UseHttpsRedirection();
//}
app.UseForwardedHeaders();
//
app.UseCors();
//app.UseRouting();
//app.UseAuthentication();
app.UseAuthorization();
app.UseMiddleware<AuthorizationMiddleware>();
app.MapControllers();
app.Run();