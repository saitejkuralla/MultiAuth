## Multiple Authentication Schemes in ASP.NET Core

🔐 Multiple authentication schemes allow you to support multiple authentication methods in your ASP.NET Core application. 
- This means that different parts of your application can use different authentication methods based on specific requirements. 
- For example, you might want to use JWT (JSON Web Tokens) for authentication in some parts of your application, while using cookies for authentication in other parts.

## Installation
Make sure you have the necessary NuGet packages installed. In your project file or Package Manager Console, ensure you have the following packages:

`Microsoft.AspNetCore.Authentication.JwtBearer` This package provides JWT bearer authentication capabilities.
`Microsoft.AspNetCore.Authentication.Cookies` This package provides cookie-based authentication capabilities.
`Microsoft.AspNetCore.Authorization` This package provides authorization middleware.

## 📝 Step 1: Configure Authentication Schemes

In your `Startup.cs` file, configure the authentication schemes by adding them to the `ConfigureServices` method.

## 🔐 Default JWT Authentication Scheme

`Scheme Name`: JwtBearerDefaults.AuthenticationScheme
`Description`: This authentication scheme uses JSON Web Tokens (JWT) for authentication.
Configuration:
```
services.AddAuthentication(options =>
{
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = "https://localhost:7208/",
        ValidAudience = "https://localhost:7208/",
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("superSecretKey@1"))
    };
});
```
### 🔒 Issuer Validation `(ValidateIssuer)`:
- This parameter specifies whether the token's issuer should be validated.
- Setting it to true ensures that the issuer (iss) claim in the token matches the specified ValidIssuer value.

### 🔒 Audience Validation `(ValidateAudience)`:
- This parameter specifies whether the token's audience should be validated.
- Setting it to true ensures that the audience (aud) claim in the token matches the specified ValidAudience value.

### 🔒 Issuer Signing Key Validation `(ValidateIssuerSigningKey)`:
- This parameter specifies whether the token's signing key should be validated.
- Setting it to true ensures that the signing key used to sign the token is trusted. 
- In this case, a symmetric security key is used, generated from the provided secret key.

### 🌍 Valid Issuer `(ValidIssuer)`:
- This parameter specifies the valid issuer for the token. 
- The received token's issuer claim should match this value for successful validation.
- In the example, the valid issuer is set to "https://localhost:7208/".

### 🌍 Valid Audience `(ValidAudience)`:
- This parameter specifies the valid audience for the token. 
- The received token's audience claim should match this value for successful validation.
- In the example, the valid audience is set to "https://localhost:7208/".

### 🔒 Issuer Signing Key `(IssuerSigningKey)`:
- This parameter specifies the key used for validating the signature of the token.
- Here, a symmetric security key is created using the provided secret key encoded as UTF-8.

### 🚀 Customize these parameters according to your application's requirements and security considerations.

## 🔐 Second JWT Authentication Scheme

`Scheme Name`: "SecondJwtScheme"
`Description`: This authentication scheme represents a second JWT authentication scheme with different validation parameters.
Configuration:
```
services.AddAuthentication()
    .AddJwtBearer("SecondJwtScheme", options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = "https://localhost:7209/",
            ValidAudience = "https://localhost:7208/",
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("superSecretKey@2"))
        };
    });
```
### 🔐 Issuer Validation `(ValidateIssuer)`:
- This parameter specifies whether the token's issuer should be validated.
-  By setting it to true, the validation process ensures that the issuer (iss) claim in the token matches the specified ValidIssuer value.

### 🔐 Audience Validation `(ValidateAudience)`:
- This parameter specifies whether the token's audience should be validated.
-  When set to true, the validation process ensures that the audience (aud) claim in the token matches the specified ValidAudience value.

### 🔐 Issuer Signing Key Validation `(ValidateIssuerSigningKey)`:
- This parameter determines whether the token's signing key should be validated. 
- If set to true, the validation process checks that the signing key used to sign the token is trusted.
-  In this case, a symmetric security key is created from the provided secret key.

### 🌍 Valid Issuer `(ValidIssuer)`:
- This parameter defines the valid issuer for the token. 
- The received token's issuer claim should match this value for successful validation.
-  In the example, the valid issuer is set to "https://localhost:7209/".

### 🌍 Valid Audience `(ValidAudience)`:
- This parameter specifies the valid audience for the token. 
- The received token's audience claim should match this value for successful validation.
-  In the example, the valid audience is set to "https://localhost:7208/".

### 🔐 Issuer Signing Key `(IssuerSigningKey)`:
- This parameter determines the key used for validating the token's signature.
-  Here, a symmetric security key is created using the provided secret key encoded as UTF-8.

### 🚀 Customize these parameters according to your application's requirements and security considerations.

## 📜 Step 2: Policy-based Scheme Selection

- To `configure` policy-based scheme selection for authentication in your ASP.NET Core application
- Use the `AddPolicyScheme` method to add a policy-based scheme. 
```
 .AddPolicyScheme("MultiAuthSchemes", JwtBearerDefaults.AuthenticationScheme, options =>
            {
                options.ForwardDefaultSelector = context =>
                {
                    string authorization = context.Request.Headers[HeaderNames.Authorization];
                    if (!string.IsNullOrEmpty(authorization) && authorization.StartsWith("Bearer "))
                    {
                        var token = authorization.Substring("Bearer ".Length).Trim();
                        var jwtHandler = new JwtSecurityTokenHandler();

                        return (jwtHandler.CanReadToken(token) && jwtHandler.ReadJwtToken(token).Issuer.Equals("https://localhost:7208/"))
                            ? JwtBearerDefaults.AuthenticationScheme : "SecondJwtScheme";
                    }

                    return JwtBearerDefaults.AuthenticationScheme;
                };
            });
```
### 💡 Policy-based Scheme Selection

- The code snippet provided demonstrates the configuration of a policy-based scheme selection for authentication in ASP.NET Core. 
- This feature allows you to dynamically select the authentication scheme based on the request context and its authorization header.

### 🔀 Add Policy Scheme
- The AddPolicyScheme method is used to add a policy-based scheme. In this case, it is named "MultiAuthSchemes".
-  The policy scheme enables you to define custom logic for selecting the appropriate authentication scheme.

### 🔀 Forward Default Selector
- The ForwardDefaultSelector property is set to a delegate that determines the authentication scheme based on the request's authorization header. 
- It inspects the authorization header, extracts the bearer token, and performs additional checks to determine the appropriate scheme.

### 🧾 Context Request and Authorization Header
- The context.Request object represents the current HTTP request being processed. 
- The Headers property is accessed to retrieve the authorization header.

### 🔑 Bearer Token Extraction
- The authorization header is checked to ensure it is not empty and starts with the "Bearer " prefix.
- If these conditions are met, the bearer token is extracted from the header.

### 🔒 Token Validation
- A JwtSecurityTokenHandler is created to validate the bearer token. 
- The CanReadToken method verifies if the token can be read, and ReadJwtToken reads the token and provides access to its properties.

### ✅ Scheme Selection
- The delegate returns JwtBearerDefaults.
- AuthenticationScheme if the token is successfully validated and its issuer matches "https://localhost:7208/".
-  Otherwise, it returns "SecondJwtScheme" as the authentication scheme.

## 📜 Step 3: Authentication Controller and Token Generation

- To implement `authentication` in your ASP.NET Core application, follow these steps:

### ✨ Create Authentication Controller
- Create a controller class named AuthController that derives from ControllerBase. 
- This controller will handle authentication operations.
```
namespace JWTAuthentication.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        // Controller actions go here
    }
}
```
### 🔐 Login with Default JWT Token:
-  Create an action method named `LoginDefaultJwt` that logs in a user and generates a default JWT token.
```
[HttpPost("loginDefaultJwt")]
public IActionResult LoginDefaultJwt([FromBody] User user)
{
    // Token generation code goes here
}
```
### 🔑 Generate Default JWT Token:
-  Within the `LoginDefaultJwt` method, create a `SymmetricSecurityKey` using a secret key encoded as UTF-8.
-  Then, create `SigningCredentials` with the security key and the HMAC-SHA256 algorithm.
```
var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("superSecretKey@1"));
var signinCredentials = new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256);
```
### 🚀 Configure Token Options: 
- Create a `JwtSecurityToken` instance with the issuer, audience, claims, expiration time, and signing credentials.
- Customize these options according to your application's requirements.
```
var tokenOptions = new JwtSecurityToken(
    issuer: "https://localhost:7208/",
    audience: "https://localhost:7208/",
    claims: new List<Claim>() { new Claim(ClaimTypes.Name, user.UserName) },
    expires: DateTime.Now.AddMinutes(30),
    signingCredentials: signinCredentials
);
```
### 🎉 Generate Token String: 
- Use the `JwtSecurityTokenHandler` to write the token options as a string representation of the JWT token.
```
var tokenString = new JwtSecurityTokenHandler().WriteToken(tokenOptions);
```
### 📤 Return Token as `HTTP Response`:
- Return an HTTP response with the generated token as the `payload`.
- In this example, an anonymous object is used to wrap the token string.
```
return Ok(new { Token = tokenString });
```
### 🔄 Repeat above Steps  for `Second JWT Token`:
- To generate a `second JWT token`, create another action method named `LoginSecondJwt` following the same pattern as `LoginDefaultJwt`.
- Adjust the issuer, signing key, and other token options accordingly.
```
[HttpPost("loginSecondJwt")]
public IActionResult LoginSecondJwt([FromBody] User user)
{
    // Token generation code for the second JWT token goes here
}
```
### 🚀 Customize the token generation process based on your `authentication` requirements and security considerations.

## 📜 Step 4: Weather Forecast Controller

To handle weather forecast data in your ASP.NET Core application, follow these steps:

### 🌦️ Create Weather Forecast Controller: 
- Create a `controller` class named `WeatherForecastController` that derives from `ControllerBase`. 
- This controller will handle weather forecast data operations.
```
namespace JWTtoken.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class WeatherForecastController : ControllerBase
    {
        private static readonly string[] Summaries = new[]
        {
            "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
        };

        private readonly ILogger<WeatherForecastController> _logger;

        public WeatherForecastController(ILogger<WeatherForecastController> logger)
        {
            _logger = logger;
        }

        // Controller actions go here
    }
}
```
### 🌍 Retrieve Weather Forecast Data for `ServerA`:
- Create an action method named Get that retrieves weather forecast data for `ServerA`.
- Apply the `[HttpGet("ServerA")]` attribute to specify the route for this action.
```
[HttpGet("ServerA")]
[Authorize]
public IEnumerable<WeatherForecast> Get()
{
    // Weather forecast data retrieval code for ServerA goes here
}
```
### 🔐 Authorize Access to ServerA: 
- Apply the `[Authorize]` attribute to the Get action to enforce authentication and authorize access to `ServerA`.
- This ensures that only authenticated users can access this endpoint.

### 🌍 Retrieve Weather Forecast Data for `ServerB`:
- Create another action method named `GetServerB` that retrieves weather forecast data for `ServerB`.
- Apply the `[HttpGet("ServerB")]` attribute to specify the route for this action.

```
[HttpGet("ServerB")]
[Authorize(AuthenticationSchemes = "SecondJwtScheme")]
public IEnumerable<WeatherForecast> GetServerB()
{
    // Weather forecast data retrieval code for ServerB goes here
}
```
### 🔐 Authorize Access to `ServerB`:
- Apply the `[Authorize(AuthenticationSchemes = "SecondJwtScheme")]` attribute to the `GetServerB` action to enforce authentication and authorize access to `ServerB` using the "SecondJwtScheme" authentication scheme.

### 🌟 Retrieve Weather Forecast Data for `Admins`:
- Create another action method named `GetForAdmin` that retrieves weather forecast data specifically for `admins`.
- Apply the `[HttpGet("admin")]` attribute to specify the route for this action.

```
[HttpGet("admin")]
[Authorize(AuthenticationSchemes = "MultiAuthSchemes")]
public IActionResult GetForAdmin()
{
    // Weather forecast data retrieval code for admins goes here
}
```
### 🔐 Authorize Access for Admins:
-  Apply the `[Authorize(AuthenticationSchemes = "MultiAuthSchemes")]` attribute to the `GetForAdmin` action to enforce authentication and authorize access to this endpoint for `admins`.
- This ensures that only authenticated admins can access this endpoint.

### 🚀 Customize the weather forecast data retrieval process based on your application's requirements and authorization rules.

## 📜 Step 5: Conclusion - Multiple Authentication Schemes

### 🔒✨ Conclusion:
-  By following the above steps, you can implement multiple authentication schemes in your ASP.NET Core application.
 - This provides enhanced security and flexibility, allowing you to control access to specific endpoints based on different `authentication` requirements. 💪🔐






