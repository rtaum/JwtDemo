using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Listen on http://localhost:5000 for simplicity
builder.WebHost.UseUrls("http://localhost:5000");

// ======== JWT validation setup ========
const string Issuer = "http://localhost:5000";
const string Audience = "api";
const string ScopeRequired = "api.read";

// Symmetric signing key (keep it long)
const string SigningKey = "this_is_a_dev_only_super_long_signing_key_please_replace_me_1234567890_1234567890";

var signingKeyBytes = Encoding.UTF8.GetBytes(SigningKey);
var securityKey = new SymmetricSecurityKey(signingKeyBytes);

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidIssuer = Issuer,
            ValidAudience = Audience,
            IssuerSigningKey = securityKey,
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero
        };
    });

builder.Services.AddAuthorization(opts =>
{
    opts.AddPolicy("ApiRead", policy =>
        policy.RequireAssertion(ctx =>
            ctx.User.Claims.Any(c => c.Type == "scope" &&
                                     c.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                                        .Contains(ScopeRequired))));
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// ======== OAuth2 client-credentials token endpoint ========
// POST /connect/token
// Content-Type: application/x-www-form-urlencoded
// Authorization: Basic base64(client_id:client_secret)
// body: grant_type=client_credentials&scope=api.read
app.MapPost("/connect/token", async (HttpContext http) =>
{
    static (string? clientId, string? clientSecret) ParseBasicAuth(HttpRequest req)
    {
        if (!req.Headers.TryGetValue("Authorization", out var header)) return (null, null);
        var value = header.ToString();
        if (!value.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase)) return (null, null);
        var raw = value.Substring("Basic ".Length).Trim();
        var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(raw));
        var idx = decoded.IndexOf(':');
        if (idx < 0) return (null, null);
        return (decoded[..idx], decoded[(idx + 1)..]);
    }

    // Demo in-memory client registry
    const string validClientId = "client-app";
    const string validClientSecret = "client-secret";

    var (cid, csecret) = ParseBasicAuth(http.Request);
    if (cid != validClientId || csecret != validClientSecret)
    {
        return Results.Unauthorized();
    }

    // Parse form
    var form = await http.Request.ReadFormAsync();
    var grantType = form["grant_type"].ToString();
    var scope = form["scope"].ToString();
    if (!string.Equals(grantType, "client_credentials", StringComparison.Ordinal) ||
        !scope.Split(' ', StringSplitOptions.RemoveEmptyEntries).Contains(ScopeRequired))
    {
        return Results.BadRequest(new
        {
            error = "unsupported_grant_type_or_scope",
            error_description = "Use client_credentials and request scope=api.read"
        });
    }

    // Issue JWT (short lifetime to demonstrate refresh)
    var now = DateTimeOffset.UtcNow;
    var expires = now.AddSeconds(30);

    var claims = new List<Claim>
    {
        new("scope", ScopeRequired),
        new(JwtRegisteredClaimNames.Sub, cid!),
        new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("n"))
    };

    var creds = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
    var token = new JwtSecurityToken(
        issuer: Issuer,
        audience: Audience,
        claims: claims,
        notBefore: now.UtcDateTime,
        expires: expires.UtcDateTime,
        signingCredentials: creds);

    var tokenValue = new JwtSecurityTokenHandler().WriteToken(token);

    Console.WriteLine($"[TokenServer] Issued token at {now:t}, exp {expires:t} (jti={claims.First(c=>c.Type==JwtRegisteredClaimNames.Jti).Value})");

    return Results.Json(new
    {
        access_token = tokenValue,
        token_type = "Bearer",
        expires_in = (int)TimeSpan.FromSeconds(20).TotalSeconds,
        scope = ScopeRequired
    });
});

// ======== Protected API ========
app.MapGet("/weather", [Authorize("ApiRead")] () =>
{
    var sample = Enumerable.Range(1, 5).Select(i => new
    {
        date = DateOnly.FromDateTime(DateTime.UtcNow.AddDays(i)),
        temperatureC = RandomNumberGenerator.GetInt32(-10, 35),
        summary = new[] { "Freezing", "Bracing", "Chilly", "Mild", "Warm", "Hot" }[
            RandomNumberGenerator.GetInt32(0, 6)]
    });
    return Results.Ok(sample);
});

app.MapGet("/", () => "JWT API up. POST /connect/token then GET /weather with Bearer token.");

app.Run();
