using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using EndpointLens.Server.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace EndpointLens.Server.Pages.Account;

public sealed class LoginModel(AppDbContext db, IPasswordHasher<AdminUser> hasher, TimeProvider clock) : PageModel
{
    private const int MaxFailures = 5;
    private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);

    [BindProperty, Required] public string UserName { get; set; } = "";
    [BindProperty, Required, DataType(DataType.Password)] public string Password { get; set; } = "";
    public string? Error { get; set; }

    public async Task<IActionResult> OnGetAsync()
    {
        if (!await db.AdminUsers.AnyAsync()) return RedirectToPage("Setup");
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(string? returnUrl)
    {
        if (!ModelState.IsValid) return Page();

        var now = clock.GetUtcNow();
        var user = await db.AdminUsers.FirstOrDefaultAsync(u => u.UserName == UserName.Trim());
        if (user?.LockedUntilUtc > now)
        {
            Error = "Account temporarily locked after repeated failed sign-ins. Try again later.";
            return Page();
        }

        var ok = user is not null && hasher.VerifyHashedPassword(user, user.PasswordHash, Password) != PasswordVerificationResult.Failed;
        if (!ok)
        {
            if (user is not null)
            {
                user.FailedLogins++;
                if (user.FailedLogins >= MaxFailures) { user.LockedUntilUtc = now + LockoutDuration; user.FailedLogins = 0; }
                await db.SaveChangesAsync();
            }
            Error = "Invalid user name or password.";
            return Page();
        }

        user!.FailedLogins = 0;
        user.LockedUntilUtc = null;
        await db.SaveChangesAsync();

        var identity = new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, user.UserName), new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()) },
            CookieAuthenticationDefaults.AuthenticationScheme);
        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));
        return LocalRedirect(Url.IsLocalUrl(returnUrl) ? returnUrl! : "/");
    }
}
