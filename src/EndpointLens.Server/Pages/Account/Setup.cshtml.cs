using System.ComponentModel.DataAnnotations;
using EndpointLens.Server.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace EndpointLens.Server.Pages.Account;

/// <summary>First-run page: creates the single administrator account. Disabled once an admin exists.</summary>
public sealed class SetupModel(AppDbContext db, IPasswordHasher<AdminUser> hasher, TimeProvider clock) : PageModel
{
    [BindProperty, Required, StringLength(64, MinimumLength = 3)] public string UserName { get; set; } = "admin";
    [BindProperty, Required, StringLength(128, MinimumLength = 12, ErrorMessage = "Use at least 12 characters.")]
    [DataType(DataType.Password)] public string Password { get; set; } = "";
    [BindProperty, Compare(nameof(Password), ErrorMessage = "Passwords do not match.")]
    [DataType(DataType.Password)] public string ConfirmPassword { get; set; } = "";

    public async Task<IActionResult> OnGetAsync() =>
        await db.AdminUsers.AnyAsync() ? RedirectToPage("Login") : Page();

    public async Task<IActionResult> OnPostAsync()
    {
        if (await db.AdminUsers.AnyAsync()) return RedirectToPage("Login");
        if (!ModelState.IsValid) return Page();

        var user = new AdminUser { UserName = UserName.Trim(), CreatedAtUtc = clock.GetUtcNow() };
        user.PasswordHash = hasher.HashPassword(user, Password);
        db.AdminUsers.Add(user);
        await db.SaveChangesAsync();
        TempData["Message"] = "Administrator account created. Please sign in.";
        return RedirectToPage("Login");
    }
}
