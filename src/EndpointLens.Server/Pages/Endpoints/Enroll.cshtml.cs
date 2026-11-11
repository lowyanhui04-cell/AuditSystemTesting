using System.ComponentModel.DataAnnotations;
using EndpointLens.Server.Data;
using EndpointLens.Server.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace EndpointLens.Server.Pages.Endpoints;

public sealed class EnrollModel(AppDbContext db, TimeProvider clock) : PageModel
{
    [BindProperty, Required, StringLength(64), RegularExpression(@"^[A-Za-z0-9][A-Za-z0-9 ._-]*$", ErrorMessage = "Use letters, digits, space, dot, dash or underscore.")]
    public string Name { get; set; } = "";

    [BindProperty, StringLength(500)]
    public string? Notes { get; set; }

    public string? IssuedToken { get; private set; }
    public int? IssuedEndpointId { get; private set; }

    public void OnGet() { }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid) return Page();
        var name = Name.Trim();
        if (await db.Endpoints.AnyAsync(e => e.Name == name))
        {
            ModelState.AddModelError(nameof(Name), "An endpoint with this name already exists.");
            return Page();
        }

        var endpoint = new Data.Endpoint { Name = name, Notes = Notes?.Trim(), CreatedAtUtc = clock.GetUtcNow(), TokenHash = "pending" };
        db.Endpoints.Add(endpoint);
        await db.SaveChangesAsync();

        // The id is part of the credential, so it is generated after the row exists.
        var (token, hash) = EndpointCredentials.Generate(endpoint.Id);
        endpoint.TokenHash = hash;
        await db.SaveChangesAsync();

        IssuedToken = token;
        IssuedEndpointId = endpoint.Id;
        return Page();
    }
}
