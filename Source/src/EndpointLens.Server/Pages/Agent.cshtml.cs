using EndpointLens.Server.Data;
using EndpointLens.Server.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace EndpointLens.Server.Pages;

/// <summary>One place to get the agent: one click adds a computer and downloads an agent already connected to it.</summary>
public sealed class AgentModel(AppDbContext db, AgentPackage agent, TimeProvider clock) : PageModel
{
    public bool Available { get; private set; }
    public string ServerUrl { get; private set; } = "";
    public bool Loopback { get; private set; }

    public void OnGet()
    {
        Available = agent.IsAvailable;
        ServerUrl = agent.ServerUrl(Request);
        Loopback = AgentPackage.IsLoopback(ServerUrl);
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        if (!agent.IsAvailable)
        {
            TempData["Message"] = "The agent file is not on the server yet. See the steps on this page.";
            return RedirectToPage();
        }

        var endpoint = await QuickEnroll.CreateAsync(db, clock.GetUtcNow(), ct);
        var (token, hash) = EndpointCredentials.Generate(endpoint.Id);
        endpoint.TokenHash = hash;
        var zip = await agent.BuildAsync(endpoint.Name, agent.ServerUrl(Request), token, ct);
        await db.SaveChangesAsync(ct);
        return File(zip, "application/zip", "EndpointLens-Agent.zip");
    }
}
