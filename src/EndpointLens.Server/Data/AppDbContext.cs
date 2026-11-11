using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace EndpointLens.Server.Data;

public sealed class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<AdminUser> AdminUsers => Set<AdminUser>();
    public DbSet<Endpoint> Endpoints => Set<Endpoint>();
    public DbSet<Audit> Audits => Set<Audit>();
    public DbSet<Finding> Findings => Set<Finding>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<AdminUser>().HasIndex(u => u.UserName).IsUnique();
        b.Entity<Endpoint>().HasIndex(e => e.Name).IsUnique();
        b.Entity<Audit>().HasIndex(a => a.SnapshotId).IsUnique();   // idempotent retries
        b.Entity<Audit>().HasIndex(a => new { a.EndpointId, a.CollectedAtUtc });
        b.Entity<Finding>().Property(f => f.Severity).HasConversion<string>();
        b.Entity<Finding>().Property(f => f.Outcome).HasConversion<string>();
    }

    protected override void ConfigureConventions(ModelConfigurationBuilder c)
    {
        // SQLite cannot order by DateTimeOffset natively; store as UTC ticks.
        c.Properties<DateTimeOffset>().HaveConversion<DateTimeOffsetToBinaryConverter>();
        c.Properties<DateTimeOffset?>().HaveConversion<DateTimeOffsetToBinaryConverter>();
    }
}
