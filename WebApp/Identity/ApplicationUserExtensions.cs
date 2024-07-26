using System.Security.Claims;

namespace WebApp.Identity;

public static class ApplicationUserExtensions
{
    public static HashSet<string> GetPermissions(this ClaimsPrincipal claimsPrincipal)
    {
        return claimsPrincipal
            .FindAll(ApplicationClaimTypes.Permission)
            .Select(c => c.Value)
            .ToHashSet();
    }

    public static Guid GetUserId(this ClaimsPrincipal claimsPrincipal)
    {

        var id = claimsPrincipal.FindFirstValue(ClaimTypes.NameIdentifier)
            ?? throw new InvalidOperationException("User id claim not found.");

        return Guid.Parse(id);
    }
}