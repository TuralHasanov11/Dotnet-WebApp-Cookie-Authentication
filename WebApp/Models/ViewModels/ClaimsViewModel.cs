using System.Security.Claims;

namespace WebApp.Models.ViewModels;

public class ClaimsViewModel
{
    public IEnumerable<Claim> Claims { get; set; } = [];
}