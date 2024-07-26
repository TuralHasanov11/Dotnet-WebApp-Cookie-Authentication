using System.ComponentModel.DataAnnotations;

namespace WebApp.Models.ViewModels;
public sealed class LoginViewModel
{
    [Required]
    public string Email { get; set; } = string.Empty;

    [Required]
    public string Password { get; set; } = string.Empty;
}