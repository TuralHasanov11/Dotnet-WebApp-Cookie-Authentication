using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Linq;
using System.Security.Claims;
using WebApp.Abstractions;
using WebApp.Identity;
using WebApp.Models;
using WebApp.Models.ViewModels;

namespace WebApp.Controllers;

[Route("authentication")]
public class AuthenticationController(
    SignInManager<ApplicationUser> signInManager,
    UserManager<ApplicationUser> userManager,
    RoleManager<ApplicationRole> roleManager,
    IPermissionService permissionService) : Controller
{
    private readonly SignInManager<ApplicationUser> _signInManager = signInManager;
    private readonly UserManager<ApplicationUser> _userManager = userManager;
    private readonly RoleManager<ApplicationRole> _roleManager = roleManager;
    private readonly IPermissionService _permissionService = permissionService;

    [HttpGet("login")]
    public IActionResult Login()
    {
        return View(new LoginViewModel { });
    }

    [HttpPost("login")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel request)
    {
        if (!ModelState.IsValid)
        {
            return View();
        }

        var user = await _userManager.FindByEmailAsync(request.Email);

        if (user is null)
        {
            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return View();
        }

        _signInManager.AuthenticationScheme = CookieAuthenticationDefaults.AuthenticationScheme;

        var result = await _signInManager.PasswordSignInAsync(
            user.UserName,
            request.Password,
            isPersistent: false,
            lockoutOnFailure: false);

        if (!result.Succeeded)
        {
            return View();
        }

        return RedirectToAction(nameof(Claims));
    }

    [HttpGet("register")]
    public IActionResult Register()
    {
        return View(new RegisterViewModel { });
    }

    [HttpPost("register")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Register(RegisterViewModel request)
    {
        if (!ModelState.IsValid)
        {
            return View();
        }

        var user = ApplicationUser.Create();

        await _userManager.SetUserNameAsync(user, request.Email);
        await _userManager.SetEmailAsync(user, request.Email);
        var result = await _userManager.CreateAsync(user, request.Password);

        if (!result.Succeeded)
        {
            return View();
        }

        var visitorRole = await _roleManager.FindByNameAsync(ApplicationRoles.Visitor);

        if (visitorRole is not null)
        {
            await _userManager.AddToRoleAsync(user, visitorRole.Name);
        }

        return RedirectToAction(nameof(Login));
    }

    [HttpGet("logout")]
    public async Task<IActionResult> Logout()
    {
        _signInManager.AuthenticationScheme = CookieAuthenticationDefaults.AuthenticationScheme;

        await _signInManager.SignOutAsync();
        return RedirectToAction("Index", "Home");
    }

    [Authorize]
    [HttpGet("claims")]
    public IActionResult Claims()
    {
        return View(model: new ClaimsViewModel
        {
            Claims = User.Claims.ToList()
        });
    }
}