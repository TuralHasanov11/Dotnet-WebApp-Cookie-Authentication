using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using WebApp.Abstractions;
using WebApp.Models;
using WebApp.Models.ViewModels;

namespace WebApp.Controllers;

[Route("authorization")]
public class AuthorizationController : Controller
{
    private readonly RoleManager<ApplicationRole> _roleManager;
    private readonly IPermissionService _permissionService;

    public AuthorizationController(
        RoleManager<ApplicationRole> roleManager,
        IPermissionService permissionService)
    {
        _roleManager = roleManager;
        _permissionService = permissionService;
    }

    [Authorize(Permissions.RoleView)]
    [HttpGet("roles")]
    public async Task<IActionResult> RoleList()
    {
        var roles = await _roleManager.Roles.ToListAsync();

        return View(new RolesViewModel { Roles = roles });
    }

    [Authorize(Policy = Permissions.RoleCreate)]
    [HttpGet("roles/create")]
    public IActionResult RoleCreate()
    {
        return View("RoleCreate", new CreateRoleViewModel { });
    }

    [Authorize(Policy = Permissions.RoleCreate)]
    [HttpPost("roles")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RoleCreate(CreateRoleViewModel request)
    {
        if (!ModelState.IsValid)
        {
            return View("RoleCreate");
        }

        var role = new ApplicationRole
        {
            Name = request.Name
        };

        var result = await _roleManager.CreateAsync(role);

        if (!result.Succeeded)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return View("RoleCreate");
        }

        return RedirectToAction(nameof(RoleList));
    }
}
