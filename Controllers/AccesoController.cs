using Microsoft.AspNetCore.Mvc;
using AppLogin.Models;
using AppLogin.Data;
using AppLogin.ViewModels;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using BCrypt.Net;

namespace AppLogin.Controllers
{
    public class AccesoController : Controller
    {
        private readonly AppDBContext _context;

        public AccesoController(AppDBContext context)
        {
            _context = context;
        }

        public IActionResult Login()
        {
            return View(new LoginVM());
        }

        public IActionResult Registrarse()
        {
            return View(new RegistroUsuarioVM());
        }

       
        public async Task<IActionResult> Registrarse(RegistroUsuarioVM model)
        {
            if (ModelState.IsValid)
            {
                // Verificar si el usuario ya existe
                bool usuarioExiste = await _context.Usuarios.AnyAsync(u => u.Correo == model.Correo);
                if (usuarioExiste)
                {
                    ModelState.AddModelError("Correo", "Este correo ya está registrado");
                    return View(model);
                }

                // Obtener el rol por defecto
                var rol = await _context.Roles.FirstOrDefaultAsync(r => r.IdRol == 1);
                if (rol == null)
                {
                    ModelState.AddModelError("", "Error al asignar el rol");
                    return View(model);
                }

                // Encriptar la contraseña antes de guardarla
                string hashedPassword = BCrypt.Net.BCrypt.HashPassword(model.Clave);

                // Crear el usuario
                var usuario = new Usuario
                {
                    NombreCompleto = model.NombreCompleto,
                    Correo = model.Correo,
                    Clave = hashedPassword, // Guardamos la clave encriptada
                    IdRol = 1,
                    Rol = rol
                };

                _context.Usuarios.Add(usuario);
                await _context.SaveChangesAsync();

                return RedirectToAction("Login");
            }

            return View(model);
        }

     
        public async Task<IActionResult> Login(LoginVM model)
        {
            if (ModelState.IsValid)
            {
                // Buscar el usuario por correo
                var usuario = await _context.Usuarios
                    .Include(u => u.Rol)
                    .FirstOrDefaultAsync(u => u.Correo == model.Correo);

                if (usuario != null && BCrypt.Net.BCrypt.Verify(model.Clave, usuario.Clave))
                {
                    var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, usuario.NombreCompleto),
                        new Claim("Correo", usuario.Correo),
                        new Claim(ClaimTypes.Role, usuario.Rol.NombreRol)
                    };

                    var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                    await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity));

                    // Actualizar el último acceso del usuario
                    usuario.UltimoAcceso = DateTime.UtcNow;
                    await _context.SaveChangesAsync();

                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    ModelState.AddModelError("", "Las credenciales son incorrectas");
                }
            }

            return View(model);
        }

        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Login");
        }
    }
}

