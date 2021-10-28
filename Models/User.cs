namespace MyAuthAPI.Models
{
    public class User
    {
        public int Id { get; set; }

        public string Email { get; set; }

        public string Password { get; set; }

        public Role[] Roles { get; set; }
    }

    public enum Role
    {
        User,
        Admin
    }
}
