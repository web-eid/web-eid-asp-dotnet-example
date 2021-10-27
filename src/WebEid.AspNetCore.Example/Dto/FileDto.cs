namespace WebEid.AspNetCore.Example.Dto
{
    public class FileDto
    {
        public FileDto(string name)
        {
            this.Name = name;
        }

        public string Name { get; }
    }
}